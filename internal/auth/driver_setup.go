// Package auth — setup_token OAuth driver.
//
// The setup_token flow is a vendor-specific shape (Anthropic's
// "setup-token" being the canonical example) in which the operator
// pastes a one-time token issued out-of-band by the provider. The
// driver exchanges that token at the catalog entry's TokenEndpoint
// for a long-lived OAuth credential and persists the result as an
// OAuth_Profile through Profile_Store.
//
// The flow has no interactive Start phase: the dashboard prompts
// the operator for the setup token immediately, then submits it
// through POST /api/auth/profiles/oauth/complete. Start therefore
// returns a paste-mode StartResult with an empty AuthURL, mirroring
// the PKCE paste fallback shape so the HTTP layer (Wave E task 5.2)
// can dispatch every "non-interactive" flow through the same
// CompleteInput body.
//
// Token-bytes hygiene (Requirement 8.3): every log.Printf in this
// file references only e.ID / Profile.Key() — never the raw setup
// token, access token, or refresh token. Property test 18 in Wave H
// task 9.6 captures stdout / stderr / log buffer and asserts zero
// substring matches for the pasted token across the whole flow, so
// any future addition that logs a token byte would fail the build.
//
// Validates: Requirements 8.1, 8.2, 8.3.
package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/xalgord/xalgorix/v4/internal/providers"
)

// setupTokenFlowName is the Catalog_Entry.flow value the registry
// keys this driver under. Declared as a constant so the value is
// referenced from exactly one place — the Name() method below — and
// any rename by the design team flows through a single edit.
const setupTokenFlowName = "setup_token"

// setupTokenDriver implements Driver for flow="setup_token".
//
// The struct holds only what every method needs: the Profile_Store
// it persists into, the *http.Client it uses to talk to the upstream
// token endpoint, and a *log.Logger seam tests can swap for a buffer
// to assert the no-token-bytes invariant.
type setupTokenDriver struct {
	store *Store
	http  *http.Client
	log   *log.Logger
}

// newSetupTokenDriver constructs the driver. A nil http.Client is
// substituted with http.DefaultClient so production wiring inside
// NewRegistry stays a single line. The logger defaults to log.Default
// for the same reason.
func newSetupTokenDriver(store *Store, httpClient *http.Client) *setupTokenDriver {
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	return &setupTokenDriver{
		store: store,
		http:  httpClient,
		log:   log.Default(),
	}
}

// Name returns the flow identifier this driver registers under.
func (d *setupTokenDriver) Name() string { return setupTokenFlowName }

// Start returns a paste-mode StartResult immediately. There is no
// interactive Start phase for setup_token — the dashboard collects
// the token in the same modal that submits Complete — but a Start
// call still happens through the registry so the HTTP layer can
// allocate a FlowID for correlation in audit logs.
//
// AuthURL is intentionally empty: the operator does not navigate
// anywhere. UserCode / VerificationURI are likewise unused. Mode is
// "paste" so the dashboard renders the same "paste your token"
// textarea it shows for the PKCE paste fallback.
func (d *setupTokenDriver) Start(ctx context.Context, e providers.Entry, opts StartOptions) (StartResult, error) {
	if err := ctx.Err(); err != nil {
		return StartResult{}, err
	}
	flowID, err := newSetupFlowID()
	if err != nil {
		// Generation failure means crypto/rand returned an
		// error, which on Linux only happens under getrandom(2)
		// catastrophic failure. Surface a generic message — no
		// token bytes are involved at this point.
		return StartResult{}, fmt.Errorf("auth: setup_token: generate flow id for entry %q: %w", e.ID, err)
	}
	return StartResult{
		FlowID:  flowID,
		Mode:    "paste",
		Submode: "setup_token",
	}, nil
}

// setupTokenResponse is the OAuth 2.0 RFC 6749 §5.1 success-shape we
// expect from the upstream tokenEndpoint. Vendors may include extra
// fields (e.g. id_token); they are accepted and ignored by the
// JSON decoder.
type setupTokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	Scope        string `json:"scope"`
}

// setupTokenErrorResponse is the OAuth 2.0 RFC 6749 §5.2 error-shape
// we look at to detect invalid_grant on Refresh. We deliberately do
// not look at error_description / error_uri because their content is
// vendor-specific and irrelevant to our routing decision.
type setupTokenErrorResponse struct {
	Error string `json:"error"`
}

// Complete exchanges the pasted setup token at e.TokenEndpoint and
// persists the resulting OAuth credential through Profile_Store.
//
// Validation order (matches the design's 400-vs-502 split):
//
//  1. Empty SetupToken → 400-class error before any network IO.
//  2. Empty TokenEndpoint on the Catalog_Entry → configuration
//     error (the catalog entry was created without a tokenEndpoint
//     even though its flow is set).
//  3. POST tokenEndpoint with an RFC 6749-style form body. Non-2xx
//     responses surface as providers.ErrUpstream so the HTTP handler
//     renders a 502 envelope (Requirement 8.2).
//  4. JSON-decode the response, validate access_token is present,
//     build the OAuth_Profile, and Put through the Store. The
//     Store's own validation handles unknown-provider /
//     profileId-shape checks (Requirement 4.8 etc.).
//
// The pasted SetupToken never appears in any log.Printf or returned
// error message — only e.ID and the resulting Profile.Key() do
// (Requirement 8.3).
func (d *setupTokenDriver) Complete(ctx context.Context, e providers.Entry, in CompleteInput) (Profile, error) {
	if err := ctx.Err(); err != nil {
		return Profile{}, err
	}
	if strings.TrimSpace(in.SetupToken) == "" {
		// Surface a generic "required" message rather than
		// "got <empty>" or similar — the field is empty so
		// there is nothing useful to echo, and a future
		// reviewer scanning the file for token-shaped bytes
		// should see no opportunity for leakage here.
		return Profile{}, fmt.Errorf("auth: setup_token: setupToken is required")
	}
	if e.TokenEndpoint == "" {
		return Profile{}, fmt.Errorf("auth: setup_token: catalog entry %q has no tokenEndpoint", e.ID)
	}

	// Build the form body. We include a grant_type label so the
	// upstream can reject mis-routed requests; the literal string
	// "setup_token" matches Anthropic's documented shape and is a
	// reasonable default for any vendor we onboard. Scope and
	// audience are forwarded from the catalog entry so an operator
	// can broaden / narrow the resulting credential by editing the
	// catalog rather than the driver.
	form := url.Values{}
	form.Set("grant_type", setupTokenFlowName)
	form.Set("code", in.SetupToken)
	if e.ClientID != "" {
		form.Set("client_id", e.ClientID)
	}
	if len(e.Scopes) > 0 {
		form.Set("scope", strings.Join(e.Scopes, " "))
	}
	if e.Audience != "" {
		form.Set("audience", e.Audience)
	}

	tr, err := d.exchange(ctx, e, form)
	if err != nil {
		return Profile{}, err
	}

	p := Profile{
		Provider:     e.ID,
		ProfileID:    "default",
		Type:         OAuth,
		AccessToken:  tr.AccessToken,
		RefreshToken: tr.RefreshToken,
		TokenType:    tr.TokenType,
		Scopes:       e.Scopes,
	}
	// The upstream's returned scope wins over the catalog's
	// requested scope when present — the credential's effective
	// privilege is what the upstream actually issued, not what we
	// asked for.
	if tr.Scope != "" {
		p.Scopes = strings.Fields(tr.Scope)
	}
	if tr.ExpiresIn > 0 {
		p.ExpiresAt = time.Now().Add(time.Duration(tr.ExpiresIn) * time.Second).UTC()
	}

	if err := d.store.Put(ctx, p); err != nil {
		return Profile{}, fmt.Errorf("auth: setup_token: persist profile %s for entry %q: %w", p.Key(), e.ID, err)
	}
	d.log.Printf("auth: setup_token persisted profile %s for entry %q", p.Key(), e.ID)
	return p, nil
}

// Refresh rotates the access token for a setup_token-issued profile.
//
// The driver delegates to refreshWithSink so the Requirement
// 10.1–10.4 protocol lives in exactly one place. The exchange
// callback handles three branches:
//
//   - No refresh_token was issued at Complete time → the operator
//     must paste a fresh setup token, so the callback short-circuits
//     with ErrInvalidGrant. refreshWithSink translates that into
//     RequiresReauth=true + ErrReauthRequired (Requirement 10.4) so
//     the caller sees a single sentinel regardless of why the refresh
//     failed.
//
//   - Upstream returns 4xx with body {"error":"invalid_grant"} → same
//     ErrInvalidGrant translation as above.
//
//   - Any other non-2xx → providers.ErrUpstream{StatusCode, Body} so
//     the HTTP layer renders the same 502 envelope it does for
//     Complete.
//
// Validates: Requirements 8.1 (token endpoint exchange), 10.1, 10.2,
// 10.3, 10.4.
func (d *setupTokenDriver) Refresh(ctx context.Context, p Profile, e providers.Entry) (Profile, error) {
	if err := ctx.Err(); err != nil {
		return Profile{}, err
	}

	return refreshWithSink(ctx, d.store, p.Key(), func(current Profile) (Profile, error) {
		if current.RefreshToken == "" {
			// No refresh token was ever issued for this
			// profile (the upstream's setup_token exchange
			// did not return one). The operator must paste
			// a fresh setup token; signal that through
			// ErrInvalidGrant so refreshWithSink sets
			// RequiresReauth and surfaces ErrReauthRequired.
			d.log.Printf("auth: setup_token cannot refresh profile %s for entry %q: no refresh_token on profile", current.Key(), e.ID)
			return Profile{}, ErrInvalidGrant
		}
		if e.TokenEndpoint == "" {
			return Profile{}, fmt.Errorf("auth: setup_token: catalog entry %q has no tokenEndpoint", e.ID)
		}

		form := url.Values{}
		form.Set("grant_type", "refresh_token")
		form.Set("refresh_token", current.RefreshToken)
		if e.ClientID != "" {
			form.Set("client_id", e.ClientID)
		}

		tr, err := d.exchange(ctx, e, form)
		if err != nil {
			return Profile{}, err
		}

		// Apply the rotated fields onto a copy of the current
		// profile. We preserve fields the upstream did not
		// re-issue (notably RefreshToken, which some vendors
		// rotate on every call and others leave stable) so a
		// silent omission upstream does not blank the profile.
		next := current
		next.AccessToken = tr.AccessToken
		if tr.RefreshToken != "" {
			next.RefreshToken = tr.RefreshToken
		}
		if tr.TokenType != "" {
			next.TokenType = tr.TokenType
		}
		if tr.ExpiresIn > 0 {
			next.ExpiresAt = time.Now().Add(time.Duration(tr.ExpiresIn) * time.Second).UTC()
		}
		if tr.Scope != "" {
			next.Scopes = strings.Fields(tr.Scope)
		}
		// A successful refresh clears the requires_reauth flag
		// so the dashboard stops surfacing the re-auth prompt.
		next.RequiresReauth = false
		return next, nil
	})
}

// exchange POSTs form to e.TokenEndpoint and returns the decoded
// success response. Non-2xx responses are translated to either
// ErrInvalidGrant (so refreshWithSink can apply the Requirement 10.4
// protocol) or providers.ErrUpstream (so the HTTP handler renders a
// 502 envelope per Requirement 8.2).
//
// The function intentionally does NOT log the response body — bodies
// from a successful exchange contain access tokens, and we maintain
// the no-token-bytes-in-logs invariant. providers.ErrUpstream carries
// the body to the HTTP layer, where the 502 envelope is the
// documented exfil surface.
func (d *setupTokenDriver) exchange(ctx context.Context, e providers.Entry, form url.Values) (setupTokenResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return setupTokenResponse{}, fmt.Errorf("auth: setup_token: build request for entry %q: %w", e.ID, err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := d.http.Do(req)
	if err != nil {
		// The error from http.Do may include the URL but never
		// the request body — it's safe to log and wrap.
		d.log.Printf("auth: setup_token exchange for entry %q failed: %v", e.ID, err)
		return setupTokenResponse{}, fmt.Errorf("auth: setup_token: POST tokenEndpoint for entry %q: %w", e.ID, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return setupTokenResponse{}, fmt.Errorf("auth: setup_token: read response body for entry %q: %w", e.ID, err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		// Detect invalid_grant so refreshWithSink can apply
		// the Requirement 10.4 protocol. The detection is
		// best-effort: if the body is not JSON or omits the
		// error field, we fall through to ErrUpstream and the
		// 502 envelope.
		if isInvalidGrantBody(body) {
			d.log.Printf("auth: setup_token exchange for entry %q returned invalid_grant (status %d)", e.ID, resp.StatusCode)
			return setupTokenResponse{}, ErrInvalidGrant
		}
		d.log.Printf("auth: setup_token exchange for entry %q returned non-2xx status %d", e.ID, resp.StatusCode)
		return setupTokenResponse{}, providers.ErrUpstream{StatusCode: resp.StatusCode, Body: string(body)}
	}

	var tr setupTokenResponse
	if jerr := json.Unmarshal(body, &tr); jerr != nil {
		return setupTokenResponse{}, fmt.Errorf("auth: setup_token: decode response for entry %q: %w", e.ID, jerr)
	}
	if tr.AccessToken == "" {
		return setupTokenResponse{}, fmt.Errorf("auth: setup_token: response for entry %q missing access_token", e.ID)
	}
	return tr, nil
}

// newSetupFlowID returns an opaque correlation id for a setup_token
// Start invocation. The "setup-" prefix lets log readers see at a
// glance which driver issued the id; the trailing 12-byte URL-safe
// base64 segment supplies ~72 bits of entropy, which is plenty given
// the id only needs to be unique within the lifetime of a single
// dashboard session.
func newSetupFlowID() (string, error) {
	var b [9]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return "setup-" + base64.RawURLEncoding.EncodeToString(b[:]), nil
}

// isInvalidGrantBody attempts to parse body as the OAuth 2.0 error
// envelope (RFC 6749 §5.2) and returns true when the error code is
// exactly "invalid_grant". A failed parse, missing field, or any
// other error code returns false so the caller falls through to the
// generic non-2xx → ErrUpstream branch.
func isInvalidGrantBody(body []byte) bool {
	var env setupTokenErrorResponse
	if err := json.Unmarshal(body, &env); err != nil {
		return false
	}
	return env.Error == "invalid_grant"
}

// Compile-time assertion that *setupTokenDriver satisfies Driver.
// Catches a future Driver-interface change at build time rather than
// surfacing as a registration-time panic.
var _ Driver = (*setupTokenDriver)(nil)
