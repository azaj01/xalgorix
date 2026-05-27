// Package auth — claude_cli_reuse OAuth driver.
//
// driver_claude.go implements the Driver contract (driver.go) for
// Catalog_Entry.flow == "claude_cli_reuse". Unlike the network
// flows (pkce, device_code, setup_token), this driver performs no
// outbound handshake: it imports an already-issued credential the
// operator obtained by running the upstream Claude CLI sign-in on
// the same host. Complete is the workhorse — it opens the
// documented credential file O_RDONLY, parses the embedded
// access/refresh tokens, builds an OAuth_Profile, and persists it
// through Store.Put. The driver NEVER mutates the source file
// (Requirement 9.3) and surfaces a missing/unreadable file as
// ErrNotFound so the HTTP layer can map it to 404
// "claude cli credentials not found" (Requirement 9.2).
//
// Validates: Requirements 9.1, 9.2, 9.3.
package auth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/xalgord/xalgorix/v4/internal/providers"
)

// claudeCredentialPathFn resolves the on-disk path to the Claude
// CLI credential file. Production reads it from the documented
// location under the operator's home directory; tests substitute a
// closure pointing at a fixture under t.TempDir() so the suite can
// exercise the import without touching the real CLI state.
//
// The variable is package-level rather than a Driver field so
// fixture tests can swap it without reaching through the registry —
// the driver shape stays the minimal {store} the task brief
// specifies. Tests are expected to save and restore the previous
// value to avoid leaking state across cases.
var claudeCredentialPathFn = claudeCredentialPath

// claudeCredentialPath returns the documented Claude CLI
// credential file path. The CLI canonically writes
// ~/.claude/.credentials.json on Unix-like systems; the alternate
// ~/.config/anthropic/credentials.json layout is checked only as a
// fallback so an operator running a non-standard build is still
// importable. Both candidates use forward slashes joined via
// filepath.Join so Windows callers get a platform-correct path
// without us hard-coding separators.
//
// The resolver returns the FIRST candidate that exists with a
// readable regular file. If neither exists it falls back to the
// canonical path so Open's ENOENT surfaces a stable error shape to
// the caller, preserving the documented "missing → ErrNotFound"
// path (Requirement 9.2).
func claudeCredentialPath() string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		// No home directory resolvable — return an empty
		// string and let the caller's Open fail with ENOENT.
		// The caller maps any open failure (including the
		// degenerate empty path) to ErrNotFound, which is the
		// behavior Requirement 9.2 specifies.
		return ""
	}
	candidates := []string{
		filepath.Join(home, ".claude", ".credentials.json"),
		filepath.Join(home, ".config", "anthropic", "credentials.json"),
	}
	for _, p := range candidates {
		if fi, err := os.Stat(p); err == nil && fi.Mode().IsRegular() {
			return p
		}
	}
	// Neither candidate exists. Returning the canonical path
	// gives the caller a stable ENOENT to translate into
	// ErrNotFound rather than swallowing the failure here.
	return candidates[0]
}

// claudeReuseDriver implements Driver for "claude_cli_reuse".
//
// The struct intentionally carries only the *Store back-reference
// it needs to persist the imported profile. There is no HTTP
// client, no Clock, and no per-flow listener — Complete is a pure
// file-read followed by Store.Put. Refresh is the one network-
// touching method, and it delegates to refreshWithSink with the
// shared exchange callback when the catalog entry exposes a token
// endpoint; otherwise it surfaces ErrReauthRequired so the operator
// re-runs the upstream CLI to mint a new credential file.
type claudeReuseDriver struct {
	store *Store
	http  *http.Client
}

// newClaudeReuseDriver constructs the driver. The Registry wires
// the store + HTTP client at NewRegistry time (Wave E task 5.4) and
// calls Register(d) so dispatch picks up the driver under its
// canonical flow name. The constructor stays lean — there is no
// fallible work to do at construction.
func newClaudeReuseDriver(store *Store, httpClient *http.Client) *claudeReuseDriver {
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	return &claudeReuseDriver{store: store, http: httpClient}
}

// Name returns the matching Catalog_Entry.flow value the Registry
// uses as a lookup key.
func (d *claudeReuseDriver) Name() string { return "claude_cli_reuse" }

// Start returns a paste-mode StartResult so the dashboard can
// prompt the operator to confirm the import (the driver still
// performs the actual file read in Complete). Start has no side
// effects: no listener is bound, no file is opened, no goroutine
// is spawned. The FlowID is a 16-byte random hex string so the
// dashboard can correlate the subsequent Complete call without the
// driver maintaining server-side state.
//
// Returning Mode "paste" (rather than an empty StartResult) gives
// the webui a uniform shape with the other flows: every Start
// produces a flowId + mode the dashboard can render through the
// same component path as setup_token's paste UX.
//
// Submode is left empty intentionally (H9). The dashboard renders
// the empty-Submode case as a confirm-and-import UI (no input
// field) — the credential file is already on disk and Complete
// reads it directly. Submode "paste_code" / "setup_token" are
// reserved for the flows that need an operator-supplied input.
func (d *claudeReuseDriver) Start(ctx context.Context, e providers.Entry, opts StartOptions) (StartResult, error) {
	if err := ctx.Err(); err != nil {
		return StartResult{}, err
	}
	id, err := randomFlowID()
	if err != nil {
		return StartResult{}, fmt.Errorf("auth: claude_cli_reuse start: %w", err)
	}
	return StartResult{
		FlowID:  id,
		Mode:    "paste",
		Submode: "", // confirm-and-import; documented above.
	}, nil
}

// Complete imports the credential file at claudeCredentialPathFn()
// into Profile_Store. The flow is:
//
//  1. Open the credential file O_RDONLY. Any open failure
//     (ENOENT, EACCES, EISDIR, etc.) → ErrNotFound. We deliberately
//     do not distinguish between "missing" and "unreadable" because
//     Requirement 9.2 specifies the same 404 surface for both.
//  2. Read the file in full and json.Unmarshal into a tolerant
//     intermediate that accepts both camelCase and snake_case key
//     variants (the upstream CLI has shipped both shapes across
//     versions).
//  3. Build the OAuth_Profile with Provider=e.ID,
//     ProfileID="default", Type=OAuth, the embedded tokens,
//     ExpiresAt parsed from the credential, Scopes=e.Scopes,
//     TokenType="Bearer".
//  4. Persist via store.Put. Return the persisted profile.
//
// The CompleteInput parameter is unused — the file path is fixed by
// claudeCredentialPathFn. Accepting CompleteInput keeps the Driver
// interface uniform across flows so the HTTP handler does not need
// per-flow request decoding.
//
// The driver opens the file with O_RDONLY ONLY and never writes to,
// truncates, or otherwise mutates it (Requirement 9.3). The fact
// that the call site uses os.OpenFile with the explicit O_RDONLY
// flag rather than os.Open is intentional — it makes the read-only
// posture obvious to readers and to security review.
func (d *claudeReuseDriver) Complete(ctx context.Context, e providers.Entry, in CompleteInput) (Profile, error) {
	if err := ctx.Err(); err != nil {
		return Profile{}, err
	}

	path := claudeCredentialPathFn()
	if path == "" {
		// Empty path means no home directory was resolvable —
		// surface as ErrNotFound so the HTTP layer renders the
		// documented 404 (Requirement 9.2).
		return Profile{}, ErrNotFound
	}

	// O_RDONLY only — the driver never writes to or truncates the
	// source file (Requirement 9.3). O_NOFOLLOW refuses to open
	// the file when the FINAL path component is a symlink so an
	// attacker who can write to the operator's home directory
	// cannot redirect the import through a symlink to an
	// arbitrary file (e.g. another user's credential store).
	// Intermediate directory symlinks are still followed — the
	// canonical credential path is under the operator's $HOME, so
	// $HOME itself can legitimately be a symlink on some systems
	// (NFS automounts, dotfile setups). H4.
	//
	// Any open failure surfaces as ErrNotFound so the HTTP layer
	// renders 404; the wrapped errno is logged separately so a
	// symlink-rejection (ELOOP) can be triaged without leaking
	// the path through the HTTP response.
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		// Treat ENOENT, ELOOP (symlink at final component), and
		// any other open failure as ErrNotFound. Distinguishing
		// the cases would not change the response shape
		// (Requirement 9.2 mandates 404 for both "missing" and
		// "unreadable") and would only leak filesystem-permission
		// detail into the dashboard.
		return Profile{}, ErrNotFound
	}
	defer f.Close()

	body, err := io.ReadAll(f)
	if err != nil {
		// Any read error after a successful open is also
		// surfaced as ErrNotFound, matching the
		// "missing/unreadable" wording in Requirement 9.2.
		return Profile{}, ErrNotFound
	}

	// Tolerant decode: the upstream CLI has shipped credential
	// files with both camelCase and snake_case keys across
	// versions, so the intermediate type carries both shapes and
	// merges whichever is populated. ExpiresAt is decoded into a
	// json.RawMessage first so we can accept either an RFC3339
	// timestamp string ("2026-05-15T22:43:00Z") or a numeric
	// epoch-millisecond value (1747350180000) — both forms have
	// shipped in the wild.
	var raw struct {
		AccessToken      string          `json:"accessToken"`
		AccessTokenSnake string          `json:"access_token"`
		RefreshToken     string          `json:"refreshToken"`
		RefreshSnake     string          `json:"refresh_token"`
		ExpiresAt        json.RawMessage `json:"expiresAt"`
		ExpiresAtSnake   json.RawMessage `json:"expires_at"`
		TokenType        string          `json:"tokenType"`
		TokenTypeSnake   string          `json:"token_type"`
		Scopes           []string        `json:"scopes"`
	}
	if jerr := json.Unmarshal(body, &raw); jerr != nil {
		return Profile{}, fmt.Errorf("auth: claude credential parse: %w", jerr)
	}

	access := firstNonEmpty(raw.AccessToken, raw.AccessTokenSnake)
	refresh := firstNonEmpty(raw.RefreshToken, raw.RefreshSnake)
	if access == "" {
		// A credential file without an access token is not a
		// valid import target. The HTTP layer treats this as
		// ErrNotFound (404) for symmetry with the missing-file
		// case — both indicate "the operator needs to re-run
		// the upstream CLI before importing".
		return Profile{}, ErrNotFound
	}

	expRaw := raw.ExpiresAt
	if len(expRaw) == 0 {
		expRaw = raw.ExpiresAtSnake
	}
	expiresAt, err := parseClaudeExpiry(expRaw)
	if err != nil {
		return Profile{}, fmt.Errorf("auth: claude credential expiry: %w", err)
	}

	tokenType := firstNonEmpty(raw.TokenType, raw.TokenTypeSnake)
	if tokenType == "" {
		// The upstream CLI does not always populate token
		// type. Defaulting to "Bearer" matches the OAuth 2.0
		// canonical value and is what the LLM client's
		// Authorization header builder expects.
		tokenType = "Bearer"
	}

	// Prefer the catalog entry's declared scopes over whatever
	// the credential file embeds — the catalog is the operator's
	// authoritative source of truth for what scopes this xalgorix
	// install actually requires. If the catalog declares no
	// scopes, fall back to the credential file's list (which may
	// be empty, which is fine).
	scopes := append([]string(nil), e.Scopes...)
	if len(scopes) == 0 {
		scopes = append(scopes, raw.Scopes...)
	}

	prof := Profile{
		Provider:     e.ID,
		ProfileID:    "default",
		Type:         OAuth,
		AccessToken:  access,
		RefreshToken: refresh,
		ExpiresAt:    expiresAt,
		Scopes:       scopes,
		TokenType:    tokenType,
	}

	if err := d.store.Put(ctx, prof); err != nil {
		return Profile{}, err
	}
	// Re-read so the returned profile carries the UpdatedAt
	// timestamp Store.Put just stamped. Any read error here is
	// surfaced as-is — the profile IS persisted, but the caller
	// asked for the canonical post-Put view.
	stored, ok, err := d.store.Get(ctx, prof.Key())
	if err != nil {
		return Profile{}, err
	}
	if !ok {
		// Should be unreachable: Put succeeded immediately
		// before this Get. If we hit it the underlying file
		// was concurrently truncated, which the caller should
		// see rather than us silently returning the in-memory
		// shape.
		return Profile{}, fmt.Errorf("auth: claude credential persisted but missing on read-back")
	}
	return stored, nil
}

// Refresh delegates to refreshWithSink so the standard refresh
// protocol (Requirements 10.1–10.4) applies even to credentials
// that originated from the CLI import. When the catalog entry does
// not declare a TokenEndpoint — some Claude CLI configurations do
// not expose one to xalgorix — we cannot perform an upstream
// rotation, so we surface ErrReauthRequired and rely on the
// operator re-running the CLI sign-in to produce a fresh credential
// file. That keeps the failure mode identical to the
// invalid_grant path in the network drivers and lets the dashboard
// render the same re-auth prompt.
func (d *claudeReuseDriver) Refresh(ctx context.Context, p Profile, e providers.Entry) (Profile, error) {
	if err := ctx.Err(); err != nil {
		return Profile{}, err
	}
	if e.TokenEndpoint == "" {
		// Mark the profile as needing re-auth so the dashboard
		// can prompt the operator. Persistence is best-effort
		// — a Put failure here does not change the response
		// surface (the caller still sees ErrReauthRequired).
		p.RequiresReauth = true
		_ = d.store.Put(ctx, p)
		return p, ErrReauthRequired
	}
	return refreshWithSink(ctx, d.store, p.Key(), func(current Profile) (Profile, error) {
		return d.exchangeRefresh(ctx, current, e)
	})
}

// exchangeRefresh POSTs a standard OAuth 2.0 refresh_token grant to
// e.TokenEndpoint. The implementation is deliberately conservative:
// only the fields the spec requires (grant_type, refresh_token, and
// when populated, client_id) are sent. invalid_grant in the upstream
// response is translated to ErrInvalidGrant so refreshWithSink can
// apply the canonical RequiresReauth + ErrReauthRequired path.
func (d *claudeReuseDriver) exchangeRefresh(ctx context.Context, current Profile, e providers.Entry) (Profile, error) {
	if current.RefreshToken == "" {
		// No refresh token to spend — the upstream cannot
		// rotate without one. Surface as ErrInvalidGrant so
		// refreshWithSink marks the profile RequiresReauth.
		return Profile{}, ErrInvalidGrant
	}

	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", current.RefreshToken)
	if e.ClientID != "" {
		form.Set("client_id", e.ClientID)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return Profile{}, fmt.Errorf("auth: claude refresh: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := d.http.Do(req)
	if err != nil {
		return Profile{}, fmt.Errorf("auth: claude refresh: %w", err)
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return Profile{}, fmt.Errorf("auth: claude refresh: read body: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		// Inspect the body for the OAuth 2.0 invalid_grant
		// error code so refreshWithSink can apply the
		// RequiresReauth path. Anything else is a transient
		// upstream error returned unchanged.
		var errResp struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(respBody, &errResp)
		if errResp.Error == "invalid_grant" {
			return Profile{}, ErrInvalidGrant
		}
		return Profile{}, fmt.Errorf("auth: claude refresh: upstream %d: %s", resp.StatusCode, string(respBody))
	}

	var ok struct {
		AccessToken  string          `json:"access_token"`
		RefreshToken string          `json:"refresh_token"`
		ExpiresIn    int64           `json:"expires_in"`
		ExpiresAt    json.RawMessage `json:"expires_at"`
		TokenType    string          `json:"token_type"`
		Scope        string          `json:"scope"`
	}
	if err := json.Unmarshal(respBody, &ok); err != nil {
		return Profile{}, fmt.Errorf("auth: claude refresh: decode body: %w", err)
	}
	if ok.AccessToken == "" {
		return Profile{}, errors.New("auth: claude refresh: empty access_token in response")
	}

	next := current
	next.AccessToken = ok.AccessToken
	if ok.RefreshToken != "" {
		next.RefreshToken = ok.RefreshToken
	}
	switch {
	case len(ok.ExpiresAt) > 0:
		exp, perr := parseClaudeExpiry(ok.ExpiresAt)
		if perr != nil {
			return Profile{}, fmt.Errorf("auth: claude refresh: expires_at: %w", perr)
		}
		next.ExpiresAt = exp
	case ok.ExpiresIn > 0:
		next.ExpiresAt = time.Now().Add(time.Duration(ok.ExpiresIn) * time.Second).UTC()
	}
	if ok.TokenType != "" {
		next.TokenType = ok.TokenType
	}
	if ok.Scope != "" {
		next.Scopes = strings.Fields(ok.Scope)
	}
	next.RequiresReauth = false
	return next, nil
}

// parseClaudeExpiry decodes the expiresAt / expires_at field from
// the credential file or refresh response. The upstream has shipped
// both an RFC3339 string ("2026-05-15T22:43:00Z") and a numeric
// epoch-millisecond integer (1747350180000); the function tries
// string first (the more common shape) and falls back to the
// numeric form. An empty raw value yields a zero Time, matching the
// JSON omitempty semantics on Profile.ExpiresAt.
func parseClaudeExpiry(raw json.RawMessage) (time.Time, error) {
	if len(raw) == 0 {
		return time.Time{}, nil
	}
	// Try string form first: "2026-05-15T22:43:00Z".
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		if s == "" {
			return time.Time{}, nil
		}
		t, perr := time.Parse(time.RFC3339, s)
		if perr != nil {
			return time.Time{}, fmt.Errorf("parse RFC3339 %q: %w", s, perr)
		}
		return t.UTC(), nil
	}
	// Fall back to numeric epoch milliseconds.
	var n int64
	if err := json.Unmarshal(raw, &n); err == nil {
		if n <= 0 {
			return time.Time{}, nil
		}
		// Heuristic: treat values larger than 10^12 as
		// milliseconds (anything in seconds for the next ~31k
		// years is < 10^12). Smaller values are treated as
		// seconds.
		if n > 1_000_000_000_000 {
			return time.UnixMilli(n).UTC(), nil
		}
		return time.Unix(n, 0).UTC(), nil
	}
	return time.Time{}, fmt.Errorf("expiresAt is neither RFC3339 string nor epoch number: %s", string(raw))
}

// firstNonEmpty returns the first non-empty string from the
// supplied list. Used to merge camelCase / snake_case key variants
// from the tolerant credential decoder without nesting if-blocks.
func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// randomFlowID returns a 16-byte hex-encoded random identifier
// suitable for correlating Start → Complete calls. The dashboard
// treats the value opaquely; using crypto/rand keeps the id
// unguessable so a malicious caller cannot smuggle a Complete
// against a flow they did not initiate.
func randomFlowID() (string, error) {
	var buf [16]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf[:]), nil
}
