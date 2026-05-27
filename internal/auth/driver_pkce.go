// Package auth — pkceDriver implements the RFC 7636 authorization-
// code-with-PKCE flow on top of the cross-driver Driver contract.
//
// The driver supports two completion paths from a single Start:
//
//   1. Loopback (default): bind a one-shot HTTP listener on
//      127.0.0.1:<ephemeral>, return the authorization URL to the
//      dashboard so the operator can complete consent in their
//      browser, and finalize the flow inside the loopback callback
//      handler. This is the happy path described by Requirements
//      6.1–6.5.
//
//   2. Paste fallback: when the operator has set XALGORIX_BIND to a
//      non-loopback address (Requirement 13.2), or when the
//      dashboard explicitly requests paste mode (operator on a
//      headless host without browser automation), the driver
//      refuses to bind a listener and returns Mode="paste" with an
//      authorization URL using the OOB redirect_uri. The operator
//      pastes the resulting authorization code through
//      POST /api/auth/profiles/oauth/complete (Requirement 6.6),
//      which routes back to Driver.Complete with FlowID +
//      AuthorizationCode + State.
//
// Both paths share the same code-exchange helper (exchange) so the
// resulting OAuth_Profile is byte-identical regardless of whether
// the auth code arrived via loopback redirect or operator paste.
//
// The 300-second flow deadline (Requirement 6.5) is enforced by
// arming a time.AfterFunc on Start; on fire it closes the listener
// (loopback path) and removes the flow entry so a subsequent
// paste-fallback Complete returns ErrFlowTimeout — which the HTTP
// layer maps to 408 "oauth flow timed out".
//
// Refresh follows the canonical refreshWithSink protocol declared
// in driver.go (Requirements 10.1–10.4). The exchange callback
// POSTs grant_type=refresh_token to e.TokenEndpoint; an
// invalid_grant response surfaces as ErrInvalidGrant, which
// refreshWithSink translates into Profile.RequiresReauth=true and
// the ErrReauthRequired sentinel.
//
// Validates: Requirements 6.1, 6.2, 6.3, 6.4, 6.5, 6.6, 13.1, 13.2.
package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/xalgord/xalgorix/v4/internal/providers"
)

// pkceFlowDeadline is the upper bound on how long a single PKCE
// flow stays alive between Start and Complete. The listener is
// force-closed and the flow entry is removed after this many
// seconds elapse, so a paste-fallback Complete invoked late
// returns ErrFlowTimeout.
//
// Declared as a package-private var (rather than a const) so the
// driver_pkce_test.go suite can shrink the deadline to a few tens
// of milliseconds for the timeout test without sleeping for the
// full 300 seconds. Production callers never assign to this
// symbol.
//
// Validates: Requirement 6.5.
var pkceFlowDeadline = 300 * time.Second

const (
	// pkceCallbackPath is the fixed path component of the
	// loopback redirect_uri. The path is part of the value
	// embedded in the authorization request so the registered
	// callback (the only http handler mounted on the ephemeral
	// listener) is the only endpoint that can receive the
	// authorization code.
	pkceCallbackPath = "/oauth/callback"

	// pkceOOBRedirect is the redirect_uri value advertised in
	// paste-fallback mode. The literal "out-of-band" URN is the
	// historical OAuth 2.0 placeholder for flows that finalize
	// outside the browser; the driver does not actually rely on
	// the upstream provider redirecting to it — the operator
	// pastes the code into the dashboard.
	pkceOOBRedirect = "urn:ietf:wg:oauth:2.0:oob"

	// pkceDefaultProfileID is the placeholder profileId
	// assigned to a new OAuth_Profile when the flow does not
	// otherwise specify one. The dashboard can rename the
	// resulting profile after persistence; this constant only
	// avoids collisions in Profile.Key on the initial Put.
	pkceDefaultProfileID = "default"
)

// pkceDriver is the per-flow handler for Catalog_Entry.flow="pkce".
//
// flows is keyed by FlowID and owns every in-flight pkceFlow value;
// entries are inserted in Start and removed by expireFlow on
// completion / timeout. sync.Map is the right shape because writes
// happen at flow-creation rate (1 per operator action) while reads
// happen on every callback / paste-fallback Complete, and Go's
// sync.Map outperforms a sync.RWMutex+map for that read-mostly
// pattern without forcing the caller to hold a lock across the
// network exchange.
type pkceDriver struct {
	store *Store
	http  *http.Client
	flows sync.Map // flowID → *pkceFlow
}

// pkceFlow captures every piece of state the callback handler /
// paste-fallback Complete needs to finalize a single PKCE
// authorization. Field meanings:
//
//   - verifier: the 32-byte random PKCE code_verifier sent at the
//     token-exchange step (Requirement 6.2).
//   - state: the 32-byte random state value validated against the
//     callback's ?state= parameter (Requirement 6.3).
//   - entry: a captured copy of the Catalog_Entry consulted at
//     Start. Captured rather than re-fetched so a catalog edit
//     mid-flow cannot retarget the token exchange to a different
//     upstream.
//   - profileID: the requested ProfileID (defaults to
//     pkceDefaultProfileID; the StartOptions surface does not
//     propagate this field today, see the doc comment on Start).
//   - listener / server: nil in paste mode; non-nil in loopback
//     mode.
//   - timer: the AfterFunc handle so successful completion can
//     stop the deadline before it fires.
//   - redirect: the redirect_uri actually advertised in the
//     authorization request — must match exactly at exchange time,
//     so we capture it once and reuse on Complete.
//   - done: signal channel closed by cleanup when the flow
//     finalizes / times out. Currently unused outside expireFlow,
//     but kept on the struct so a future "wait for completion"
//     surface can listen on it without touching the cleanup
//     plumbing.
//   - cleanup: ensures listener.Close, server.Shutdown, and timer.Stop
//     all run at most once even when both the timer and a callback
//     race to expire the same flow.
//   - flowID: kept on the struct so signalFlow can identify the
//     entry without piping the id through every closure.
type pkceFlow struct {
	verifier  string
	state     string
	entry     providers.Entry
	profileID string
	// mu serializes mutations to the timer / listener / server
	// fields. Without it, the AfterFunc goroutine that reads
	// flow.timer inside expireFlow's cleanup.Do races against
	// the Start goroutine that assigns flow.timer right after
	// the AfterFunc returns. The race is benign at the
	// production deadline (300s) but real under the Go memory
	// model — the race detector flags it correctly when tests
	// shrink pkceFlowDeadline to a few tens of milliseconds for
	// the timeout test. Holding mu across the assignment in
	// Start and the read in cleanup establishes the missing
	// happens-before edge.
	mu        sync.Mutex
	listener  net.Listener
	server    *http.Server
	timer     *time.Timer
	redirect  string
	done      chan error
	cleanup   sync.Once
	flowID    string
}

// pkceTokenResponse models the OAuth 2.0 token-endpoint response
// body shape consumed by both the authorization-code exchange and
// the refresh-token exchange. Field-level json tags follow the
// RFC 6749 spelling. Prefixed pkce* so other driver files (3.5,
// 3.6, 3.7) can declare their own response types without
// colliding at package scope.
type pkceTokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	Scope        string `json:"scope"`
}

// expiresAt converts the relative expires_in into an absolute UTC
// timestamp anchored to wall-clock now. Returns the zero Time when
// expires_in is unspecified — Profile.ExpiresAt's omitempty json
// tag elides the field in that case so downstream "needs refresh"
// checks can treat zero as "no expiry advertised".
func (t pkceTokenResponse) expiresAt() time.Time {
	if t.ExpiresIn <= 0 {
		return time.Time{}
	}
	return time.Now().UTC().Add(time.Duration(t.ExpiresIn) * time.Second)
}

// pkceTokenError models the RFC 6749 error response body. The
// error field is the only one we branch on (invalid_grant →
// ErrInvalidGrant); error_description is captured solely so the
// wrapped error message has something useful to show in logs.
type pkceTokenError struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

// newPKCEDriver constructs a pkceDriver bound to the supplied
// Profile_Store and *http.Client. Wave E task 5.4 wires the result
// onto a Registry via Registry.Register — the constructor itself
// does not touch the registry so this file stays decoupled from
// the eventual NewRegistry call site (per the task brief).
//
// nil httpClient defaults to http.DefaultClient so a minimal test
// harness can construct the driver without preassembling an
// outbound transport.
func newPKCEDriver(store *Store, httpClient *http.Client) *pkceDriver {
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	return &pkceDriver{store: store, http: httpClient}
}

// Name returns the matching Catalog_Entry.flow value. Registry
// uses this string as the lookup key.
func (d *pkceDriver) Name() string { return "pkce" }

// Start kicks off a PKCE flow. The behavior branches on whether
// the dashboard's effective bind address is loopback:
//
//   - loopback (XALGORIX_BIND unset / "127.0.0.1") → bind an
//     ephemeral listener on 127.0.0.1:0 (Requirement 6.1, 13.1),
//     mount the callback handler, return Mode="loopback" plus the
//     authorization URL.
//   - non-loopback (e.g., 0.0.0.0, public IP) → refuse to bind
//     (Requirement 13.2), return Mode="paste" with the same
//     authorization URL but using the OOB redirect_uri.
//   - opts.PreferPaste forces the paste shape even on loopback
//     (operator on a headless host without browser automation).
//
// The 300-second AfterFunc fires regardless of mode so a stale
// flow entry is reaped even when the operator never returns.
//
// The returned StartResult.ProfileID is implicit at
// pkceDefaultProfileID; StartOptions does not currently propagate
// a profileId. The dashboard renames the persisted profile after
// completion if the operator wants a non-default name.
//
// Validates: Requirements 6.1, 6.2, 6.3, 6.5, 13.1, 13.2.
func (d *pkceDriver) Start(ctx context.Context, e providers.Entry, opts StartOptions) (StartResult, error) {
	verifier, err := pkceRandomBase64URL(32)
	if err != nil {
		return StartResult{}, fmt.Errorf("auth/pkce: code_verifier: %w", err)
	}
	state, err := pkceRandomBase64URL(32)
	if err != nil {
		return StartResult{}, fmt.Errorf("auth/pkce: state: %w", err)
	}
	flowID, err := pkceRandomFlowID()
	if err != nil {
		return StartResult{}, fmt.Errorf("auth/pkce: flowID: %w", err)
	}
	challenge := pkceChallenge(verifier)

	flow := &pkceFlow{
		verifier:  verifier,
		state:     state,
		entry:     e,
		profileID: pkceDefaultProfileID,
		done:      make(chan error, 1),
		flowID:    flowID,
	}
	expiresAt := time.Now().UTC().Add(pkceFlowDeadline)

	// Decide listener vs paste mode. PreferPaste short-circuits
	// the loopback branch (operator opted out); a non-loopback
	// BindAddr forces paste per R13.2.
	usePaste := opts.PreferPaste || !pkceIsLoopbackBind(opts.BindAddr)
	if usePaste {
		flow.redirect = pkceOOBRedirect
		d.flows.Store(flowID, flow)
		// AfterFunc still arms in paste mode so a stale flow
		// is reaped — otherwise an operator who abandons the
		// paste UI would leave a verifier+state pair pinned in
		// memory forever. Hold flow.mu across the assignment so
		// the AfterFunc callback (which acquires the same
		// mutex inside expireFlow's cleanup.Do) cannot race
		// the field write.
		flow.mu.Lock()
		flow.timer = time.AfterFunc(pkceFlowDeadline, func() {
			d.expireFlow(flowID, ErrFlowTimeout)
		})
		flow.mu.Unlock()
		return StartResult{
			FlowID:    flowID,
			Mode:      "paste",
			Submode:   "paste_code",
			AuthURL:   pkceBuildAuthURL(e, flow.redirect, state, challenge),
			ExpiresAt: expiresAt,
		}, nil
	}

	// Loopback path: bind 127.0.0.1:0 and capture the assigned
	// port so the redirect_uri sent in the authorization URL
	// matches the listener exactly. A net.TCPAddr type
	// assertion is safe here because we explicitly asked for
	// "tcp" / "127.0.0.1:0".
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return StartResult{}, fmt.Errorf("auth/pkce: bind loopback: %w", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	redirect := fmt.Sprintf("http://127.0.0.1:%d%s", port, pkceCallbackPath)
	flow.listener = listener
	flow.redirect = redirect

	mux := http.NewServeMux()
	mux.HandleFunc(pkceCallbackPath, d.callbackHandler(flow))
	flow.server = &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	d.flows.Store(flowID, flow)

	// Serve in a background goroutine. Serve returns
	// http.ErrServerClosed on Shutdown / listener.Close, so the
	// goroutine exits cleanly when expireFlow runs.
	go func() {
		_ = flow.server.Serve(listener)
	}()

	// Hold flow.mu across the timer assignment so the
	// AfterFunc-spawned callback cannot read flow.timer before
	// the assignment completes — see the field-level comment
	// on pkceFlow.mu.
	flow.mu.Lock()
	flow.timer = time.AfterFunc(pkceFlowDeadline, func() {
		d.expireFlow(flowID, ErrFlowTimeout)
	})
	flow.mu.Unlock()

	return StartResult{
		FlowID:    flowID,
		Mode:      "loopback",
		AuthURL:   pkceBuildAuthURL(e, redirect, state, challenge),
		ExpiresAt: expiresAt,
	}, nil
}

// Complete finalizes the flow from the paste-fallback HTTP
// handler. The loopback callback handler does not route through
// here — it calls exchange directly so the HTTP response body can
// be flushed to the operator's browser before cleanup runs.
//
// On a missing flow entry (the timer already fired and removed
// it), Complete returns ErrFlowTimeout so the HTTP layer maps to
// 408. The state-mismatch case is mapped at the HTTP layer too;
// the sentinel-vs-fmt distinction here is intentional — a stale
// flow is a deterministic timeout, while a state mismatch is a
// security-relevant validation failure with a different status
// code.
//
// Validates: Requirement 6.6.
func (d *pkceDriver) Complete(ctx context.Context, e providers.Entry, in CompleteInput) (Profile, error) {
	raw, ok := d.flows.Load(in.FlowID)
	if !ok {
		return Profile{}, fmt.Errorf("%w: flow %q not found or expired", ErrFlowTimeout, in.FlowID)
	}
	flow := raw.(*pkceFlow)
	if in.State == "" || in.State != flow.state {
		return Profile{}, fmt.Errorf("auth/pkce: state mismatch")
	}
	if in.AuthorizationCode == "" {
		return Profile{}, fmt.Errorf("auth/pkce: authorization code required")
	}
	prof, err := d.exchange(ctx, flow, in.AuthorizationCode)
	// Whether exchange succeeded or not, the flow's authorization
	// code is single-use — clear the entry so a second Complete
	// call cannot replay. expireFlow is idempotent via sync.Once.
	d.expireFlow(in.FlowID, err)
	if err != nil {
		return Profile{}, err
	}
	return prof, nil
}

// Refresh delegates to refreshWithSink, supplying an exchange
// callback that POSTs grant_type=refresh_token at the entry's
// TokenEndpoint. Sink coalescing and the invalid_grant →
// ErrReauthRequired translation are owned by refreshWithSink so
// the protocol stays in one place across drivers.
//
// Validates: Requirements 10.1, 10.2, 10.3, 10.4.
func (d *pkceDriver) Refresh(ctx context.Context, p Profile, e providers.Entry) (Profile, error) {
	return refreshWithSink(ctx, d.store, p.Key(), func(current Profile) (Profile, error) {
		return d.exchangeRefresh(ctx, e, current)
	})
}

// Revoke implements auth.Revoker by POSTing the stored
// refresh_token (or, when the profile has none, the access_token)
// to the catalog entry's RevocationEndpoint per RFC 7009. When
// RevocationEndpoint is empty we fall back to "<tokenEndpoint>/revoke"
// — that's the canonical sibling-path convention OAuth servers
// follow when the metadata document doesn't advertise a separate
// endpoint. If neither is resolvable the call is a no-op (the
// caller treats Revoke errors as best-effort, so a skip here is
// indistinguishable from a clean revoke from the operator's point
// of view).
//
// The implementation is tolerant: any non-2xx response or transport
// error is returned to the caller for logging but never bubbles up
// to fail the profile delete. RFC 7009 §2.2 requires servers to
// return 200 even for unknown tokens, so a non-2xx here means the
// upstream is unhealthy or doesn't support revocation — both are
// states where forcing the operator to keep the local profile
// would be the wrong default.
//
// Validates: H1 (best-effort revoke on delete).
func (d *pkceDriver) Revoke(ctx context.Context, e providers.Entry, p Profile) error {
	endpoint := pkceRevocationEndpoint(e)
	if endpoint == "" {
		// No revocation surface available — treat as a no-op.
		// The operator deleted the profile locally, which is
		// what they asked for; the upstream may keep an
		// orphaned token but cannot impersonate the operator
		// without re-issuing one.
		return nil
	}
	form := url.Values{}
	tokenHint := "refresh_token"
	token := p.RefreshToken
	if token == "" {
		token = p.AccessToken
		tokenHint = "access_token"
	}
	if token == "" {
		return nil
	}
	form.Set("token", token)
	form.Set("token_type_hint", tokenHint)
	if e.ClientID != "" {
		form.Set("client_id", e.ClientID)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return fmt.Errorf("auth/pkce: build revoke request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := d.http.Do(req)
	if err != nil {
		return fmt.Errorf("auth/pkce: revoke endpoint: %w", err)
	}
	defer resp.Body.Close()
	// Drain the body up to a small cap so connection reuse works,
	// but discard the contents — RFC 7009 says a successful response
	// MAY include a body but callers are not expected to act on it.
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("auth/pkce: revoke endpoint returned %d", resp.StatusCode)
	}
	return nil
}

// pkceRevocationEndpoint resolves the upstream revocation URL for
// the supplied catalog entry. RevocationEndpoint wins when set;
// otherwise we synthesize "<tokenEndpoint>/revoke" per the RFC 7009
// sibling-path convention. Returns "" when neither field can produce
// a usable URL — the caller treats that as "no revocation surface".
func pkceRevocationEndpoint(e providers.Entry) string {
	if v := strings.TrimSpace(e.RevocationEndpoint); v != "" {
		return v
	}
	if v := strings.TrimSpace(e.TokenEndpoint); v != "" {
		return strings.TrimRight(v, "/") + "/revoke"
	}
	return ""
}

// callbackHandler returns the http.HandlerFunc mounted at
// pkceCallbackPath on the loopback listener. It is captured per-
// flow so the closure has direct access to the flow's verifier /
// state without a registry lookup.
//
// Branches:
//
//   - ?error=… → upstream returned an OAuth error (user denied,
//     misconfigured client, etc.). 400 to the operator's browser
//     and surface the error through expireFlow.
//   - state mismatch → likely CSRF / replay attempt. 400 and
//     surface.
//   - missing code → malformed callback. 400 and surface.
//   - happy path → exchange + persist + 200 with a "you can close
//     this tab" message, then expireFlow.
//
// Every response branch sets the no-cache + no-referrer header
// triple before writing the status so an authorization-code
// mid-flight (in the URL the browser navigated through) cannot get
// cached upstream and cannot leak through the Referer header on a
// follow-up navigation. We also set a same-origin Referrer-Policy
// rather than no-referrer-strict so a future success page could
// still surface its own origin if needed (today the body is plain
// text, so the policy is effectively academic but the header keeps
// the contract explicit). H2.
//
// expireFlow is invoked from a background goroutine (signalFlow)
// so the HTTP response is flushed to the operator's browser
// before the listener begins shutdown — otherwise Shutdown would
// race with the response write and the operator might see a
// connection-reset page.
//
// Validates: Requirements 6.3, 6.4; H2 (loopback callback no-cache
// + no-referrer headers).
func (d *pkceDriver) callbackHandler(flow *pkceFlow) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Always set the loopback-callback hardening headers
		// before any response branch writes. http.Error and
		// w.WriteHeader both flush the header map on first
		// call, so setting these up front guarantees they ride
		// the response regardless of which branch fires.
		setPKCECallbackHeaders(w)

		q := r.URL.Query()
		if errParam := q.Get("error"); errParam != "" {
			http.Error(w, fmt.Sprintf("oauth error: %s", errParam), http.StatusBadRequest)
			d.signalFlow(flow, fmt.Errorf("auth/pkce: provider error: %s", errParam))
			return
		}
		if q.Get("state") != flow.state {
			http.Error(w, "state mismatch", http.StatusBadRequest)
			d.signalFlow(flow, fmt.Errorf("auth/pkce: state mismatch on callback"))
			return
		}
		code := q.Get("code")
		if code == "" {
			http.Error(w, "missing authorization code", http.StatusBadRequest)
			d.signalFlow(flow, fmt.Errorf("auth/pkce: missing code on callback"))
			return
		}
		if _, err := d.exchange(r.Context(), flow, code); err != nil {
			http.Error(w, "token exchange failed", http.StatusBadGateway)
			d.signalFlow(flow, err)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("Sign-in complete. You can close this tab and return to xalgorix."))
		d.signalFlow(flow, nil)
	}
}

// setPKCECallbackHeaders installs the response-header triple every
// PKCE callback branch needs to set before its status write:
//
//   - Cache-Control: no-store, no-cache, must-revalidate — keeps
//     an authorization-code mid-flight (in the URL the browser
//     navigated through) out of any intermediary or browser cache.
//   - Pragma: no-cache — HTTP/1.0 fallback for the same property.
//   - Referrer-Policy: no-referrer — prevents the authorization
//     code (in the request URL the browser is currently rendering)
//     from leaking through the Referer header of any follow-up
//     navigation the operator might trigger from the success page.
//
// Validates: H2 (loopback callback hardening headers).
func setPKCECallbackHeaders(w http.ResponseWriter) {
	h := w.Header()
	h.Set("Cache-Control", "no-store, no-cache, must-revalidate")
	h.Set("Pragma", "no-cache")
	h.Set("Referrer-Policy", "no-referrer")
}

// exchange performs the authorization-code → access-token
// exchange against flow.entry.TokenEndpoint and persists the
// resulting OAuth_Profile through the Store. It is the shared
// helper used by both the loopback callback handler and the
// paste-fallback Complete path so the on-disk profile shape is
// identical across modes.
//
// Validates: Requirement 6.4.
func (d *pkceDriver) exchange(ctx context.Context, flow *pkceFlow, code string) (Profile, error) {
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", flow.redirect)
	form.Set("client_id", flow.entry.ClientID)
	form.Set("code_verifier", flow.verifier)

	tok, err := d.postTokenForm(ctx, flow.entry.TokenEndpoint, form)
	if err != nil {
		return Profile{}, err
	}

	// Prefer the upstream-returned scope when present; otherwise
	// echo the catalog-configured scopes. Both are joined by
	// space per RFC 6749 §3.3.
	scopes := append([]string(nil), flow.entry.Scopes...)
	if tok.Scope != "" {
		scopes = strings.Fields(tok.Scope)
	}

	p := Profile{
		Provider:     flow.entry.ID,
		ProfileID:    flow.profileID,
		Type:         OAuth,
		AccessToken:  tok.AccessToken,
		RefreshToken: tok.RefreshToken,
		ExpiresAt:    tok.expiresAt(),
		Scopes:       scopes,
		TokenType:    tok.TokenType,
	}
	if err := d.store.Put(ctx, p); err != nil {
		return Profile{}, fmt.Errorf("auth/pkce: persist profile: %w", err)
	}
	// Re-read so the returned Profile carries the Store-stamped
	// UpdatedAt. Fall back to the in-memory value when the
	// re-read miss is somehow possible (it should not be — Put
	// committed under the flock — but a defensive fallback is
	// cheaper than panicking).
	fresh, ok, err := d.store.Get(ctx, p.Key())
	if err != nil {
		return Profile{}, fmt.Errorf("auth/pkce: re-read persisted profile: %w", err)
	}
	if !ok {
		return p, nil
	}
	return fresh, nil
}

// exchangeRefresh is the refresh-token leg consumed by
// refreshWithSink's exchange callback. It produces a Profile with
// the rotated tokens but does NOT persist — the shared helper
// owns the Put step (under the sink mutex) so concurrent in-
// process refreshes converge on a single committed snapshot.
//
// Empty refresh_token in the response means the upstream chose
// not to rotate the refresh token; we keep the existing one in
// that case (the OAuth 2.0 spec explicitly permits this).
//
// On invalid_grant we return ErrInvalidGrant unchanged so
// refreshWithSink can detect it via errors.Is.
func (d *pkceDriver) exchangeRefresh(ctx context.Context, e providers.Entry, current Profile) (Profile, error) {
	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", current.RefreshToken)
	form.Set("client_id", e.ClientID)

	tok, err := d.postTokenForm(ctx, e.TokenEndpoint, form)
	if err != nil {
		return Profile{}, err
	}

	next := current
	next.AccessToken = tok.AccessToken
	if tok.RefreshToken != "" {
		next.RefreshToken = tok.RefreshToken
	}
	next.ExpiresAt = tok.expiresAt()
	if tok.TokenType != "" {
		next.TokenType = tok.TokenType
	}
	if tok.Scope != "" {
		next.Scopes = strings.Fields(tok.Scope)
	}
	// Successful refresh clears any previously-set requires_reauth
	// flag — the operator's stored credential is good again.
	next.RequiresReauth = false
	return next, nil
}

// postTokenForm POSTs the form-encoded body to endpoint and
// decodes the response. Non-2xx with body.error == "invalid_grant"
// returns the ErrInvalidGrant sentinel directly so callers (and
// refreshWithSink) can errors.Is on it. Other non-2xx responses
// are wrapped with the upstream status code.
//
// The 1MiB cap on response body reads is defensive — token
// endpoints return a few hundred bytes at most; capping protects
// xalgorix from a misbehaving upstream that streams unbounded
// data.
func (d *pkceDriver) postTokenForm(ctx context.Context, endpoint string, form url.Values) (pkceTokenResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return pkceTokenResponse{}, fmt.Errorf("auth/pkce: build token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := d.http.Do(req)
	if err != nil {
		return pkceTokenResponse{}, fmt.Errorf("auth/pkce: token endpoint: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return pkceTokenResponse{}, fmt.Errorf("auth/pkce: read token response: %w", err)
	}

	if resp.StatusCode/100 != 2 {
		var te pkceTokenError
		_ = json.Unmarshal(body, &te)
		if te.Error == "invalid_grant" {
			return pkceTokenResponse{}, ErrInvalidGrant
		}
		if te.Error != "" {
			return pkceTokenResponse{}, fmt.Errorf("auth/pkce: token endpoint status %d: %s (%s)", resp.StatusCode, te.Error, te.ErrorDescription)
		}
		return pkceTokenResponse{}, fmt.Errorf("auth/pkce: token endpoint status %d", resp.StatusCode)
	}

	var tok pkceTokenResponse
	if err := json.Unmarshal(body, &tok); err != nil {
		return pkceTokenResponse{}, fmt.Errorf("auth/pkce: decode token response: %w", err)
	}
	if tok.AccessToken == "" {
		return pkceTokenResponse{}, fmt.Errorf("auth/pkce: token response missing access_token")
	}
	return tok, nil
}

// expireFlow removes the flow entry from d.flows (so subsequent
// Complete calls observe a "not found" / timeout) and runs the
// per-flow cleanup exactly once via sync.Once.
//
// The cleanup steps in order:
//
//  1. Stop the AfterFunc timer so a successful completion does
//     not still trigger the timeout callback.
//  2. Shutdown the http.Server with a short deadline so any
//     in-flight callback response is allowed to drain.
//  3. Close the listener as a belt-and-suspenders measure
//     (Shutdown closes the underlying listener but Close is
//     idempotent and protects against the rare case where Serve
//     never started).
//  4. Send the result error onto done (non-blocking) and close
//     it so any future "wait for flow" surface unblocks.
//
// Validates: Requirement 6.5 (timer-driven cleanup).
func (d *pkceDriver) expireFlow(flowID string, err error) {
	raw, ok := d.flows.LoadAndDelete(flowID)
	if !ok {
		return
	}
	flow := raw.(*pkceFlow)
	flow.cleanup.Do(func() {
		// Snapshot the per-flow resources under flow.mu so the
		// AfterFunc-spawned cleanup observes the same fields
		// that Start assigned — without the mutex, the timer /
		// listener / server reads here race against Start's
		// writes when the deadline is short enough for the
		// callback to fire near the assignment.
		flow.mu.Lock()
		timer := flow.timer
		server := flow.server
		listener := flow.listener
		flow.mu.Unlock()
		if timer != nil {
			timer.Stop()
		}
		if server != nil {
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			_ = server.Shutdown(shutdownCtx)
			cancel()
		}
		if listener != nil {
			_ = listener.Close()
		}
		// Non-blocking send — done has cap=1 so this only
		// races against itself, and sync.Once already
		// guarantees a single visit. The select's default
		// branch protects against the (impossible) case where
		// the channel was already drained.
		select {
		case flow.done <- err:
		default:
		}
		close(flow.done)
	})
}

// signalFlow runs expireFlow on a background goroutine so the
// caller (typically the loopback callback handler mid-write) can
// flush its HTTP response before the server begins Shutdown.
// Calling expireFlow synchronously inside an HTTP handler would
// race the response write against Shutdown's listener close.
func (d *pkceDriver) signalFlow(flow *pkceFlow, err error) {
	go d.expireFlow(flow.flowID, err)
}

// pkceBuildAuthURL constructs the authorization URL the dashboard
// directs the operator's browser to. The query string is
// deterministic in field order (url.Values.Encode sorts keys), so
// the resulting URL is byte-identical for identical inputs —
// which makes test assertions on exact URL shape feasible.
//
// If e.AuthorizationEndpoint already contains a query string
// (some providers carry tenant ids in the URL, e.g.,
// ?tenant=common), we append with '&' so we don't clobber.
func pkceBuildAuthURL(e providers.Entry, redirect, state, challenge string) string {
	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", e.ClientID)
	q.Set("redirect_uri", redirect)
	q.Set("state", state)
	q.Set("code_challenge", challenge)
	q.Set("code_challenge_method", "S256")
	if len(e.Scopes) > 0 {
		q.Set("scope", strings.Join(e.Scopes, " "))
	}
	if e.Audience != "" {
		q.Set("audience", e.Audience)
	}
	sep := "?"
	if strings.Contains(e.AuthorizationEndpoint, "?") {
		sep = "&"
	}
	return e.AuthorizationEndpoint + sep + q.Encode()
}

// pkceChallenge derives the S256 PKCE code_challenge from the
// supplied code_verifier per RFC 7636 §4.2:
// BASE64URL-NO-PAD(SHA256(code_verifier)).
//
// Validates: Requirement 6.2.
func pkceChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// pkceRandomBase64URL returns n cryptographically-random bytes
// rendered as base64url-no-pad. Used for both code_verifier (R6.2)
// and state (R6.3) — RFC 7636 only requires the verifier to be
// 43–128 unreserved characters, and 32 bytes of base64url is 43
// characters, so this is the minimum-length compliant verifier.
func pkceRandomBase64URL(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// pkceRandomFlowID returns a short, URL-safe flow id of the form
// "f-<12-hex-chars>". Hex (rather than base64url) is chosen so
// the id is also a valid URL path segment without escaping —
// useful if a future endpoint encodes the flow id in a path.
func pkceRandomFlowID() (string, error) {
	buf := make([]byte, 6)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return "f-" + hex.EncodeToString(buf), nil
}

// pkceIsLoopbackBind reports whether addr names the loopback
// interface. Treats the empty string and "localhost" as loopback
// (the dashboard's effective default when XALGORIX_BIND is
// unset). Strips a host:port suffix when present.
//
// Returns false for any non-loopback IPv4/IPv6 literal, including
// the wildcards 0.0.0.0 / ::, so a dashboard bound to "0.0.0.0"
// triggers paste fallback per Requirement 13.2.
func pkceIsLoopbackBind(addr string) bool {
	if addr == "" {
		return true
	}
	host := addr
	if h, _, err := net.SplitHostPort(addr); err == nil {
		host = h
	}
	if host == "" || strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	if ip == nil {
		// Non-IP, non-localhost hostnames (e.g., a Tailscale
		// MagicDNS name) are conservatively non-loopback.
		return false
	}
	return ip.IsLoopback()
}

// Compile-time assertion that *pkceDriver satisfies the Driver
// interface. Mirrors the iface_check_test.go pattern used for the
// CatalogResolver assertion.
var _ Driver = (*pkceDriver)(nil)
var _ Revoker = (*pkceDriver)(nil)
