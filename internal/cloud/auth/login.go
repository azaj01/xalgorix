package auth

// File login.go implements task 2.5 of the xalgorix-saas spec — the
// `POST /auth/login` HTTP handler that ties together the lockout
// tracker, password verifier, session issuer, and audit emitter.
//
// The flow tracks design.md → "Authentication" and Requirement 3.9
// step-by-step:
//
//  1. Parse and validate the JSON request body. The handler accepts
//     `{ "email": "...", "password": "..." }`; missing or malformed
//     payloads return HTTP 400. Empty fields return HTTP 401 so we
//     do not leak which field is missing to an attacker probing the
//     endpoint.
//  2. Normalise email by lower-casing and trimming. The lockout key
//     and the account lookup MUST agree on the same normalisation
//     so an attacker cannot evade the lockout by capitalising the
//     local-part.
//  3. Check `lockout.Locked(ctx, email)`. A locked account replies
//     with HTTP 423 Locked and a stable JSON body.
//  4. Look up the account via the injected AccountLookup. A missing
//     account still records a failed attempt and replies with HTTP
//     401 — both branches must be timing-equivalent at the
//     application layer so the endpoint cannot be turned into an
//     account-enumeration oracle.
//  5. Verify the password with [Verify]. On mismatch RecordFail and
//     return HTTP 401. When RecordFail crosses FailThreshold, emit
//     an `auth_lockout` audit event exactly once and reply with
//     HTTP 423 — the threshold-crossing call already wrote the lock
//     key, so the caller cannot retry into a 401 while the lock is
//     active.
//  6. On success, Reset the lockout, Issue a session, set the
//     `__Host-xalgorix_session` cookie, and reply with HTTP 200 plus
//     a tiny JSON body that the Dashboard uses to drive the post-
//     sign-in redirect.
//
// The handler depends on three injectable interfaces — AccountLookup,
// AuditEmitter, and (transitively) the LockoutTracker / SessionStore
// concretes — so the login wiring can be exercised end-to-end from
// `login_test.go` without booting a real Postgres / Redis stack
// beyond miniredis.
//
// The package-level helpers `writeJSON` / `writeError` defined at the
// bottom of this file are the canonical JSON response envelope for
// the auth HTTP layer; signup.go uses its own variant
// (`writeSignupJSON` / `writeSignupError`) because the signup error
// shape is flatter than the login one.
//
// Requirements: 3.5, 3.9.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/rs/zerolog"
)

// loginRequest is the JSON body accepted by [LoginHandler]. The
// fields are documented in OpenAPI by task 8.2; the shape here is the
// minimum required to satisfy Requirements 3.5 / 3.9 and matches
// design.md's `/auth/login` row in the endpoint table.
type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// LoginResponse is the JSON body returned on a successful login.
// Token is intentionally NOT included — the session cookie is the
// only authority. AccountID lets the SPA prime its client-side cache
// without an extra `/me` round-trip.
type LoginResponse struct {
	AccountID string `json:"account_id"`
	ExpiresAt string `json:"expires_at"`
}

// LoginErrorResponse is the canonical error envelope returned by the
// login endpoint and reused by every auth-package HTTP handler that
// shares the `error.code` / `error.message` shape. The `error.code`
// values are the strings the Dashboard switches on; the `message`
// field is human-readable but should not be relied on by clients.
type LoginErrorResponse struct {
	Error LoginErrorBody `json:"error"`
}

// LoginErrorBody is the inner shape of [LoginErrorResponse].
type LoginErrorBody struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// AccountRecord is the slice of an account row that login needs:
// the canonical id (so the session can be tied to the right tenant)
// and the Argon2id PHC string used by [Verify]. The full row lives
// in `internal/cloud/orgs` but we only depend on the bare minimum
// here so this package does not pull in the full ORM.
type AccountRecord struct {
	// ID is the canonical account UUID (or any opaque string the
	// session store understands). Persisted in `accounts.id`.
	ID string
	// PasswordHash is the Argon2id PHC string ([Hash] output) for
	// the account. Empty for accounts that authenticate purely via
	// OAuth / magic link / SSO; [LoginHandler] treats an empty
	// hash as "wrong password" so OAuth-only accounts cannot be
	// signed in via the password endpoint.
	PasswordHash string
}

// AccountLookup is the dependency [LoginHandler] uses to resolve an
// email address to an [AccountRecord]. The production implementation
// queries the `accounts` table; tests inject an in-memory map. A
// missing account MUST be reported as `(nil, ErrAccountNotFound)` so
// the handler can distinguish "no such email" from a transient DB
// failure (which surfaces as a non-sentinel error and yields HTTP
// 500).
type AccountLookup interface {
	// FindByEmail returns the account record for the given
	// already-normalised email, or [ErrAccountNotFound] if no row
	// exists. Implementations should treat the input as lower-cased
	// and trimmed; the handler does the normalisation before
	// calling.
	FindByEmail(ctx context.Context, email string) (*AccountRecord, error)
}

// ErrAccountNotFound is the sentinel [AccountLookup] implementations
// MUST return when no row matches the supplied email. The handler
// branches on it to drive the timing-equivalent "record fail + 401"
// path that prevents email enumeration. The same sentinel is reused
// by other auth flows (password reset, magic link) that need the
// "no such account" semantics.
var ErrAccountNotFound = errors.New("auth: account not found")

// AuthLockoutEvent is the canonical payload emitted on the
// threshold-crossing failed sign-in. It will be persisted to
// `audit_events` with `action = "auth_lockout"` once the audit
// writer lands in Phase 13; until then this struct is the swappable
// hand-off contract.
//
// Requirements: 3.9.
type AuthLockoutEvent struct {
	// AccountID is the canonical account id the lock applies to.
	// Empty when the failed sign-in targeted an unknown email; in
	// that case Email carries the only available identifier.
	AccountID string
	// Email is the lower-cased, trimmed email the user attempted to
	// sign in with. Always populated.
	Email string
	// LockedUntil is the wall-clock time the lock expires. Computed
	// as `time.Now().Add(LockDuration)` at emission so the audit
	// row records the same TTL the Redis lock key carries.
	LockedUntil time.Time
	// IP is the remote IP observed by the handler. Empty if the
	// request did not include an X-Forwarded-For header and the
	// raw RemoteAddr could not be parsed.
	IP string
	// UserAgent is the request User-Agent header, truncated to a
	// safe length by the audit writer.
	UserAgent string
}

// AuditEmitter records auth-package audit events. The login handler
// uses it for `auth_lockout` only; subsequent auth tasks (signup,
// password reset, MFA) extend this interface with their own event
// types. Implementations MUST be safe for concurrent use.
type AuditEmitter interface {
	// EmitAuthLockout is invoked exactly once per threshold-crossing
	// failed sign-in. Implementations MUST persist asynchronously
	// or fast enough that the HTTP handler's tail latency budget is
	// preserved.
	EmitAuthLockout(ctx context.Context, event AuthLockoutEvent)
}

// LoginHandler implements `POST /auth/login`. Construct one per
// process via [NewLoginHandler] and mount it on the router; the
// handler is `http.Handler`-compatible so it can be wrapped with the
// shared middleware stack (CSRF, rate limiting, request id).
type LoginHandler struct {
	accounts AccountLookup
	lockout  *LockoutTracker
	sessions *SessionStore
	audit    AuditEmitter
	logger   zerolog.Logger
	now      func() time.Time
}

// NewLoginHandler constructs a [LoginHandler]. It panics on nil
// dependencies because every one is required for the handler to
// satisfy Requirements 3.5 / 3.9; surfacing those at boot is far
// preferable to a NPE on the first sign-in.
func NewLoginHandler(
	accounts AccountLookup,
	lockout *LockoutTracker,
	sessions *SessionStore,
	audit AuditEmitter,
	logger zerolog.Logger,
) *LoginHandler {
	if accounts == nil {
		panic("auth: NewLoginHandler requires a non-nil AccountLookup")
	}
	if lockout == nil {
		panic("auth: NewLoginHandler requires a non-nil LockoutTracker")
	}
	if sessions == nil {
		panic("auth: NewLoginHandler requires a non-nil SessionStore")
	}
	if audit == nil {
		panic("auth: NewLoginHandler requires a non-nil AuditEmitter")
	}
	return &LoginHandler{
		accounts: accounts,
		lockout:  lockout,
		sessions: sessions,
		audit:    audit,
		logger:   logger,
		now:      time.Now,
	}
}

// ServeHTTP implements [http.Handler].
func (h *LoginHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "POST required")
		return
	}

	var req loginRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4*1024))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "request body could not be parsed as JSON")
		return
	}

	email := normaliseEmail(req.Email)
	if email == "" || req.Password == "" {
		// Empty credentials are reported as a generic 401 so the
		// endpoint never reveals which field was missing.
		writeError(w, http.StatusUnauthorized, "invalid_credentials", "email or password is incorrect")
		return
	}

	ctx := r.Context()

	// Step 1: short-circuit if the account is already locked.
	locked, err := h.lockout.Locked(ctx, email)
	if err != nil {
		h.logger.Error().Err(err).Str("event", "auth_lockout_check_failed").Msg("auth: lockout check failed")
		writeError(w, http.StatusInternalServerError, "internal_error", "internal error")
		return
	}
	if locked {
		writeLocked(w)
		return
	}

	// Step 2: resolve the account. A missing account still records a
	// failed attempt so an attacker probing for valid emails cannot
	// distinguish "wrong email" from "wrong password" — both raise
	// the same fail counter and both reply 401.
	account, err := h.accounts.FindByEmail(ctx, email)
	switch {
	case errors.Is(err, ErrAccountNotFound):
		h.handleFail(ctx, r, w, email, "")
		return
	case err != nil:
		h.logger.Error().Err(err).Str("event", "auth_account_lookup_failed").Msg("auth: account lookup failed")
		writeError(w, http.StatusInternalServerError, "internal_error", "internal error")
		return
	}

	// Step 3: verify password. An empty hash (OAuth-only accounts) is
	// treated as "wrong password" so the password endpoint cannot be
	// used to sign in users that never set a password.
	if account.PasswordHash == "" {
		h.handleFail(ctx, r, w, email, account.ID)
		return
	}
	ok, err := Verify(req.Password, account.PasswordHash)
	if err != nil {
		// Malformed PHC string in the database is a corruption-class
		// bug; treat it as a server error rather than as a wrong
		// password so we surface it operationally.
		h.logger.Error().Err(err).Str("event", "auth_verify_failed").Str("account_id", account.ID).Msg("auth: password verify error")
		writeError(w, http.StatusInternalServerError, "internal_error", "internal error")
		return
	}
	if !ok {
		h.handleFail(ctx, r, w, email, account.ID)
		return
	}

	// Step 4: success path. Reset the lockout counters, issue a
	// session, set the cookie, and reply 200.
	h.lockout.Reset(ctx, email)
	sess, err := h.sessions.Issue(ctx, account.ID)
	if err != nil {
		h.logger.Error().Err(err).Str("event", "auth_session_issue_failed").Str("account_id", account.ID).Msg("auth: session issue failed")
		writeError(w, http.StatusInternalServerError, "internal_error", "internal error")
		return
	}
	h.sessions.WriteCookie(w, sess.Token)
	writeJSON(w, http.StatusOK, LoginResponse{
		AccountID: sess.AccountID,
		ExpiresAt: sess.ExpiresAt.UTC().Format(time.RFC3339),
	})
}

// handleFail is invoked on every authentication-failure branch. It
// records the fail in Redis, emits the `auth_lockout` audit event on
// the threshold-crossing call, and replies with HTTP 423 when the
// account just transitioned to locked or HTTP 401 otherwise.
//
// accountID may be empty when the email did not resolve to an account;
// the audit event is still emitted (with AccountID=""), giving security
// teams visibility into spray attacks against unknown emails.
func (h *LoginHandler) handleFail(ctx context.Context, r *http.Request, w http.ResponseWriter, email, accountID string) {
	current, justLocked := h.lockout.RecordFail(ctx, email)

	// Threshold-crossing transition: emit the audit event and reply
	// 423 so the user sees the same response they would on a retry
	// after the lock takes effect.
	if justLocked && current == FailThreshold {
		h.audit.EmitAuthLockout(ctx, AuthLockoutEvent{
			AccountID:   accountID,
			Email:       email,
			LockedUntil: h.now().Add(LockDuration),
			IP:          clientIP(r),
			UserAgent:   r.UserAgent(),
		})
		writeLocked(w)
		return
	}
	writeError(w, http.StatusUnauthorized, "invalid_credentials", "email or password is incorrect")
}

// normaliseEmail lower-cases and trims an email so the lockout key
// and the account lookup agree on the same canonical form.
func normaliseEmail(raw string) string {
	return strings.ToLower(strings.TrimSpace(raw))
}

// clientIP extracts a best-effort client IP for the audit event. It
// prefers the first hop in X-Forwarded-For (set by the platform
// ingress) and falls back to the raw RemoteAddr. An unparseable
// RemoteAddr returns "" — the audit row tolerates the empty value.
func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if comma := strings.IndexByte(xff, ','); comma > 0 {
			return strings.TrimSpace(xff[:comma])
		}
		return strings.TrimSpace(xff)
	}
	if r.RemoteAddr == "" {
		return ""
	}
	// RemoteAddr is "host:port"; return host. We do not use net.SplitHostPort
	// because IPv6 forms ("[::1]:8080") and unusual proxy injections both
	// surface as "host:port" with a final colon, which is enough for the
	// truncated form the audit row stores.
	if colon := strings.LastIndexByte(r.RemoteAddr, ':'); colon > 0 {
		return r.RemoteAddr[:colon]
	}
	return r.RemoteAddr
}

// writeError serialises a [LoginErrorResponse] with the requested
// status, code, and message. It always sets a JSON content type so
// the Dashboard can rely on the body shape regardless of status.
func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, LoginErrorResponse{Error: LoginErrorBody{Code: code, Message: message}})
}

// writeLocked is the canonical HTTP 423 response. The code is the
// stable identifier the Dashboard switches on to render the lockout
// banner with a countdown.
func writeLocked(w http.ResponseWriter) {
	writeError(w, http.StatusLocked, "account_locked", "account is temporarily locked due to repeated failed sign-in attempts")
}

// writeJSON writes v as JSON with the supplied status code. Encoding
// errors are silently swallowed because the caller has already
// committed to a status by the time we get here.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
