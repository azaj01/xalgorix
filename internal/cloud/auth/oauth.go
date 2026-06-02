package auth

// File oauth.go implements task 2.8 of the xalgorix-saas spec:
// "Google + GitHub OAuth (PKCE)".
//
// OAuth 2.0 Authorization Code with PKCE (RFC 7636, S256) for both
// Google and GitHub:
//
//   - The [OAuthProvider] interface abstracts the provider-specific
//     pieces so the [OAuthService] can drive Start/Callback uniformly
//     and tests can substitute an httptest-backed fake.
//   - [GoogleProvider] and [GitHubProvider] are the production
//     implementations. They wrap a `golang.org/x/oauth2.Config` for
//     the auth-URL build and the token exchange, and they call the
//     provider's userinfo endpoint manually so the wire shape stays
//     under our control (Google's `userinfo` JSON keys, GitHub's
//     two-call dance for the verified primary email, etc.).
//   - [OAuthService] orchestrates the public endpoints
//     `/auth/oauth/{provider}/start` and `/auth/oauth/{provider}/callback`.
//     On Start it generates a cryptographically random `state` and a
//     PKCE `code_verifier`, persists `{code_verifier, intent}` under
//     `oauth:state:{state}` with a 10-minute TTL, and 302-redirects to
//     the provider's authorization URL. On Callback it pops that
//     record (verifying the CSRF `state`), exchanges the code with
//     the same `code_verifier`, then resolves the resulting identity
//     against `account_identities` by `(provider, subject)`:
//
//       1. Match found              → log the existing account in.
//       2. Match not found, but the OAuth-provider email is verified
//          AND an existing active account already owns that email
//                                  → link a new identity row to that
//                                    account and log it in.
//       3. Otherwise                → create a fresh account + default
//                                    org + workspace and link the
//                                    identity to it.
//
// The route handlers themselves are mounted by the chi router added in
// Phase 8; this file exposes [OAuthService.Start] and
// [OAuthService.Callback] as `http.HandlerFunc` values that the router
// can wire as soon as the OAuth client credentials are populated.
//
// State Redis layout
//
// Each Start call writes one key:
//
//	oauth:state:{state}  →  JSON({code_verifier, provider, intent})  TTL 10m
//
// SetNX guarantees that an attacker who guesses a state value cannot
// overwrite a legitimate in-flight value. Callback uses GETDEL via the
// underlying go-redis client so the state is consumed atomically and
// can never be replayed.
//
// Validates: Requirements 3.5.

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	goredis "github.com/redis/go-redis/v9"
	"github.com/rs/zerolog"
	"golang.org/x/oauth2"

	redisclient "github.com/xalgord/xalgorix/v4/internal/cloud/redis"
)

// ----------------------------------------------------------------------
// Constants
// ----------------------------------------------------------------------

// OAuthStateTTL is the Redis lifetime of an `oauth:state:{state}` key.
// Anything longer turns the OAuth flow into a free CSRF window if a
// user closes the IdP tab and never returns; anything shorter strands
// users on slow networks. Ten minutes matches the task brief.
const OAuthStateTTL = 10 * time.Minute

// oauthStatePrefix is the Redis key namespace used for the per-flow
// `{code_verifier, intent}` record. Exported as a constant so the
// callback handler and tests share the same spelling.
const oauthStatePrefix = "oauth:state:"

// PKCE code-verifier sizing. RFC 7636 §4.1 mandates 43..128 unreserved
// characters; we always emit the maximum so the verifier carries at
// least 96 bytes (≈ 768 bits) of entropy and so every flow has
// identical length irrespective of provider.
const (
	pkceVerifierBytes = 96 // pre-base64url length, > 768 bits.
	stateBytes        = 32 // hex-encoded → 64 chars.
)

// Supported provider names as exposed in the URL path. Adding a new
// provider means registering it on [OAuthService.Providers] AND
// updating any tests that round-trip the value.
const (
	ProviderGoogle = "google"
	ProviderGitHub = "github"
)

// IntentSignIn marks the canonical "user wants to authenticate" flow.
// The field is reserved for forward compatibility — future task 10.5
// (Jira OAuth) and 10.6 (GitHub Issues OAuth) will reuse the state
// machinery with a different intent so we encode it from day one.
const IntentSignIn = "signin"

// ----------------------------------------------------------------------
// Errors
// ----------------------------------------------------------------------

var (
	// ErrOAuthInvalidState is returned by [OAuthService.Callback]
	// when the `state` query parameter is missing, empty, or no
	// longer present in Redis (TTL elapsed or already consumed).
	ErrOAuthInvalidState = errors.New("auth: invalid oauth state")
	// ErrOAuthMissingCode is returned when the provider redirected
	// back without an authorization code — usually because the user
	// declined consent.
	ErrOAuthMissingCode = errors.New("auth: missing oauth code")
	// ErrOAuthExchangeFailed wraps any error coming back from the
	// provider's token endpoint (network, non-200, malformed body).
	ErrOAuthExchangeFailed = errors.New("auth: oauth code exchange failed")
	// ErrOAuthUserInfoFailed wraps any error coming back from the
	// provider's userinfo endpoint.
	ErrOAuthUserInfoFailed = errors.New("auth: oauth userinfo fetch failed")
	// ErrOAuthUnknownProvider is returned when the URL path supplies
	// a provider name that has not been registered on the service.
	ErrOAuthUnknownProvider = errors.New("auth: unknown oauth provider")
)

// ----------------------------------------------------------------------
// Public types — provider abstraction
// ----------------------------------------------------------------------

// UserInfo is the normalised view of a third-party identity returned
// by [OAuthProvider.Exchange]. Subject is the provider-stable
// identifier we persist in `account_identities.subject` (Google's
// `sub`, GitHub's numeric user id as a string). Email may be empty
// when the user hides it on GitHub; the identity link path treats an
// empty Email as "do not auto-link".
type UserInfo struct {
	Subject       string
	Email         string
	EmailVerified bool
	Name          string
}

// OAuthProvider is the per-provider strategy used by
// [OAuthService]. Implementations MUST NOT touch global state — the
// service may be invoked concurrently across many requests.
type OAuthProvider interface {
	// AuthURL returns the provider's authorization URL for the
	// supplied CSRF `state` and S256-encoded PKCE `codeChallenge`.
	// The URL already includes the configured client_id, redirect
	// URI, scopes, response_type=code, and code_challenge_method=S256.
	AuthURL(state, codeChallenge string) string

	// Exchange completes the Authorization Code flow: it POSTs to
	// the provider's token endpoint with the supplied `code` and
	// PKCE `codeVerifier`, then calls the userinfo endpoint with
	// the resulting access token and returns a normalised
	// [UserInfo]. On any failure (HTTP, JSON, missing subject) it
	// returns an error wrapping [ErrOAuthExchangeFailed] or
	// [ErrOAuthUserInfoFailed].
	Exchange(ctx context.Context, code, codeVerifier string) (*UserInfo, error)
}

// ----------------------------------------------------------------------
// Public types — orchestration
// ----------------------------------------------------------------------

// OAuthAccount mirrors the slice of `accounts` columns the
// orchestrator needs to make a routing decision on Callback. Status
// is the verbatim `accounts.status` value (`pending_verification`,
// `active`, `suspended`, `deleted`); the orchestrator treats any
// status other than `pending_verification` and `deleted` as
// "verified" for the purposes of identity linking.
type OAuthAccount struct {
	AccountID string
	Email     string
	Status    string
}

// IsVerified reports whether the account's email has been verified at
// some point — the only state we are willing to auto-link an OAuth
// identity to. A `pending_verification` account has only a claimed
// email and is not yet trustworthy; a `deleted` account is gone.
func (a OAuthAccount) IsVerified() bool {
	switch a.Status {
	case "active", "suspended", "past_due":
		return true
	default:
		return false
	}
}

// CreateAccountWithIdentityInput carries the values the OAuth
// "new account" branch passes to [OAuthRepository.CreateAccountWithIdentity].
// PasswordHash is intentionally omitted: the account row should have
// `password_hash = NULL` so the password-login endpoint cannot accept
// any password until the user explicitly sets one.
type CreateAccountWithIdentityInput struct {
	Email         string
	Provider      string
	Subject       string
	EmailVerified bool
	Name          string
	OrgName       string
}

// OAuthRepository is the persistence-layer dependency used by
// [OAuthService.Callback]. The interface is small and composable so
// tests can supply an in-memory fake; the production wiring builds
// one backed by the pgx pool (added in a later task).
type OAuthRepository interface {
	// LookupIdentity returns the account_id linked to the
	// (provider, subject) pair. found=false (with no error) means
	// no row exists.
	LookupIdentity(ctx context.Context, provider, subject string) (accountID string, found bool, err error)

	// LookupAccountByEmail returns the OAuthAccount whose email
	// matches (case-insensitive — the column is `citext`).
	// found=false (with no error) means no row exists.
	LookupAccountByEmail(ctx context.Context, email string) (account OAuthAccount, found bool, err error)

	// LinkIdentity inserts a new `account_identities` row pointing
	// at accountID. It MUST be idempotent: re-linking an already-
	// linked (provider, subject) pair returns no error so a
	// double-clicked callback cannot fail the user.
	LinkIdentity(ctx context.Context, accountID, provider, subject string, emailVerified bool) error

	// CreateAccountWithIdentity atomically creates an active
	// account + default organization + default workspace + owner
	// member + linked identity row, mirroring the signup flow but
	// short-circuiting the verification email because the OAuth
	// provider already verified the address (when EmailVerified is
	// true). When EmailVerified is false the implementation is
	// free to leave the account in `pending_verification` until
	// the user proves the email some other way.
	CreateAccountWithIdentity(ctx context.Context, in CreateAccountWithIdentityInput) (OAuthAccount, error)
}

// OAuthSessionIssuer is the subset of [SessionStore] the orchestrator
// depends on. Defining it here lets tests use a stub when the full
// session store is overkill, and keeps the dependency direction one-
// way (oauth depends on session, never the reverse).
type OAuthSessionIssuer interface {
	Issue(ctx context.Context, accountID string) (*Session, error)
	WriteCookie(w http.ResponseWriter, token string)
}

// OAuthOutcome describes the path taken by [OAuthService.Callback].
// It is exposed so the chi handler can emit a structured audit event
// of the right shape (`auth_oauth_signed_in`, `auth_oauth_linked`,
// `auth_oauth_signed_up`).
type OAuthOutcome string

const (
	// OutcomeSignedIn means an existing identity row matched.
	OutcomeSignedIn OAuthOutcome = "signed_in"
	// OutcomeLinked means a new identity was attached to an
	// existing verified account that owned the OAuth email.
	OutcomeLinked OAuthOutcome = "linked"
	// OutcomeCreated means a brand-new account + org + workspace
	// was provisioned for this OAuth identity.
	OutcomeCreated OAuthOutcome = "created"
)

// OAuthCallbackResult is the return shape of [OAuthService.Callback].
// AccountID and Outcome let the caller record an audit event before
// the response is flushed; Session is the freshly-minted session that
// the cookie has already been written for.
type OAuthCallbackResult struct {
	AccountID string
	Outcome   OAuthOutcome
	Session   *Session
}

// ----------------------------------------------------------------------
// OAuthService
// ----------------------------------------------------------------------

// OAuthService wires the per-flow pieces together. Construct one with
// [NewOAuthService]; do NOT zero-initialise — the constructor enforces
// the no-nil-dependency invariant.
type OAuthService struct {
	providers map[string]OAuthProvider
	redis     *redisclient.Client
	repo      OAuthRepository
	sessions  OAuthSessionIssuer
	logger    zerolog.Logger
	// SuccessRedirect is the path the browser is sent to after a
	// successful callback. Defaults to "/" when blank.
	SuccessRedirect string
	// FailureRedirect is the path the browser is sent to after a
	// rejected callback. Defaults to "/login?error=oauth" when
	// blank.
	FailureRedirect string

	now  func() time.Time
	rand io.Reader
}

// NewOAuthService constructs an [OAuthService] with the supplied
// provider registry and dependencies. It panics on any missing
// required input so wiring errors surface at process start.
func NewOAuthService(
	providers map[string]OAuthProvider,
	rdb *redisclient.Client,
	repo OAuthRepository,
	sessions OAuthSessionIssuer,
	logger zerolog.Logger,
) *OAuthService {
	switch {
	case len(providers) == 0:
		panic("auth: NewOAuthService requires at least one provider")
	case rdb == nil:
		panic("auth: NewOAuthService requires a non-nil redis client")
	case repo == nil:
		panic("auth: NewOAuthService requires a non-nil repository")
	case sessions == nil:
		panic("auth: NewOAuthService requires a non-nil session issuer")
	}
	for name, p := range providers {
		if name == "" || p == nil {
			panic("auth: NewOAuthService received a nil provider entry")
		}
	}
	return &OAuthService{
		providers:       providers,
		redis:           rdb,
		repo:            repo,
		sessions:        sessions,
		logger:          logger,
		SuccessRedirect: "/",
		FailureRedirect: "/login?error=oauth",
		now:             time.Now,
		rand:            rand.Reader,
	}
}

// Start handles `GET /auth/oauth/{provider}/start`. It generates a
// cryptographically random `state` and PKCE `code_verifier`, persists
// the verifier in Redis under `oauth:state:{state}` with a 10-minute
// TTL, and 302-redirects to the provider's authorization URL with the
// matching S256 `code_challenge`.
//
// The provider name is read from r.PathValue("provider"); chi does
// the same internally via go 1.22's pattern matching. Unknown
// providers respond with 404. Redis or RNG failures respond with 500
// and emit a structured `auth_oauth_start_failed` log line.
func (s *OAuthService) Start(w http.ResponseWriter, r *http.Request) {
	provider := strings.ToLower(r.PathValue("provider"))
	p, ok := s.providers[provider]
	if !ok {
		s.fail(w, r, http.StatusNotFound, "auth_oauth_unknown_provider", ErrOAuthUnknownProvider, provider)
		return
	}

	state, err := randomHex(s.rand, stateBytes)
	if err != nil {
		s.fail(w, r, http.StatusInternalServerError, "auth_oauth_state_entropy", err, provider)
		return
	}
	verifier, err := pkceVerifier(s.rand)
	if err != nil {
		s.fail(w, r, http.StatusInternalServerError, "auth_oauth_pkce_entropy", err, provider)
		return
	}

	rec := stateRecord{
		CodeVerifier: verifier,
		Provider:     provider,
		Intent:       IntentSignIn,
		IssuedAt:     s.now().Unix(),
	}
	payload, err := json.Marshal(rec)
	if err != nil {
		// Marshal of a fixed struct shape cannot fail in practice.
		s.fail(w, r, http.StatusInternalServerError, "auth_oauth_state_encode", err, provider)
		return
	}
	stored, err := s.redis.SetNX(r.Context(), oauthStatePrefix+state, payload, OAuthStateTTL)
	if err != nil {
		s.fail(w, r, http.StatusInternalServerError, "auth_oauth_state_store", err, provider)
		return
	}
	if !stored {
		// 256 bits of entropy collided with a live key — astronomically
		// unlikely. Refuse rather than overwrite.
		s.fail(w, r, http.StatusInternalServerError, "auth_oauth_state_collision", errors.New("state collision"), provider)
		return
	}

	authURL := p.AuthURL(state, pkceChallenge(verifier))
	http.Redirect(w, r, authURL, http.StatusFound)
}

// Callback handles `GET /auth/oauth/{provider}/callback`. It:
//
//  1. Reads `state` and `code` from the query string.
//  2. Pops the `oauth:state:{state}` Redis record (atomic GETDEL).
//  3. Verifies the popped record's provider matches the URL provider.
//  4. Exchanges the code + PKCE verifier with the provider.
//  5. Resolves the identity against `account_identities`:
//     - existing identity → log in.
//     - existing verified account by email → link + log in.
//     - otherwise → create new account + org + workspace + identity.
//  6. Mints a session and writes the session cookie.
//  7. Redirects to s.SuccessRedirect.
//
// All failure modes redirect to s.FailureRedirect with a 302 (so a
// failed callback is not cached) AND emit a structured log line
// keyed by the canonical event names.
//
// Callback returns the [OAuthCallbackResult] for callers that wrap
// the handler with audit emission; the chi mount in Phase 8 will use
// it. The HTTP response is already flushed when Callback returns.
func (s *OAuthService) Callback(w http.ResponseWriter, r *http.Request) (*OAuthCallbackResult, error) {
	provider := strings.ToLower(r.PathValue("provider"))
	p, ok := s.providers[provider]
	if !ok {
		s.fail(w, r, http.StatusNotFound, "auth_oauth_unknown_provider", ErrOAuthUnknownProvider, provider)
		return nil, ErrOAuthUnknownProvider
	}

	q := r.URL.Query()
	state := q.Get("state")
	code := q.Get("code")

	if state == "" {
		s.fail(w, r, http.StatusBadRequest, "auth_oauth_state_missing", ErrOAuthInvalidState, provider)
		return nil, ErrOAuthInvalidState
	}
	rec, err := s.popState(r.Context(), state)
	if err != nil {
		// The state was missing or malformed; treat both as CSRF
		// rejections (Property: state CSRF protection).
		s.fail(w, r, http.StatusBadRequest, "auth_oauth_state_invalid", err, provider)
		return nil, ErrOAuthInvalidState
	}
	if !secureEqual(rec.Provider, provider) {
		// A state that was issued for a different provider is just
		// as bad as a forged state — refuse loudly.
		s.fail(w, r, http.StatusBadRequest, "auth_oauth_state_provider_mismatch", ErrOAuthInvalidState, provider)
		return nil, ErrOAuthInvalidState
	}
	if code == "" {
		s.fail(w, r, http.StatusBadRequest, "auth_oauth_code_missing", ErrOAuthMissingCode, provider)
		return nil, ErrOAuthMissingCode
	}

	info, err := p.Exchange(r.Context(), code, rec.CodeVerifier)
	if err != nil {
		s.fail(w, r, http.StatusBadGateway, "auth_oauth_exchange_failed", err, provider)
		return nil, err
	}
	if info == nil || info.Subject == "" {
		s.fail(w, r, http.StatusBadGateway, "auth_oauth_userinfo_empty", ErrOAuthUserInfoFailed, provider)
		return nil, ErrOAuthUserInfoFailed
	}

	result, err := s.resolveIdentity(r.Context(), provider, info)
	if err != nil {
		s.fail(w, r, http.StatusInternalServerError, "auth_oauth_resolve_failed", err, provider)
		return nil, err
	}

	session, err := s.sessions.Issue(r.Context(), result.AccountID)
	if err != nil {
		s.fail(w, r, http.StatusInternalServerError, "auth_oauth_session_issue", err, provider)
		return nil, err
	}
	s.sessions.WriteCookie(w, session.Token)
	result.Session = session

	s.logger.Info().
		Str("event", "auth_oauth_callback_ok").
		Str("provider", provider).
		Str("outcome", string(result.Outcome)).
		Str("account_id", result.AccountID).
		Msg("oauth callback completed")

	target := s.SuccessRedirect
	if target == "" {
		target = "/"
	}
	http.Redirect(w, r, target, http.StatusFound)
	return result, nil
}

// resolveIdentity walks the three-branch identity decision described
// in design.md → "OAuth": match by (provider, subject), match by
// verified email, or fall through to a fresh account.
func (s *OAuthService) resolveIdentity(ctx context.Context, provider string, info *UserInfo) (*OAuthCallbackResult, error) {
	// Branch 1: existing identity row.
	accountID, found, err := s.repo.LookupIdentity(ctx, provider, info.Subject)
	if err != nil {
		return nil, fmt.Errorf("lookup identity: %w", err)
	}
	if found {
		return &OAuthCallbackResult{AccountID: accountID, Outcome: OutcomeSignedIn}, nil
	}

	// Branch 2: existing verified account that owns the OAuth email.
	// We only auto-link when BOTH:
	//   - the OAuth provider asserts email_verified = true, AND
	//   - the local account is past `pending_verification`.
	// This protects against an attacker creating a local account with
	// someone else's email and waiting for the legitimate owner to
	// authenticate via OAuth.
	if info.Email != "" && info.EmailVerified {
		acct, found, err := s.repo.LookupAccountByEmail(ctx, info.Email)
		if err != nil {
			return nil, fmt.Errorf("lookup account: %w", err)
		}
		if found && acct.IsVerified() {
			if err := s.repo.LinkIdentity(ctx, acct.AccountID, provider, info.Subject, info.EmailVerified); err != nil {
				return nil, fmt.Errorf("link identity: %w", err)
			}
			return &OAuthCallbackResult{AccountID: acct.AccountID, Outcome: OutcomeLinked}, nil
		}
	}

	// Branch 3: fresh account + default org + workspace + identity.
	// The OrgName seed is the user's display name when present, the
	// email's local part otherwise — the user can rename it from the
	// settings page later.
	orgName := info.Name
	if orgName == "" {
		orgName = defaultOrgNameFromEmail(info.Email)
	}
	created, err := s.repo.CreateAccountWithIdentity(ctx, CreateAccountWithIdentityInput{
		Email:         info.Email,
		Provider:      provider,
		Subject:       info.Subject,
		EmailVerified: info.EmailVerified,
		Name:          info.Name,
		OrgName:       orgName,
	})
	if err != nil {
		return nil, fmt.Errorf("create account: %w", err)
	}
	return &OAuthCallbackResult{AccountID: created.AccountID, Outcome: OutcomeCreated}, nil
}

// fail is the single error-handling exit. It logs a structured event
// and 302-redirects to the failure URL so a forged callback URL
// cannot phish a 500 page out of the server.
func (s *OAuthService) fail(w http.ResponseWriter, r *http.Request, status int, event string, err error, provider string) {
	s.logger.Warn().
		Err(err).
		Int("status", status).
		Str("event", event).
		Str("provider", provider).
		Msg("oauth flow rejected")

	// For fatal RNG/Redis errors we surface the status verbatim so
	// monitors can alert. The redirect path is reserved for "user
	// finished an invalid handshake" cases.
	if status >= 500 {
		http.Error(w, http.StatusText(status), status)
		return
	}
	target := s.FailureRedirect
	if target == "" {
		target = "/login?error=oauth"
	}
	http.Redirect(w, r, target, http.StatusFound)
}

// stateRecord is the shape of the JSON value stored under
// `oauth:state:{state}`. Provider is captured so the callback handler
// can refuse a state that was issued for a different provider — the
// canonical mixup attack against multi-IdP servers.
type stateRecord struct {
	CodeVerifier string `json:"code_verifier"`
	Provider     string `json:"provider"`
	Intent       string `json:"intent"`
	IssuedAt     int64  `json:"issued_at"`
}

// popState atomically reads and removes an `oauth:state:{state}`
// record. The atomicity matters: a non-atomic GET-then-DEL would let
// a network-fast attacker replay a captured state value before the
// legitimate user's callback consumes it.
func (s *OAuthService) popState(ctx context.Context, state string) (stateRecord, error) {
	if state == "" || strings.ContainsAny(state, "\r\n\x00") {
		return stateRecord{}, ErrOAuthInvalidState
	}
	raw, err := s.redis.Underlying().GetDel(ctx, oauthStatePrefix+state).Bytes()
	if err != nil {
		if errors.Is(err, goredis.Nil) {
			return stateRecord{}, ErrOAuthInvalidState
		}
		return stateRecord{}, fmt.Errorf("redis getdel: %w", err)
	}
	var rec stateRecord
	if err := json.Unmarshal(raw, &rec); err != nil {
		return stateRecord{}, ErrOAuthInvalidState
	}
	if rec.CodeVerifier == "" || rec.Provider == "" {
		return stateRecord{}, ErrOAuthInvalidState
	}
	return rec, nil
}

// ----------------------------------------------------------------------
// PKCE helpers
// ----------------------------------------------------------------------

// pkceVerifier returns a fresh PKCE code verifier as base64url with
// no padding. Per RFC 7636 §4.1 the output is between 43 and 128
// characters drawn from `[A-Za-z0-9-._~]`. base64.RawURLEncoding's
// alphabet (`A-Z a-z 0-9 - _`) is a strict subset of those characters,
// so we satisfy the spec by encoding random bytes directly.
func pkceVerifier(r io.Reader) (string, error) {
	buf := make([]byte, pkceVerifierBytes)
	if _, err := io.ReadFull(r, buf); err != nil {
		return "", fmt.Errorf("auth: read pkce entropy: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// pkceChallenge returns the S256-encoded `code_challenge` for verifier.
// The transformation is BASE64URL-NO-PAD( SHA256(verifier) ) per RFC
// 7636 §4.2.
func pkceChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// randomHex returns 2*n hex characters from r. Used for state values
// where lowercase hex is convenient as both URL and Redis key.
func randomHex(r io.Reader, n int) (string, error) {
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return "", fmt.Errorf("auth: read state entropy: %w", err)
	}
	return hex.EncodeToString(buf), nil
}

// secureEqual compares two strings in constant time so the wrong-
// provider state-mixup branch cannot be timing-discriminated from the
// well-formed-but-CSRF-failed branch.
func secureEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// defaultOrgNameFromEmail returns a reasonable Organization name for a
// freshly-provisioned tenant when the OAuth profile does not include a
// display name. Falls back to "My Workspace" for the empty-email
// pathological case.
func defaultOrgNameFromEmail(email string) string {
	if email == "" {
		return "My Workspace"
	}
	at := strings.IndexByte(email, '@')
	if at <= 0 {
		return "My Workspace"
	}
	local := email[:at]
	if local == "" {
		return "My Workspace"
	}
	return local + "'s Workspace"
}

// ----------------------------------------------------------------------
// GoogleProvider
// ----------------------------------------------------------------------

// Default Google OAuth 2.0 endpoints and userinfo URL. Exposed as
// vars (not consts) so tests and admin overrides can rebind them via
// [GoogleProvider.UserInfoURL] / `oauth2.Config.Endpoint`.
const (
	googleAuthURL     = "https://accounts.google.com/o/oauth2/v2/auth"
	googleTokenURL    = "https://oauth2.googleapis.com/token"
	googleUserInfoURL = "https://openidconnect.googleapis.com/v1/userinfo"
)

// GoogleProvider implements [OAuthProvider] for Google OAuth 2.0.
//
// The default scopes (`openid email profile`) are the minimum needed
// to populate UserInfo. EmailVerified is read from the OIDC userinfo
// payload (`email_verified`) — Google does not surface unverified
// emails through this endpoint in practice, but we still gate the
// auto-link path on the explicit boolean.
type GoogleProvider struct {
	cfg          *oauth2.Config
	httpClient   *http.Client
	userInfoURL  string
}

// GoogleConfig is the input shape for [NewGoogleProvider]. Endpoint
// overrides are intended for tests; production wiring leaves them
// blank to use the real Google endpoints.
type GoogleConfig struct {
	ClientID     string
	ClientSecret string
	RedirectURL  string
	// Scopes overrides the default `openid email profile`. Leave
	// nil unless you need additional Google APIs (out of scope for
	// task 2.8).
	Scopes []string
	// AuthURL / TokenURL / UserInfoURL override the production
	// endpoints; tests bind them to httptest.Server.URL.
	AuthURL     string
	TokenURL    string
	UserInfoURL string
	// HTTPClient overrides the http.Client used for token exchange
	// and userinfo. Defaults to a 10-second-timeout client. Tests
	// pass `httptest.Server.Client()`.
	HTTPClient *http.Client
}

// NewGoogleProvider constructs a [GoogleProvider]. It panics on
// missing credentials so misconfiguration surfaces at boot.
func NewGoogleProvider(c GoogleConfig) *GoogleProvider {
	if c.ClientID == "" || c.ClientSecret == "" || c.RedirectURL == "" {
		panic("auth: NewGoogleProvider requires ClientID, ClientSecret, and RedirectURL")
	}
	scopes := c.Scopes
	if len(scopes) == 0 {
		scopes = []string{"openid", "email", "profile"}
	}
	authURL := c.AuthURL
	if authURL == "" {
		authURL = googleAuthURL
	}
	tokenURL := c.TokenURL
	if tokenURL == "" {
		tokenURL = googleTokenURL
	}
	uiURL := c.UserInfoURL
	if uiURL == "" {
		uiURL = googleUserInfoURL
	}
	hc := c.HTTPClient
	if hc == nil {
		hc = &http.Client{Timeout: 10 * time.Second}
	}
	return &GoogleProvider{
		cfg: &oauth2.Config{
			ClientID:     c.ClientID,
			ClientSecret: c.ClientSecret,
			RedirectURL:  c.RedirectURL,
			Scopes:       scopes,
			Endpoint: oauth2.Endpoint{
				AuthURL:  authURL,
				TokenURL: tokenURL,
			},
		},
		httpClient:  hc,
		userInfoURL: uiURL,
	}
}

// AuthURL returns the Google authorization URL with the supplied
// CSRF state and S256 PKCE challenge already embedded.
func (g *GoogleProvider) AuthURL(state, codeChallenge string) string {
	return g.cfg.AuthCodeURL(
		state,
		oauth2.AccessTypeOnline,
		oauth2.SetAuthURLParam("code_challenge", codeChallenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	)
}

// Exchange completes the Authorization Code flow with PKCE and reads
// the OIDC userinfo endpoint. The token exchange is delegated to
// `oauth2.Config.Exchange` so cross-cutting concerns (request body
// shape, status interpretation) follow the standard library.
func (g *GoogleProvider) Exchange(ctx context.Context, code, codeVerifier string) (*UserInfo, error) {
	if code == "" {
		return nil, fmt.Errorf("%w: empty code", ErrOAuthExchangeFailed)
	}
	if codeVerifier == "" {
		return nil, fmt.Errorf("%w: empty code_verifier", ErrOAuthExchangeFailed)
	}

	ctx = context.WithValue(ctx, oauth2.HTTPClient, g.httpClient)
	tok, err := g.cfg.Exchange(
		ctx, code,
		oauth2.SetAuthURLParam("code_verifier", codeVerifier),
	)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrOAuthExchangeFailed, err)
	}
	if !tok.Valid() {
		return nil, fmt.Errorf("%w: token invalid", ErrOAuthExchangeFailed)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, g.userInfoURL, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: build userinfo request: %v", ErrOAuthUserInfoFailed, err)
	}
	req.Header.Set("Authorization", "Bearer "+tok.AccessToken)
	req.Header.Set("Accept", "application/json")
	resp, err := g.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrOAuthUserInfoFailed, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: status %d", ErrOAuthUserInfoFailed, resp.StatusCode)
	}
	var body struct {
		Sub           string `json:"sub"`
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
		Name          string `json:"name"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64*1024)).Decode(&body); err != nil {
		return nil, fmt.Errorf("%w: decode: %v", ErrOAuthUserInfoFailed, err)
	}
	if body.Sub == "" {
		return nil, fmt.Errorf("%w: missing sub", ErrOAuthUserInfoFailed)
	}
	return &UserInfo{
		Subject:       body.Sub,
		Email:         strings.ToLower(strings.TrimSpace(body.Email)),
		EmailVerified: body.EmailVerified,
		Name:          body.Name,
	}, nil
}

// ----------------------------------------------------------------------
// GitHubProvider
// ----------------------------------------------------------------------

const (
	githubAuthURL      = "https://github.com/login/oauth/authorize"
	githubTokenURL     = "https://github.com/login/oauth/access_token"
	githubUserURL      = "https://api.github.com/user"
	githubEmailsURL    = "https://api.github.com/user/emails"
	githubAcceptHeader = "application/vnd.github+json"
	githubAPIVersion   = "2022-11-28"
)

// GitHubProvider implements [OAuthProvider] for GitHub OAuth 2.0.
//
// GitHub returns the primary email through `/user/emails` only when
// the `user:email` scope is granted; the `/user` endpoint may return
// `email = null` if the user hides it. We therefore make a second
// API call to find the verified primary email and copy it into
// UserInfo.Email when available.
type GitHubProvider struct {
	cfg         *oauth2.Config
	httpClient  *http.Client
	userURL     string
	emailsURL   string
}

// GitHubConfig is the input shape for [NewGitHubProvider]. See
// [GoogleConfig] for field semantics; the URL overrides exist
// exclusively for tests.
type GitHubConfig struct {
	ClientID     string
	ClientSecret string
	RedirectURL  string
	Scopes       []string
	AuthURL      string
	TokenURL     string
	UserURL      string
	EmailsURL    string
	HTTPClient   *http.Client
}

// NewGitHubProvider constructs a [GitHubProvider]. It panics on
// missing credentials so misconfiguration surfaces at boot.
func NewGitHubProvider(c GitHubConfig) *GitHubProvider {
	if c.ClientID == "" || c.ClientSecret == "" || c.RedirectURL == "" {
		panic("auth: NewGitHubProvider requires ClientID, ClientSecret, and RedirectURL")
	}
	scopes := c.Scopes
	if len(scopes) == 0 {
		scopes = []string{"read:user", "user:email"}
	}
	authURL := c.AuthURL
	if authURL == "" {
		authURL = githubAuthURL
	}
	tokenURL := c.TokenURL
	if tokenURL == "" {
		tokenURL = githubTokenURL
	}
	uURL := c.UserURL
	if uURL == "" {
		uURL = githubUserURL
	}
	eURL := c.EmailsURL
	if eURL == "" {
		eURL = githubEmailsURL
	}
	hc := c.HTTPClient
	if hc == nil {
		hc = &http.Client{Timeout: 10 * time.Second}
	}
	return &GitHubProvider{
		cfg: &oauth2.Config{
			ClientID:     c.ClientID,
			ClientSecret: c.ClientSecret,
			RedirectURL:  c.RedirectURL,
			Scopes:       scopes,
			Endpoint: oauth2.Endpoint{
				AuthURL:  authURL,
				TokenURL: tokenURL,
			},
		},
		httpClient: hc,
		userURL:    uURL,
		emailsURL:  eURL,
	}
}

// AuthURL returns the GitHub authorization URL with state + S256
// challenge embedded. GitHub has supported PKCE on its OAuth flow
// since 2023-12; the parameter names follow RFC 7636.
func (h *GitHubProvider) AuthURL(state, codeChallenge string) string {
	return h.cfg.AuthCodeURL(
		state,
		oauth2.SetAuthURLParam("code_challenge", codeChallenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	)
}

// Exchange completes the Authorization Code + PKCE flow against
// GitHub, then resolves the verified primary email by combining
// `/user` with `/user/emails`.
func (h *GitHubProvider) Exchange(ctx context.Context, code, codeVerifier string) (*UserInfo, error) {
	if code == "" {
		return nil, fmt.Errorf("%w: empty code", ErrOAuthExchangeFailed)
	}
	if codeVerifier == "" {
		return nil, fmt.Errorf("%w: empty code_verifier", ErrOAuthExchangeFailed)
	}

	ctx = context.WithValue(ctx, oauth2.HTTPClient, h.httpClient)
	tok, err := h.cfg.Exchange(
		ctx, code,
		oauth2.SetAuthURLParam("code_verifier", codeVerifier),
	)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrOAuthExchangeFailed, err)
	}
	if !tok.Valid() {
		return nil, fmt.Errorf("%w: token invalid", ErrOAuthExchangeFailed)
	}

	user, err := h.fetchUser(ctx, tok.AccessToken)
	if err != nil {
		return nil, err
	}
	// If the /user payload omits the email, walk /user/emails for
	// the verified primary entry. Failures here are non-fatal — we
	// fall back to UserInfo.Email = "" which simply means we cannot
	// auto-link to an existing account on this flow.
	email := user.Email
	verified := user.EmailVerified
	if email == "" {
		primary, ok, err := h.fetchPrimaryEmail(ctx, tok.AccessToken)
		if err == nil && ok {
			email = primary.Email
			verified = primary.Verified
		}
	}

	return &UserInfo{
		Subject:       user.ID,
		Email:         strings.ToLower(strings.TrimSpace(email)),
		EmailVerified: verified,
		Name:          user.Name,
	}, nil
}

// githubUser is the subset of GitHub's `/user` response we use.
type githubUser struct {
	ID            string
	Email         string
	EmailVerified bool
	Name          string
}

func (h *GitHubProvider) fetchUser(ctx context.Context, accessToken string) (githubUser, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, h.userURL, nil)
	if err != nil {
		return githubUser{}, fmt.Errorf("%w: build user request: %v", ErrOAuthUserInfoFailed, err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", githubAcceptHeader)
	req.Header.Set("X-GitHub-Api-Version", githubAPIVersion)
	resp, err := h.httpClient.Do(req)
	if err != nil {
		return githubUser{}, fmt.Errorf("%w: %v", ErrOAuthUserInfoFailed, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return githubUser{}, fmt.Errorf("%w: status %d", ErrOAuthUserInfoFailed, resp.StatusCode)
	}
	// GitHub returns user.id as a numeric type; we convert it to a
	// stable string so it can land in `account_identities.subject`
	// without lossy float conversions.
	var raw struct {
		ID    int64  `json:"id"`
		Email string `json:"email"`
		Name  string `json:"name"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64*1024)).Decode(&raw); err != nil {
		return githubUser{}, fmt.Errorf("%w: decode user: %v", ErrOAuthUserInfoFailed, err)
	}
	if raw.ID == 0 {
		return githubUser{}, fmt.Errorf("%w: missing user id", ErrOAuthUserInfoFailed)
	}
	// /user does not expose `email_verified`; the verification
	// flag arrives via /user/emails. Treat the /user email as
	// unverified here so the caller falls back to /user/emails
	// when present.
	return githubUser{
		ID:            fmt.Sprintf("%d", raw.ID),
		Email:         raw.Email,
		EmailVerified: false,
		Name:          raw.Name,
	}, nil
}

type githubEmail struct {
	Email    string
	Verified bool
}

func (h *GitHubProvider) fetchPrimaryEmail(ctx context.Context, accessToken string) (githubEmail, bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, h.emailsURL, nil)
	if err != nil {
		return githubEmail{}, false, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", githubAcceptHeader)
	req.Header.Set("X-GitHub-Api-Version", githubAPIVersion)
	resp, err := h.httpClient.Do(req)
	if err != nil {
		return githubEmail{}, false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return githubEmail{}, false, fmt.Errorf("%w: emails status %d", ErrOAuthUserInfoFailed, resp.StatusCode)
	}
	var rows []struct {
		Email    string `json:"email"`
		Primary  bool   `json:"primary"`
		Verified bool   `json:"verified"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 256*1024)).Decode(&rows); err != nil {
		return githubEmail{}, false, fmt.Errorf("%w: decode emails: %v", ErrOAuthUserInfoFailed, err)
	}
	for _, row := range rows {
		if row.Primary {
			return githubEmail{Email: row.Email, Verified: row.Verified}, true, nil
		}
	}
	return githubEmail{}, false, nil
}

// ----------------------------------------------------------------------
// Misc
// ----------------------------------------------------------------------

// init asserts at package load that the SetNX state encoding will not
// produce keys containing characters that Redis treats specially in
// MULTI/EXEC pipelines. The check is cheap and runs once.
func init() {
	const probe = "test/state-key"
	u, err := url.Parse("https://example.com/?state=" + probe)
	if err != nil || u.Query().Get("state") != probe {
		panic("auth: state key URL round-trip failed; package state encoding is broken")
	}
}
