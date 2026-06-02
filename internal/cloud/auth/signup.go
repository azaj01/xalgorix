// Package auth — signup endpoint and verification email dispatch.
//
// This file implements task 2.4 of the xalgorix-saas spec:
//
//	POST /auth/signup
//	  body: {"email": "...", "password": "...", "org_name": "..."}
//
// Steps (per the task body in tasks.md and the sequence diagram in
// design.md → "Sequence diagrams → 1. Signup"):
//
//  1. Decode + validate the request payload.
//  2. Run [EnforcePolicy] from task 2.1 on the password; map each
//     sentinel error to HTTP 422 with a JSON body that names the
//     specific policy rule violated (Requirement 3.3).
//  3. Optionally call [Pwner.Pwned]; if the upstream reports the
//     password is pwned, reject with HTTP 422 and rule
//     "password_pwned". The HIBP check fails open by contract, so a
//     transient outage never blocks signup (design.md §"HIBP timeout
//     policy").
//  4. Hash the password with Argon2id ([Hash] from task 2.1).
//  5. In a single repository transaction, create the
//     account (status=`pending_verification`) + default organization +
//     default workspace (`default`) + members row with
//     role=`owner`. The repository handles the actual SQL, so the
//     handler stays free of any pgx coupling.
//  6. Mint a 32-byte random verification token (uppercase hex), store
//     `verify:{token} = account_id` in Redis with a 24h TTL via
//     [redisclient.Client.SetNX] (a fresh-token collision is
//     astronomically unlikely; we use SetNX anyway so a stray token
//     reuse cannot overwrite an in-flight verification).
//  7. Hand the token to the injected [EmailSender]. The signup handler
//     never speaks Resend directly; production wiring supplies a thin
//     Resend wrapper, tests substitute an in-memory fake.
//
// Email delivery is intentionally synchronous and *non-fatal*: a
// transient Resend outage must not roll back the freshly-minted
// account, otherwise duplicate-email retries lock the user out. The
// handler logs the dispatch failure and still returns 201 — the
// account exists, the verification token is stored, and a manual
// resend (task 2.7 / task 2.5 followups) can recover.
//
// Validates: Requirements 3.1, 4.1.

package auth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/mail"
	"strings"
	"time"

	"github.com/rs/zerolog"

	redisclient "github.com/xalgord/xalgorix/v4/internal/cloud/redis"
)

// VerifyTokenTTL is the lifetime of a `verify:{token}` Redis key.
// Requirement 3.1 requires "valid for 24 hours".
const VerifyTokenTTL = 24 * time.Hour

// verifyTokenBytes is the entropy of the verification token before
// hex encoding. 32 bytes (256 bits) matches the spec literally.
const verifyTokenBytes = 32

// verifyKeyPrefix is the Redis key namespace used by the verification
// flow. It is exported as a constant so the upcoming verify endpoint
// (sibling of this file) and the integration tests can share it.
const verifyKeyPrefix = "verify:"

// ----------------------------------------------------------------------
// Public types
// ----------------------------------------------------------------------

// SignupRequest is the JSON body accepted by [SignupHandler.Handle].
// Field tags are lowercase + snake_case to match the task description
// and design.md verbatim. Trimming and validation happens inside the
// handler so wire-level layout stays untouched.
type SignupRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	OrgName  string `json:"org_name"`
}

// SignupResponse is the JSON body returned on a successful signup.
// AccountID and OrgID are surfaced so the Dashboard onboarding flow
// can immediately display "check your email at <addr>" while a
// background poller watches for activation.
type SignupResponse struct {
	AccountID string `json:"account_id"`
	OrgID     string `json:"org_id"`
}

// SignupErrorResponse is the JSON body returned for every 4xx response
// from the signup handler. Rule names the violated policy clause so
// the API contract aligns with Requirement 3.3 and matches the test
// fixtures wired in signup_test.go.
type SignupErrorResponse struct {
	Error string `json:"error"`
	Rule  string `json:"rule,omitempty"`
}

// SignupAccount captures the row inserted in `accounts` plus the
// organization + workspace tied to the freshly-created Owner. The
// repository populates every field; the handler treats it as opaque
// for everything except AccountID + OrgID + Email (the latter two are
// part of the response or the verification email).
type SignupAccount struct {
	AccountID   string
	OrgID       string
	WorkspaceID string
	Email       string
}

// SignupRepository is the storage-side dependency the handler uses to
// persist the new tenant. Implementations are expected to perform the
// account + org + workspace + member inserts inside a single
// transaction so a partial failure cannot leave a half-built tenant.
//
// Implementations MUST surface a duplicate-email collision as
// [ErrDuplicateEmail] so the handler can render a stable HTTP 409
// without sniffing pgx error codes.
type SignupRepository interface {
	// CreateAccountWithOrg atomically creates:
	//   - an `accounts` row with email + password_hash and status =
	//     "pending_verification",
	//   - an `organizations` row with the supplied name (and a
	//     repository-chosen slug) plus default plan = "free",
	//   - a `workspaces` row named "default",
	//   - a `members` row joining the new account to the new org with
	//     role = "owner" and workspace_access = [the new workspace].
	//
	// On a unique-violation against the `accounts.email` index the
	// implementation MUST return [ErrDuplicateEmail].
	CreateAccountWithOrg(ctx context.Context, in CreateAccountWithOrgInput) (SignupAccount, error)
}

// CreateAccountWithOrgInput carries the values [SignupRepository]
// implementations need to materialise the new tenant. The handler
// passes already-trimmed and policy-validated inputs; the repository
// is free to canonicalise the email further (lowercasing happens
// implicitly via `citext`) but must not reject otherwise-valid input.
type CreateAccountWithOrgInput struct {
	// Email is the case-insensitive identifier of the account.
	Email string
	// PasswordHash is the Argon2id PHC string produced by [Hash].
	PasswordHash string
	// OrgName is the human-readable Organization label chosen by the
	// signing-up account.
	OrgName string
}

// ErrDuplicateEmail is returned by [SignupRepository.CreateAccountWithOrg]
// when an account with the same email already exists. The handler
// translates it into a stable HTTP 409 response so callers can render
// an actionable error.
var ErrDuplicateEmail = errors.New("auth: email already registered")

// EmailSender abstracts the transactional email channel used by the
// signup flow. The production wiring (task 11.2 / Phase 14) supplies a
// thin Resend wrapper; tests substitute an in-memory recorder.
//
// SendVerificationEmail is fire-and-forget from the handler's point of
// view: a non-nil error is logged but does not roll back the account.
// Implementations are responsible for retries and dead-lettering.
type EmailSender interface {
	SendVerificationEmail(ctx context.Context, msg VerificationEmail) error
}

// VerificationEmail is the message passed to [EmailSender]. Producing
// the actual HTML/text body is the sender's responsibility; the
// handler only supplies the recipient and the verification URL the
// account must follow.
type VerificationEmail struct {
	// To is the recipient email address (verbatim from the signup
	// form, post-trim).
	To string
	// AccountID is the account the verification token resolves to.
	// Surfaced so structured logs and audit emitters downstream of
	// the sender can correlate the message.
	AccountID string
	// Token is the raw 64-character hex verification token. The
	// caller MUST embed it in the verification URL.
	Token string
	// VerifyURL is the fully-formed URL the recipient must follow to
	// activate their account. Constructed as
	//   "{base}/auth/verify?token={token}"
	// where {base} is the handler's configured PublicBaseURL.
	VerifyURL string
}

// ----------------------------------------------------------------------
// Handler
// ----------------------------------------------------------------------

// SignupHandler implements `POST /auth/signup`. The struct exposes its
// dependencies as exported fields so the eventual wiring code in
// `cmd/xalgorix-cloud` can populate them with the production
// implementations, while tests assemble the handler with fakes.
//
// All fields are required except [SignupHandler.Pwner] (HIBP is
// optional per the task description) and [SignupHandler.Logger] (a
// no-op logger is used when zero-valued).
type SignupHandler struct {
	// Redis stores the `verify:{token}` keys with a 24h TTL.
	Redis *redisclient.Client
	// Hasher hashes the supplied password using Argon2id. The field
	// is a function value so tests can inject a deterministic hasher
	// without introducing yet another interface.
	Hasher func(password string) (string, error)
	// Pwner is the optional HIBP probe (task 2.2). When nil the
	// handler skips the pwned-password check.
	Pwner Pwner
	// Email is the transactional email channel.
	Email EmailSender
	// Repo is the persistence layer.
	Repo SignupRepository
	// Logger receives structured warn/info events. The zero value
	// logs to the global zerolog default; pass [zerolog.Nop] in
	// tests that do not care about log output.
	Logger zerolog.Logger
	// PublicBaseURL is the canonical origin used to build the
	// verification URL embedded in the email (e.g.
	// "https://app.xalgorix.com"). It MUST be set; the constructor
	// panics on an empty value to surface misconfiguration at
	// process start.
	PublicBaseURL string
}

// NewSignupHandler returns a [SignupHandler] with the supplied
// dependencies. It panics on any missing required dependency so
// boot-time wiring errors cannot escape into a production runtime.
func NewSignupHandler(
	rdb *redisclient.Client,
	hasher func(string) (string, error),
	pwner Pwner,
	email EmailSender,
	repo SignupRepository,
	publicBaseURL string,
	logger zerolog.Logger,
) *SignupHandler {
	switch {
	case rdb == nil:
		panic("auth: NewSignupHandler requires a non-nil redis client")
	case hasher == nil:
		panic("auth: NewSignupHandler requires a non-nil password hasher")
	case email == nil:
		panic("auth: NewSignupHandler requires a non-nil email sender")
	case repo == nil:
		panic("auth: NewSignupHandler requires a non-nil signup repository")
	case strings.TrimSpace(publicBaseURL) == "":
		panic("auth: NewSignupHandler requires a non-empty PublicBaseURL")
	}
	return &SignupHandler{
		Redis:         rdb,
		Hasher:        hasher,
		Pwner:         pwner,
		Email:         email,
		Repo:          repo,
		Logger:        logger,
		PublicBaseURL: strings.TrimRight(strings.TrimSpace(publicBaseURL), "/"),
	}
}

// Handle is the chi-compatible HTTP handler for `POST /auth/signup`.
// It runs the seven-step flow described at the top of this file and
// translates every failure mode into a stable JSON 4xx/5xx response.
func (h *SignupHandler) Handle(w http.ResponseWriter, r *http.Request) {
	// 0. Method gate. The router is expected to mount us on POST
	//    only, but defending in depth is cheap.
	if r.Method != http.MethodPost {
		writeSignupError(w, http.StatusMethodNotAllowed, "method_not_allowed", "")
		return
	}

	// 1. Decode the JSON body. Use DisallowUnknownFields so a typo
	//    in the field name is loud, not silently dropped on the
	//    floor — the alternative ("password" vs "passwd") would lead
	//    to confusing 422s from the policy validator.
	var req SignupRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4*1024))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeSignupError(w, http.StatusBadRequest, "invalid_json", "")
		return
	}

	email := strings.TrimSpace(req.Email)
	password := req.Password // do NOT trim — leading/trailing spaces are allowed in passwords.
	orgName := strings.TrimSpace(req.OrgName)

	// 2a. Required-field checks. Each missing field maps to a
	//     dedicated rule name so the Dashboard can highlight the
	//     offending input.
	if email == "" {
		writeSignupError(w, http.StatusUnprocessableEntity, "missing_field", "email")
		return
	}
	if password == "" {
		writeSignupError(w, http.StatusUnprocessableEntity, "missing_field", "password")
		return
	}
	if orgName == "" {
		writeSignupError(w, http.StatusUnprocessableEntity, "missing_field", "org_name")
		return
	}

	// 2b. RFC 5322 email parse. The repository will lower-case via
	//     citext, so we keep the user-supplied case in the audit
	//     trail and only validate structure here.
	if _, err := mail.ParseAddress(email); err != nil {
		writeSignupError(w, http.StatusUnprocessableEntity, "invalid_email", "email")
		return
	}

	// 2c. Password policy (task 2.1). Each sentinel maps to a stable
	//     rule name in the response body.
	if err := EnforcePolicy(password); err != nil {
		writeSignupError(w, http.StatusUnprocessableEntity, "weak_password", policyRule(err))
		return
	}

	ctx := r.Context()

	// 3. HIBP check (optional + fail-open; task 2.2). [Pwner.Pwned]
	//    already swallows transient errors and returns (false, nil),
	//    so we can treat a non-nil error as a programmer-error.
	if h.Pwner != nil {
		pwned, err := h.Pwner.Pwned(ctx, password)
		if err != nil {
			h.logger().Warn().
				Err(err).
				Str("event", "auth_pwner_error").
				Msg("hibp probe returned an error; treating as not pwned")
		} else if pwned {
			writeSignupError(w, http.StatusUnprocessableEntity, "weak_password", "password_pwned")
			return
		}
	}

	// 4. Argon2id hash.
	hash, err := h.Hasher(password)
	if err != nil {
		h.logger().Error().Err(err).Str("event", "auth_signup_hash_failed").Msg("password hashing failed")
		writeSignupError(w, http.StatusInternalServerError, "internal_error", "")
		return
	}

	// 5. Persist account + org + workspace + owner member.
	created, err := h.Repo.CreateAccountWithOrg(ctx, CreateAccountWithOrgInput{
		Email:        email,
		PasswordHash: hash,
		OrgName:      orgName,
	})
	if err != nil {
		if errors.Is(err, ErrDuplicateEmail) {
			writeSignupError(w, http.StatusConflict, "email_already_registered", "")
			return
		}
		h.logger().Error().Err(err).Str("event", "auth_signup_persist_failed").Msg("create account/org failed")
		writeSignupError(w, http.StatusInternalServerError, "internal_error", "")
		return
	}

	// 6. Mint + persist the verification token.
	token, err := newVerifyToken()
	if err != nil {
		h.logger().Error().Err(err).Str("event", "auth_signup_token_entropy").Msg("verify token entropy failed")
		writeSignupError(w, http.StatusInternalServerError, "internal_error", "")
		return
	}
	stored, err := h.Redis.SetNX(ctx, verifyKeyPrefix+token, created.AccountID, VerifyTokenTTL)
	if err != nil {
		h.logger().Error().Err(err).Str("event", "auth_signup_token_store").Msg("verify token persistence failed")
		writeSignupError(w, http.StatusInternalServerError, "internal_error", "")
		return
	}
	if !stored {
		// 256 bits of entropy collided with an existing token; this
		// is essentially impossible but we still surface it rather
		// than overwrite the prior tenant's link.
		h.logger().Error().Str("event", "auth_signup_token_collision").Msg("verify token already exists")
		writeSignupError(w, http.StatusInternalServerError, "internal_error", "")
		return
	}

	// 7. Send the verification email. Failure is logged but not
	//    fatal — see file header for the rationale.
	verifyURL := h.PublicBaseURL + "/auth/verify?token=" + token
	if sendErr := h.Email.SendVerificationEmail(ctx, VerificationEmail{
		To:        created.Email,
		AccountID: created.AccountID,
		Token:     token,
		VerifyURL: verifyURL,
	}); sendErr != nil {
		h.logger().Warn().
			Err(sendErr).
			Str("event", "auth_signup_email_failed").
			Str("account_id", created.AccountID).
			Msg("verification email dispatch failed; account created without email")
	}

	writeSignupJSON(w, http.StatusCreated, SignupResponse{
		AccountID: created.AccountID,
		OrgID:     created.OrgID,
	})
}

// ----------------------------------------------------------------------
// Internal helpers
// ----------------------------------------------------------------------

// logger returns the configured zerolog.Logger, falling back to the
// global default when the field was left at the zero value.
func (h *SignupHandler) logger() *zerolog.Logger {
	if h == nil {
		l := zerolog.Nop()
		return &l
	}
	return &h.Logger
}

// policyRule maps a password-policy sentinel onto the rule name the
// API surfaces in the SignupErrorResponse.Rule field. Unknown errors
// fall back to "policy_violation" so the Dashboard always has *some*
// machine-readable hint to render.
func policyRule(err error) string {
	switch {
	case errors.Is(err, ErrPasswordTooShort):
		return "password_too_short"
	case errors.Is(err, ErrPasswordMissingLetter):
		return "password_missing_letter"
	case errors.Is(err, ErrPasswordMissingDigit):
		return "password_missing_digit"
	default:
		return "policy_violation"
	}
}

// newVerifyToken returns a 32-byte random token encoded as 64 lowercase
// hex characters. We use hex (not base32) for token-URL friendliness:
// hex never produces characters that need URL escaping, which keeps
// the verification link verbatim across email clients that re-encode
// suspiciously formatted query strings.
func newVerifyToken() (string, error) {
	var b [verifyTokenBytes]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("auth: read verify token entropy: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}

// writeSignupJSON serialises v as JSON with the given status code.
// Encoding errors are silently swallowed because the caller has
// already committed to a status by the time we get here.
//
// We use a signup-specific helper rather than the package-level
// writeJSON in `login.go` so the two endpoints can evolve their
// response envelopes independently.
func writeSignupJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// writeSignupError writes a [SignupErrorResponse] with the given
// status. A non-empty rule is included in the body so
// policy-violation responses can name the broken rule (Requirement
// 3.3). The signup endpoint deliberately uses a flatter error envelope
// than `login.go` (no nested `error.code/message`) because the API
// contract documented in design.md returns a single `error`/`rule`
// pair for the signup form.
func writeSignupError(w http.ResponseWriter, status int, code, rule string) {
	writeSignupJSON(w, status, SignupErrorResponse{Error: code, Rule: rule})
}
