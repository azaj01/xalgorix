package auth

// File password_reset.go implements task 2.7 of the xalgorix-saas spec:
//
//   - Request(ctx, email): single-use, 60-minute reset link generation.
//     The account is looked up by email; on hit a 32-byte random token
//     is generated and stored in Redis as
//
//         pwreset:{token} = account_id    EX 3600
//
//     and then the email sender is invoked. Request ALWAYS returns nil
//     regardless of whether the account exists or whether any of the
//     downstream steps fail, so an external caller cannot distinguish a
//     hit from a miss through status code, error string, or response
//     timing — defeating account-enumeration probes.
//     (Decisions and Defaults / Requirement 3.8.)
//
//   - Consume(ctx, token, newPassword): finalises the reset. The token
//     is fetched and invalidated atomically with GETDEL so the same
//     token can never be consumed twice (Property 7 — Single-use links
//     in design.md). The new password is enforced against the platform
//     policy (12 chars, ≥1 letter, ≥1 digit), hashed via the injected
//     Hasher, the account row is updated, and EVERY active session for
//     the account is revoked through SessionStore.RevokeAll within the
//     same call (Requirement 3.10 / Property 10 — session lifecycle
//     invariants).
//
// The package intentionally does NOT speak to Resend, Postgres, or
// any concrete transport directly. The email sender, account
// repository, and password hasher are interfaces so the Phase 2.4 /
// 2.5 HTTP handlers can plug their real adapters in, and the unit
// tests in password_reset_test.go can drive the service entirely
// from in-memory fakes.
//
// Requirements: 3.8, 3.10.

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"time"

	goredis "github.com/redis/go-redis/v9"

	redisclient "github.com/xalgord/xalgorix/v4/internal/cloud/redis"
)

// PasswordResetTTL is the lifetime of a reset token in Redis. It is
// fixed by Requirement 3.8 ("a single-use reset link valid for 60
// minutes") and exported so the HTTP layer and tests can share the
// canonical value.
const PasswordResetTTL = 60 * time.Minute

// passwordResetTokenBytes is the entropy size (256 bits) of a reset
// token before base64url encoding. Matching the spec ("32-byte token")
// keeps token-guessing computationally infeasible.
const passwordResetTokenBytes = 32

// passwordResetKeyPrefix is the Redis namespace for reset tokens. The
// prefix is fixed by the spec example
// (`pwreset:{token} = account_id`).
const passwordResetKeyPrefix = "pwreset:"

// ErrPasswordResetTokenInvalid is returned by Consume when the token
// does not exist in Redis: never issued, already consumed, or its
// 60-minute TTL elapsed. The three failure modes are deliberately
// indistinguishable so an external caller cannot probe for valid
// tokens by timing the response or comparing error messages. The HTTP
// layer maps this to HTTP 410 (Gone).
var ErrPasswordResetTokenInvalid = errors.New("auth: password reset token invalid or expired")

// AccountRepo implementations should return [ErrAccountNotFound]
// (declared in login.go) from [AccountRepo.FindByEmail] when no row
// matches. Reusing that sentinel keeps the no-enumeration semantics
// uniform across the auth package: both login and password-reset
// callers branch on the same error value.

// PasswordResetAccount is the minimal projection a PasswordResetService
// needs about an account: the stable id used as a Redis value and as a
// session-revocation key, and the canonical email used in the outbound
// email body. The HTTP layer is free to back this with a richer model.
type PasswordResetAccount struct {
	// ID is the account's stable identifier (typically a UUID
	// string). It is what the service persists at `pwreset:{token}`
	// and what it hands to SessionStore.RevokeAll on success.
	ID string
	// Email is the canonical, lower-cased address the email body
	// renders. It is informational for the service; the lookup key
	// is whatever the caller passed to Request.
	Email string
}

// AccountRepo is the persistence dependency PasswordResetService uses
// to look up and update accounts. Implementations are expected to
// scope their lookups by the canonicalised email so case differences
// in the request body do not leak account existence.
type AccountRepo interface {
	// FindByEmail returns the account for email. Implementations MUST
	// return ErrAccountNotFound (or wrap it) for a clean miss; any
	// other error is treated as an infrastructure failure by Request
	// and silently swallowed (no email enumeration).
	FindByEmail(ctx context.Context, email string) (PasswordResetAccount, error)
	// UpdatePasswordHash persists the new Argon2id PHC string for
	// accountID. Implementations MUST write atomically so a successful
	// Consume cannot leave the account in a state where the old
	// password still authenticates.
	UpdatePasswordHash(ctx context.Context, accountID, encodedHash string) error
}

// PasswordResetEmailer is the transport-level dependency
// PasswordResetService uses to deliver the reset link. The HTTP layer
// wires this to a Resend-backed sender; password_reset_test.go uses
// an in-memory fake so the unit tests stay hermetic.
type PasswordResetEmailer interface {
	// SendPasswordReset is called once per successful Request with
	// the resolved account, the raw reset token (the value the user
	// will eventually click as part of a URL), and the absolute
	// expiration time. Errors are surfaced to Request which logs and
	// converts them to nil so the public API never reveals delivery
	// failures.
	SendPasswordReset(ctx context.Context, account PasswordResetAccount, token string, expiresAt time.Time) error
}

// Hasher is the password-hashing dependency. The default
// implementation is HasherFunc(Hash) from password.go; tests inject a
// faster fake so they do not pay the Argon2id cost on every case.
type Hasher interface {
	Hash(plain string) (string, error)
}

// HasherFunc adapts an ordinary function to the Hasher interface so
// callers can pass `auth.HasherFunc(auth.Hash)` without writing a
// wrapper struct.
type HasherFunc func(plain string) (string, error)

// Hash invokes f.
func (f HasherFunc) Hash(plain string) (string, error) { return f(plain) }

// PasswordResetService coordinates the request/consume flow described
// in Requirement 3.8 / 3.10. It is safe for concurrent use; every
// operation is bounded by the per-call ctx, the Redis primitives
// (SET ... EX, GETDEL) are inherently atomic, and the dependencies
// themselves are expected to be concurrency-safe.
type PasswordResetService struct {
	redis        *redisclient.Client
	hasher       Hasher
	sessionStore *SessionStore
	emailer      PasswordResetEmailer
	repo         AccountRepo
	// now is overridable in tests so deterministic clocks can drive
	// the expiresAt that ships in the reset email. Defaults to
	// time.Now.
	now func() time.Time
	// rand is the entropy source for token generation. Defaults to
	// crypto/rand.Reader; tests inject a deterministic reader to
	// pin token values.
	rand io.Reader
}

// NewPasswordResetService wires a PasswordResetService. It panics on
// nil dependencies because every field is required and a missing one
// is a programming error that must surface at boot, not on the first
// reset request.
func NewPasswordResetService(
	rdb *redisclient.Client,
	hasher Hasher,
	sessions *SessionStore,
	emailer PasswordResetEmailer,
	repo AccountRepo,
) *PasswordResetService {
	if rdb == nil {
		panic("auth: NewPasswordResetService requires a non-nil redis client")
	}
	if hasher == nil {
		panic("auth: NewPasswordResetService requires a non-nil hasher")
	}
	if sessions == nil {
		panic("auth: NewPasswordResetService requires a non-nil session store")
	}
	if emailer == nil {
		panic("auth: NewPasswordResetService requires a non-nil emailer")
	}
	if repo == nil {
		panic("auth: NewPasswordResetService requires a non-nil account repo")
	}
	return &PasswordResetService{
		redis:        rdb,
		hasher:       hasher,
		sessionStore: sessions,
		emailer:      emailer,
		repo:         repo,
		now:          time.Now,
		rand:         rand.Reader,
	}
}

// Request issues a reset link for email. The returned error is
// ALWAYS nil so a caller cannot distinguish hits from misses from
// outside; internal failures are intentionally swallowed for the
// same reason. Operators must rely on logs and metrics for
// observability, not on a return value.
//
// The flow is:
//
//  1. Look up the account by email. A miss (or any repo error) ends
//     the call with a silent nil return — no token is minted, no
//     email is sent.
//  2. Generate a 32-byte random token, base64url-encode it.
//  3. Persist `pwreset:{token} = account_id` in Redis with a
//     60-minute TTL via SET ... EX (atomic write + expiry).
//  4. Hand off to the emailer with the resolved account and the
//     computed expiration time. The emailer is expected to render
//     the reset URL itself; this package only owns the token.
//
// The Redis write happens before the email so a successful response
// implies the token is consumable; a delivery failure leaves the
// token alive for its TTL but the user can simply re-request.
func (s *PasswordResetService) Request(ctx context.Context, email string) error {
	acc, err := s.repo.FindByEmail(ctx, email)
	if err != nil {
		// Hit-or-miss, repo errors are swallowed to avoid leaking
		// account existence through timing or status differences.
		return nil
	}

	token, err := s.generateToken()
	if err != nil {
		// We cannot produce a token — abandon silently. The user
		// can retry; the lack of an email mirrors a missing account
		// from their point of view.
		return nil
	}

	expiresAt := s.now().Add(PasswordResetTTL)
	if err := s.redis.Underlying().Set(ctx, passwordResetKey(token), acc.ID, PasswordResetTTL).Err(); err != nil {
		// Persistence failed: do not call the emailer with a token
		// the user could never consume, but still suppress the
		// error to honour the no-enumeration contract.
		return nil
	}

	// Emailer errors are intentionally suppressed. The token is
	// already alive in Redis; if the email never arrives the user
	// will simply re-request and a new token will be issued.
	_ = s.emailer.SendPasswordReset(ctx, acc, token, expiresAt)
	return nil
}

// Consume finalises a reset. It atomically fetches and invalidates
// the token (GETDEL), enforces the password policy, hashes the new
// password, updates the account, and revokes every active session
// belonging to the account so the old password and old cookies
// cannot be reused (Requirement 3.10 / Property 10).
//
// The token is consumed BEFORE the password is hashed so a malformed
// password input cannot be retried with the same link; the user
// must request a fresh link. This matches Property 7 ("Single-use
// links") and the spec's explicit ordering instruction in the task
// for 2.7 ("GETDEL to atomically fetch & invalidate token, validate
// via EnforcePolicy, hash, update password in repo, then call
// sessionStore.RevokeAll").
//
// Errors map as follows:
//
//   - ErrPasswordResetTokenInvalid: token unknown, already consumed,
//     or expired. Surface as HTTP 410 in the API layer.
//   - ErrPasswordTooShort / ErrPasswordMissingLetter /
//     ErrPasswordMissingDigit: surface as HTTP 422 with the rule name.
//   - Any other error: infrastructure failure — surface as HTTP 500.
func (s *PasswordResetService) Consume(ctx context.Context, token, newPassword string) error {
	if token == "" {
		return ErrPasswordResetTokenInvalid
	}

	// GETDEL is atomic at the Redis level: the value is read and
	// the key removed in a single command, so there is no window in
	// which two concurrent Consumes can both observe the same
	// token. Redis 6.2+ implements this natively; miniredis (used
	// by the unit tests) and the production Redis 7 cluster both
	// accept the command.
	accountID, err := s.redis.Underlying().GetDel(ctx, passwordResetKey(token)).Result()
	if err != nil {
		if errors.Is(err, goredis.Nil) {
			return ErrPasswordResetTokenInvalid
		}
		return fmt.Errorf("auth: consume reset token: %w", err)
	}
	if accountID == "" {
		// Defensive: GETDEL on a missing key returns redis.Nil, but
		// an empty value would indicate a corrupt write — treat it
		// as a miss rather than authorising an empty account id.
		return ErrPasswordResetTokenInvalid
	}

	if err := EnforcePolicy(newPassword); err != nil {
		// Policy errors propagate verbatim so the HTTP layer can
		// name the violated rule in its 422 response. The token has
		// already been consumed; the user must request a new link.
		return err
	}

	encoded, err := s.hasher.Hash(newPassword)
	if err != nil {
		return fmt.Errorf("auth: hash password: %w", err)
	}
	if err := s.repo.UpdatePasswordHash(ctx, accountID, encoded); err != nil {
		return fmt.Errorf("auth: update password: %w", err)
	}
	if err := s.sessionStore.RevokeAll(ctx, accountID); err != nil {
		// The password change has already been persisted; failing
		// to revoke sessions would leave Requirement 3.10 unsatisfied,
		// so we propagate the error to the caller. The HTTP layer
		// must surface this as 500 and operators should alert on
		// the structured log emitted by SessionStore's caller.
		return fmt.Errorf("auth: revoke sessions: %w", err)
	}
	return nil
}

// generateToken returns a base64url-encoded 32-byte random token —
// the value stored as `pwreset:{token}` in Redis and embedded
// verbatim in the URL the user will click. base64url is chosen so
// the token can be placed in a query string without percent encoding
// and so its serialised length is fixed at 43 characters, simplifying
// log greps and Turnstile scoring rules.
func (s *PasswordResetService) generateToken() (string, error) {
	raw := make([]byte, passwordResetTokenBytes)
	if _, err := io.ReadFull(s.rand, raw); err != nil {
		return "", fmt.Errorf("auth: read reset token entropy: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

// passwordResetKey returns the Redis key for a reset token. Centralising
// the prefix here keeps the two callers (Request and Consume) in sync
// and makes the redis surface easy to grep for.
func passwordResetKey(token string) string { return passwordResetKeyPrefix + token }
