package auth

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"

	redisclient "github.com/xalgord/xalgorix/v4/internal/cloud/redis"
)

// fakeResetRepo is an in-memory AccountRepo. It records the password
// hashes that Consume writes so each test can assert post-conditions
// without booting a real Postgres. The name is suffixed to keep it
// distinct from the MFA test rig's repo (mfa_test.go).
type fakeResetRepo struct {
	mu       sync.Mutex
	byEmail  map[string]PasswordResetAccount
	hashes   map[string]string
	updates  int
	updateFn func(accountID, encoded string) error
}

func newFakeResetRepo() *fakeResetRepo {
	return &fakeResetRepo{
		byEmail: make(map[string]PasswordResetAccount),
		hashes:  make(map[string]string),
	}
}

func (f *fakeResetRepo) addAccount(acc PasswordResetAccount, currentHash string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.byEmail[strings.ToLower(acc.Email)] = acc
	f.hashes[acc.ID] = currentHash
}

func (f *fakeResetRepo) FindByEmail(_ context.Context, email string) (PasswordResetAccount, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	acc, ok := f.byEmail[strings.ToLower(email)]
	if !ok {
		return PasswordResetAccount{}, ErrAccountNotFound
	}
	return acc, nil
}

func (f *fakeResetRepo) UpdatePasswordHash(_ context.Context, accountID, encoded string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.updateFn != nil {
		if err := f.updateFn(accountID, encoded); err != nil {
			return err
		}
	}
	f.updates++
	f.hashes[accountID] = encoded
	return nil
}

func (f *fakeResetRepo) hashFor(accountID string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.hashes[accountID]
}

// recordedEmail captures one outbound reset email so tests can assert
// the sender saw the correct token / expiry / recipient.
type recordedEmail struct {
	Account   PasswordResetAccount
	Token     string
	ExpiresAt time.Time
}

// fakeEmailer collects the calls to SendPasswordReset for inspection.
type fakeEmailer struct {
	mu   sync.Mutex
	sent []recordedEmail
	err  error
}

func (e *fakeEmailer) SendPasswordReset(_ context.Context, acc PasswordResetAccount, token string, expiresAt time.Time) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.sent = append(e.sent, recordedEmail{Account: acc, Token: token, ExpiresAt: expiresAt})
	return e.err
}

func (e *fakeEmailer) calls() []recordedEmail {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]recordedEmail, len(e.sent))
	copy(out, e.sent)
	return out
}

// fastHasher avoids paying Argon2id cost in every test case while
// still producing deterministic, byte-distinct outputs that assertions
// can compare against the existing hash.
type fastHasher struct{ prefix string }

func (h fastHasher) Hash(plain string) (string, error) {
	return h.prefix + ":" + plain, nil
}

// newResetTestRig boots miniredis, a real SessionStore against it,
// the in-memory fakes, and a PasswordResetService wired to all of
// them. It returns the rig so individual tests can drive specific
// flows. Each rig gets its own miniredis so keys and pub/sub state
// cannot leak between cases.
type resetTestRig struct {
	mr       *miniredis.Miniredis
	redis    *redisclient.Client
	repo     *fakeResetRepo
	emailer  *fakeEmailer
	sessions *SessionStore
	svc      *PasswordResetService
}

func newResetTestRig(t *testing.T) *resetTestRig {
	t.Helper()
	mr := miniredis.RunT(t)
	cli, err := redisclient.New(t.Context(), redisclient.Options{Addrs: []string{mr.Addr()}})
	if err != nil {
		t.Fatalf("redis.New: %v", err)
	}
	t.Cleanup(func() { _ = cli.Close() })

	sessions := NewSessionStore(cli, signingKey())
	repo := newFakeResetRepo()
	emailer := &fakeEmailer{}
	svc := NewPasswordResetService(cli, fastHasher{prefix: "argon2idfake"}, sessions, emailer, repo)

	return &resetTestRig{
		mr:       mr,
		redis:    cli,
		repo:     repo,
		emailer:  emailer,
		sessions: sessions,
		svc:      svc,
	}
}

// TestRequestStoresTokenAndSendsEmail walks the happy path of
// /auth/password-reset: an existing account triggers a Redis write
// at `pwreset:{token}` with a 60-minute TTL, and the emailer is
// called exactly once with the resolved account and a non-empty
// token whose value matches the Redis key suffix.
func TestRequestStoresTokenAndSendsEmail(t *testing.T) {
	t.Parallel()
	rig := newResetTestRig(t)
	const accountID = "acc-1"
	rig.repo.addAccount(PasswordResetAccount{ID: accountID, Email: "user@example.com"}, "old-hash")

	if err := rig.svc.Request(context.Background(), "user@example.com"); err != nil {
		t.Fatalf("Request: %v", err)
	}

	calls := rig.emailer.calls()
	if len(calls) != 1 {
		t.Fatalf("emailer calls = %d, want 1", len(calls))
	}
	got := calls[0]
	if got.Account.ID != accountID {
		t.Fatalf("emailer account = %q, want %q", got.Account.ID, accountID)
	}
	if got.Token == "" {
		t.Fatal("emailer token must be non-empty")
	}

	// The token must be addressable in Redis and resolve to the
	// account id for the configured TTL.
	storedID, err := rig.redis.Underlying().Get(context.Background(), passwordResetKey(got.Token)).Result()
	if err != nil {
		t.Fatalf("Get pwreset:{token}: %v", err)
	}
	if storedID != accountID {
		t.Fatalf("redis value = %q, want %q", storedID, accountID)
	}
	ttl, err := rig.redis.Underlying().TTL(context.Background(), passwordResetKey(got.Token)).Result()
	if err != nil {
		t.Fatalf("TTL: %v", err)
	}
	// Allow some slack for clock drift between SET EX and TTL but
	// require the upper bound to match the spec exactly.
	if ttl <= 0 || ttl > PasswordResetTTL {
		t.Fatalf("ttl = %v, want in (0, %v]", ttl, PasswordResetTTL)
	}
}

// TestRequestUnknownEmailDoesNotEnumerate confirms the no-enumeration
// guarantee: a miss returns nil with no email and no Redis write,
// just like a hit on the public surface but without the side effects.
func TestRequestUnknownEmailDoesNotEnumerate(t *testing.T) {
	t.Parallel()
	rig := newResetTestRig(t)

	if err := rig.svc.Request(context.Background(), "nobody@example.com"); err != nil {
		t.Fatalf("Request(unknown) = %v, want nil", err)
	}
	if got := rig.emailer.calls(); len(got) != 0 {
		t.Fatalf("emailer called %d times for unknown email; want 0", len(got))
	}
	keys := rig.mr.Keys()
	for _, k := range keys {
		if strings.HasPrefix(k, passwordResetKeyPrefix) {
			t.Fatalf("unexpected reset key after unknown email: %q", k)
		}
	}
}

// TestConsumeHappyPath drives the full success flow:
// Request → Consume → password updated → token gone → sessions revoked.
// Active sessions for OTHER accounts must remain intact.
func TestConsumeHappyPath(t *testing.T) {
	t.Parallel()
	rig := newResetTestRig(t)
	ctx := context.Background()

	const accountID = "acc-happy"
	const otherID = "acc-other"
	rig.repo.addAccount(PasswordResetAccount{ID: accountID, Email: "user@example.com"}, "old")

	// Pre-issue two sessions for the target account and one for an
	// unrelated account so we can assert RevokeAll's blast radius.
	s1, err := rig.sessions.Issue(ctx, accountID)
	if err != nil {
		t.Fatalf("Issue s1: %v", err)
	}
	s2, err := rig.sessions.Issue(ctx, accountID)
	if err != nil {
		t.Fatalf("Issue s2: %v", err)
	}
	otherSess, err := rig.sessions.Issue(ctx, otherID)
	if err != nil {
		t.Fatalf("Issue other: %v", err)
	}

	if err := rig.svc.Request(ctx, "user@example.com"); err != nil {
		t.Fatalf("Request: %v", err)
	}
	calls := rig.emailer.calls()
	if len(calls) != 1 {
		t.Fatalf("emailer calls = %d, want 1", len(calls))
	}
	token := calls[0].Token

	const newPwd = "Brand-NewPa55word"
	if err := rig.svc.Consume(ctx, token, newPwd); err != nil {
		t.Fatalf("Consume: %v", err)
	}

	// Password must have been updated through the repo with the
	// hashed (not raw) value.
	got := rig.repo.hashFor(accountID)
	if got == "" {
		t.Fatal("password hash not updated")
	}
	if got == "old" {
		t.Fatal("password hash was not replaced")
	}
	if !strings.Contains(got, newPwd) {
		// The fake hasher echoes the plain text as a sentinel; this
		// guards against accidental double-hashing or no-op writes.
		t.Fatalf("hash %q does not include the new password marker", got)
	}

	// Token must be gone — same Consume call cannot succeed twice.
	if exists, _ := rig.redis.Underlying().Exists(ctx, passwordResetKey(token)).Result(); exists != 0 {
		t.Fatalf("pwreset key still present after Consume; exists=%d", exists)
	}

	// Both sessions for the target account must be invalid; the
	// unrelated account's session must still validate.
	if _, err := rig.sessions.Validate(ctx, s1.Token); !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("Validate(s1) = %v, want ErrSessionNotFound", err)
	}
	if _, err := rig.sessions.Validate(ctx, s2.Token); !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("Validate(s2) = %v, want ErrSessionNotFound", err)
	}
	if _, err := rig.sessions.Validate(ctx, otherSess.Token); err != nil {
		t.Fatalf("Validate(other) = %v, want nil", err)
	}
}

// TestConsumeIsSingleUse confirms Property 7: a token consumed
// successfully cannot be replayed; the second attempt must report
// ErrPasswordResetTokenInvalid even when the new password is also
// valid.
func TestConsumeIsSingleUse(t *testing.T) {
	t.Parallel()
	rig := newResetTestRig(t)
	ctx := context.Background()

	rig.repo.addAccount(PasswordResetAccount{ID: "acc-single", Email: "single@example.com"}, "old")
	if err := rig.svc.Request(ctx, "single@example.com"); err != nil {
		t.Fatalf("Request: %v", err)
	}
	token := rig.emailer.calls()[0].Token

	if err := rig.svc.Consume(ctx, token, "Strong-Pa55word!"); err != nil {
		t.Fatalf("first Consume: %v", err)
	}
	err := rig.svc.Consume(ctx, token, "Another-Pa55word!")
	if !errors.Is(err, ErrPasswordResetTokenInvalid) {
		t.Fatalf("second Consume = %v, want ErrPasswordResetTokenInvalid", err)
	}
}

// TestConsumeExpiredTokenRejects asserts the 60-minute lifetime: a
// token whose key has TTL'd out cannot be redeemed even though its
// raw bytes are unchanged.
func TestConsumeExpiredTokenRejects(t *testing.T) {
	t.Parallel()
	rig := newResetTestRig(t)
	ctx := context.Background()

	rig.repo.addAccount(PasswordResetAccount{ID: "acc-expired", Email: "expired@example.com"}, "old")
	if err := rig.svc.Request(ctx, "expired@example.com"); err != nil {
		t.Fatalf("Request: %v", err)
	}
	token := rig.emailer.calls()[0].Token

	rig.mr.FastForward(PasswordResetTTL + time.Minute)

	err := rig.svc.Consume(ctx, token, "Strong-Pa55word!")
	if !errors.Is(err, ErrPasswordResetTokenInvalid) {
		t.Fatalf("Consume(expired) = %v, want ErrPasswordResetTokenInvalid", err)
	}
}

// TestConsumeWeakPasswordRejected confirms the policy gate fires
// inside Consume: a sub-policy password yields the matching policy
// error and the password row is left untouched. The token, however,
// is already gone — by design, so the user must request a fresh link
// rather than retry against the same one (Property 7 invariant).
func TestConsumeWeakPasswordRejected(t *testing.T) {
	t.Parallel()
	rig := newResetTestRig(t)
	ctx := context.Background()

	const accountID = "acc-weak"
	rig.repo.addAccount(PasswordResetAccount{ID: accountID, Email: "weak@example.com"}, "old")
	if err := rig.svc.Request(ctx, "weak@example.com"); err != nil {
		t.Fatalf("Request: %v", err)
	}
	token := rig.emailer.calls()[0].Token

	cases := []struct {
		name     string
		password string
		want     error
	}{
		{"too short", "Ab1cdef", ErrPasswordTooShort},
		{"missing letter", "1234567890123", ErrPasswordMissingLetter},
		{"missing digit", "abcdefghijklm", ErrPasswordMissingDigit},
	}
	// We can only exercise one rejection per token because the token
	// is consumed atomically; iterate over cases by issuing fresh
	// tokens for each rejection scenario.
	for i, tc := range cases {
		// Re-issue a token for each case.
		if i > 0 {
			if err := rig.svc.Request(ctx, "weak@example.com"); err != nil {
				t.Fatalf("Request(%s): %v", tc.name, err)
			}
			token = rig.emailer.calls()[len(rig.emailer.calls())-1].Token
		}
		err := rig.svc.Consume(ctx, token, tc.password)
		if !errors.Is(err, tc.want) {
			t.Fatalf("[%s] Consume = %v, want %v", tc.name, err, tc.want)
		}

		// Repo must not have been updated for any rejected attempt.
		if got := rig.repo.hashFor(accountID); got != "old" {
			t.Fatalf("[%s] repo hash mutated to %q after weak password", tc.name, got)
		}
	}
}

// TestConsumeUnknownTokenRejects covers tokens that were never issued
// — for example, a stale URL from a previous environment or an
// attacker fishing for valid prefixes.
func TestConsumeUnknownTokenRejects(t *testing.T) {
	t.Parallel()
	rig := newResetTestRig(t)
	ctx := context.Background()

	cases := []string{"", "deadbeef", "not-a-real-token-value-1234567890"}
	for _, tok := range cases {
		err := rig.svc.Consume(ctx, tok, "Strong-Pa55word!")
		if !errors.Is(err, ErrPasswordResetTokenInvalid) {
			t.Fatalf("Consume(%q) = %v, want ErrPasswordResetTokenInvalid", tok, err)
		}
	}
}

// TestConsumeInvalidatesAllSessions is the explicit Requirement 3.10
// regression: even when only the password change happens (no MFA
// changes), every active session for the account must be revoked.
// We assert this against ten fanned-out sessions to avoid relying on
// the TestConsumeHappyPath two-session count being load-bearing.
func TestConsumeInvalidatesAllSessions(t *testing.T) {
	t.Parallel()
	rig := newResetTestRig(t)
	ctx := context.Background()

	const accountID = "acc-many"
	rig.repo.addAccount(PasswordResetAccount{ID: accountID, Email: "many@example.com"}, "old")

	tokens := make([]string, 0, 10)
	for i := 0; i < 10; i++ {
		s, err := rig.sessions.Issue(ctx, accountID)
		if err != nil {
			t.Fatalf("Issue %d: %v", i, err)
		}
		tokens = append(tokens, s.Token)
	}

	if err := rig.svc.Request(ctx, "many@example.com"); err != nil {
		t.Fatalf("Request: %v", err)
	}
	resetToken := rig.emailer.calls()[0].Token
	if err := rig.svc.Consume(ctx, resetToken, "Brand-NewPa55word!"); err != nil {
		t.Fatalf("Consume: %v", err)
	}

	for i, tok := range tokens {
		if _, err := rig.sessions.Validate(ctx, tok); !errors.Is(err, ErrSessionNotFound) {
			t.Fatalf("session %d still valid after reset: %v", i, err)
		}
	}
}

// TestNewPasswordResetServicePanicsOnNilDeps documents the boot-time
// contract: every dependency is required, and a missing one is a
// programming error that must surface immediately rather than at the
// first reset request.
func TestNewPasswordResetServicePanicsOnNilDeps(t *testing.T) {
	t.Parallel()
	rig := newResetTestRig(t)
	hasher := fastHasher{prefix: "x"}

	cases := []struct {
		name string
		fn   func()
	}{
		{"nil redis", func() {
			NewPasswordResetService(nil, hasher, rig.sessions, rig.emailer, rig.repo)
		}},
		{"nil hasher", func() {
			NewPasswordResetService(rig.redis, nil, rig.sessions, rig.emailer, rig.repo)
		}},
		{"nil sessions", func() {
			NewPasswordResetService(rig.redis, hasher, nil, rig.emailer, rig.repo)
		}},
		{"nil emailer", func() {
			NewPasswordResetService(rig.redis, hasher, rig.sessions, nil, rig.repo)
		}},
		{"nil repo", func() {
			NewPasswordResetService(rig.redis, hasher, rig.sessions, rig.emailer, nil)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r == nil {
					t.Fatalf("NewPasswordResetService(%s) must panic", tc.name)
				}
			}()
			tc.fn()
		})
	}
}
