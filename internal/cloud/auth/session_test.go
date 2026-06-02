package auth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"

	redisclient "github.com/xalgord/xalgorix/v4/internal/cloud/redis"
)

// signingKey returns a fixed 32-byte signing key. Tests share a
// constant key so HMAC tampering can be reasoned about deterministically.
func signingKey() []byte {
	k := make([]byte, 32)
	for i := range k {
		k[i] = byte(i + 1)
	}
	return k
}

// newTestStore starts a fresh miniredis server and returns a
// SessionStore wired to it. Each test gets its own server so per-test
// keys cannot leak across cases.
func newTestStore(t *testing.T) (*miniredis.Miniredis, *SessionStore) {
	t.Helper()
	mr := miniredis.RunT(t)
	cli, err := redisclient.New(t.Context(), redisclient.Options{Addrs: []string{mr.Addr()}})
	if err != nil {
		t.Fatalf("redis.New: %v", err)
	}
	t.Cleanup(func() {
		if cerr := cli.Close(); cerr != nil {
			t.Logf("redis close: %v", cerr)
		}
	})
	return mr, NewSessionStore(cli, signingKey())
}

// fixedClock returns a deterministic clock anchored at start that
// advances only when t.Cleanup-safe helpers ask it to.
func fixedClock(start time.Time) (now func() time.Time, advance func(time.Duration)) {
	current := start
	return func() time.Time { return current },
		func(d time.Duration) { current = current.Add(d) }
}

// TestNewSessionStorePanicsOnBadInputs documents that the constructor
// rejects misconfigurations at boot time rather than silently
// producing a store that signs everything with a weak key.
func TestNewSessionStorePanicsOnBadInputs(t *testing.T) {
	t.Parallel()
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("nil redis must panic")
		}
	}()
	NewSessionStore(nil, signingKey())
}

func TestNewSessionStorePanicsOnShortKey(t *testing.T) {
	t.Parallel()
	mr := miniredis.RunT(t)
	cli, err := redisclient.New(t.Context(), redisclient.Options{Addrs: []string{mr.Addr()}})
	if err != nil {
		t.Fatalf("redis.New: %v", err)
	}
	t.Cleanup(func() { _ = cli.Close() })

	defer func() {
		if r := recover(); r == nil {
			t.Fatal("short hmacKey must panic")
		}
	}()
	NewSessionStore(cli, []byte("too-short"))
}

// TestIssueAndValidateRoundTrip is the primary happy path: a freshly
// issued token must validate, populate Session correctly, and refresh
// last_seen_at on every read.
func TestIssueAndValidateRoundTrip(t *testing.T) {
	t.Parallel()
	_, store := newTestStore(t)
	now, advance := fixedClock(time.Date(2025, 1, 2, 12, 0, 0, 0, time.UTC))
	store.now = now

	ctx := context.Background()
	const accountID = "acc-1"
	sess, err := store.Issue(ctx, accountID)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if sess.AccountID != accountID {
		t.Fatalf("AccountID mismatch: got %q", sess.AccountID)
	}
	if !strings.Contains(sess.Token, ".") {
		t.Fatalf("token must contain a dot separator, got %q", sess.Token)
	}
	if sess.IssuedAt != now() || sess.LastSeenAt != now() {
		t.Fatalf("timestamps not anchored to the clock")
	}
	if sess.ExpiresAt.Sub(sess.IssuedAt) != SessionTTL {
		t.Fatalf("ExpiresAt should be IssuedAt + SessionTTL, got delta %v", sess.ExpiresAt.Sub(sess.IssuedAt))
	}

	// Advance and validate; last_seen_at must move forward and
	// expires_at must roll forward by SessionTTL.
	advance(time.Hour)
	got, err := store.Validate(ctx, sess.Token)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if !got.LastSeenAt.Equal(now()) {
		t.Fatalf("LastSeenAt not refreshed: got %v want %v", got.LastSeenAt, now())
	}
	if !got.ExpiresAt.Equal(now().Add(SessionTTL)) {
		t.Fatalf("ExpiresAt not refreshed: got %v want %v", got.ExpiresAt, now().Add(SessionTTL))
	}
	if got.AccountID != accountID {
		t.Fatalf("AccountID mismatch after Validate: got %q", got.AccountID)
	}
	if got.ID != sess.ID {
		t.Fatalf("session id changed across Validate")
	}
}

// TestValidateRejectsHMACTampering changes a single tag byte and
// confirms the constant-time comparison catches it. This protects
// against an attacker who can read a sid from logs but cannot forge
// the signing key.
func TestValidateRejectsHMACTampering(t *testing.T) {
	t.Parallel()
	_, store := newTestStore(t)
	ctx := context.Background()
	sess, err := store.Issue(ctx, "acc-tamper")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	// Flip one nibble of the tag without breaking hex validity.
	tampered := flipLastNibble(t, sess.Token)
	if tampered == sess.Token {
		t.Fatal("tamper helper produced an unchanged token")
	}

	if _, err := store.Validate(ctx, tampered); !errors.Is(err, ErrSessionInvalidSignature) {
		t.Fatalf("Validate(tampered) error = %v, want ErrSessionInvalidSignature", err)
	}

	// The original token still works — tampering must be a pure
	// rejection, not a destructive operation.
	if _, err := store.Validate(ctx, sess.Token); err != nil {
		t.Fatalf("Validate(original) after tamper: %v", err)
	}
}

// TestValidateRejectsMalformedTokens covers structural checks before
// any HMAC work happens; a misshapen token must not even reach Redis.
func TestValidateRejectsMalformedTokens(t *testing.T) {
	t.Parallel()
	_, store := newTestStore(t)
	ctx := context.Background()

	cases := []string{
		"",
		"no-dot",
		".onlytag",
		"sidonly.",
		"short.short",
		strings.Repeat("a", rawSessionIDBytes*2) + ".not-hex",
		strings.Repeat("a", rawSessionIDBytes*2-1) + "." + strings.Repeat("a", sha256.Size*2),
		strings.Repeat("a", rawSessionIDBytes*2) + "." + strings.Repeat("a", sha256.Size*2-1),
	}
	for _, tok := range cases {
		if _, err := store.Validate(ctx, tok); !errors.Is(err, ErrSessionMalformedToken) {
			t.Fatalf("Validate(%q) error = %v, want ErrSessionMalformedToken", tok, err)
		}
	}
}

// TestValidateExpiredKey covers the case where the Redis key has
// already TTL'd out. The token's HMAC is still valid but the backing
// record is gone, so Validate must surface ErrSessionNotFound.
func TestValidateExpiredKey(t *testing.T) {
	t.Parallel()
	mr, store := newTestStore(t)
	ctx := context.Background()

	sess, err := store.Issue(ctx, "acc-expiry")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	mr.FastForward(SessionTTL + time.Minute)

	if _, err := store.Validate(ctx, sess.Token); !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("Validate(expired) error = %v, want ErrSessionNotFound", err)
	}
}

// TestValidateIdleTimeout exercises the 12-hour absolute idle rule.
// Even when the Redis TTL is still alive, a gap larger than
// SessionAbsoluteIdle between Validates must reject and tear down.
func TestValidateIdleTimeout(t *testing.T) {
	t.Parallel()
	_, store := newTestStore(t)
	now, advance := fixedClock(time.Date(2025, 3, 4, 9, 0, 0, 0, time.UTC))
	store.now = now

	ctx := context.Background()
	sess, err := store.Issue(ctx, "acc-idle")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	advance(SessionAbsoluteIdle + time.Minute)
	if _, err := store.Validate(ctx, sess.Token); !errors.Is(err, ErrSessionIdle) {
		t.Fatalf("Validate(idle) error = %v, want ErrSessionIdle", err)
	}
	// The record must be gone after an idle rejection so the same
	// cookie cannot be replayed by rewinding the clock.
	if _, err := store.Validate(ctx, sess.Token); !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("second Validate after idle: got %v, want ErrSessionNotFound", err)
	}
}

// TestValidateRefreshKeepsSessionAlive proves the rolling expiration
// works: a session that is exercised every hour should remain valid
// well past the original 30-day window, as long as the per-call gap
// stays below SessionAbsoluteIdle.
func TestValidateRefreshKeepsSessionAlive(t *testing.T) {
	t.Parallel()
	_, store := newTestStore(t)
	now, advance := fixedClock(time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC))
	store.now = now

	ctx := context.Background()
	sess, err := store.Issue(ctx, "acc-rolling")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	for hop := 0; hop < 100; hop++ {
		advance(SessionAbsoluteIdle - time.Minute)
		got, err := store.Validate(ctx, sess.Token)
		if err != nil {
			t.Fatalf("Validate hop %d: %v", hop, err)
		}
		if !got.LastSeenAt.Equal(now()) {
			t.Fatalf("hop %d LastSeenAt mismatch", hop)
		}
	}
}

// TestRevokeRemovesRecord deletes a session and confirms subsequent
// validation is impossible, that the call is idempotent, and that
// tampered tokens cannot be used to revoke arbitrary sids.
func TestRevokeRemovesRecord(t *testing.T) {
	t.Parallel()
	_, store := newTestStore(t)
	ctx := context.Background()

	sess, err := store.Issue(ctx, "acc-revoke")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if err := store.Revoke(ctx, sess.Token); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if _, err := store.Validate(ctx, sess.Token); !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("Validate after Revoke = %v, want ErrSessionNotFound", err)
	}
	// Idempotent: a second Revoke is a no-op.
	if err := store.Revoke(ctx, sess.Token); err != nil {
		t.Fatalf("Revoke(idempotent): %v", err)
	}
	// Tampered token must be rejected even when the session no
	// longer exists.
	tampered := flipLastNibble(t, sess.Token)
	if err := store.Revoke(ctx, tampered); !errors.Is(err, ErrSessionInvalidSignature) {
		t.Fatalf("Revoke(tampered) = %v, want ErrSessionInvalidSignature", err)
	}
}

// TestRevokeAllInvalidatesEveryAccountSession proves the password
// reset / MFA rotation invariant: after RevokeAll, every previously
// issued session for the account must fail Validate, while sessions
// belonging to other accounts are untouched.
func TestRevokeAllInvalidatesEveryAccountSession(t *testing.T) {
	t.Parallel()
	_, store := newTestStore(t)
	ctx := context.Background()

	const target = "acc-bulk"
	const other = "acc-other"

	var targetTokens []string
	for i := 0; i < 3; i++ {
		s, err := store.Issue(ctx, target)
		if err != nil {
			t.Fatalf("Issue target: %v", err)
		}
		targetTokens = append(targetTokens, s.Token)
	}
	otherSess, err := store.Issue(ctx, other)
	if err != nil {
		t.Fatalf("Issue other: %v", err)
	}

	if err := store.RevokeAll(ctx, target); err != nil {
		t.Fatalf("RevokeAll: %v", err)
	}
	for i, tok := range targetTokens {
		if _, err := store.Validate(ctx, tok); !errors.Is(err, ErrSessionNotFound) {
			t.Fatalf("session %d still valid after RevokeAll: %v", i, err)
		}
	}
	if _, err := store.Validate(ctx, otherSess.Token); err != nil {
		t.Fatalf("other-account session affected by RevokeAll: %v", err)
	}
	// RevokeAll on an account with no sessions is fine.
	if err := store.RevokeAll(ctx, "acc-empty"); err != nil {
		t.Fatalf("RevokeAll(empty): %v", err)
	}
}

// TestWriteCookieSetsRequiredAttributes asserts the cookie carries the
// exact attributes Requirement 20.6 mandates: __Host- prefix, Secure,
// HttpOnly, SameSite=Lax, Path=/, no Domain.
func TestWriteCookieSetsRequiredAttributes(t *testing.T) {
	t.Parallel()
	_, store := newTestStore(t)
	rec := httptest.NewRecorder()

	const token = "deadbeef.cafef00d"
	store.WriteCookie(rec, token)

	resp := rec.Result()
	defer resp.Body.Close()

	cookies := resp.Cookies()
	if len(cookies) != 1 {
		t.Fatalf("expected exactly one cookie, got %d", len(cookies))
	}
	c := cookies[0]
	if c.Name != SessionCookieName {
		t.Fatalf("cookie name = %q, want %q", c.Name, SessionCookieName)
	}
	if !strings.HasPrefix(c.Name, "__Host-") {
		t.Fatalf("cookie missing __Host- prefix: %q", c.Name)
	}
	if c.Value != token {
		t.Fatalf("cookie value = %q, want %q", c.Value, token)
	}
	if !c.Secure {
		t.Fatal("cookie must be Secure")
	}
	if !c.HttpOnly {
		t.Fatal("cookie must be HttpOnly")
	}
	if c.SameSite != http.SameSiteLaxMode {
		t.Fatalf("cookie SameSite = %v, want Lax", c.SameSite)
	}
	if c.Path != "/" {
		t.Fatalf("cookie path = %q, want %q", c.Path, "/")
	}
	if c.Domain != "" {
		t.Fatalf("__Host- cookies must not set a Domain, got %q", c.Domain)
	}
	if c.MaxAge != int(SessionTTL.Seconds()) {
		t.Fatalf("cookie MaxAge = %d, want %d", c.MaxAge, int(SessionTTL.Seconds()))
	}
}

// TestClearCookieDeletes asserts the sign-out helper writes a cookie
// the browser will treat as immediately expired.
func TestClearCookieDeletes(t *testing.T) {
	t.Parallel()
	_, store := newTestStore(t)
	rec := httptest.NewRecorder()
	store.ClearCookie(rec)

	resp := rec.Result()
	defer resp.Body.Close()
	cookies := resp.Cookies()
	if len(cookies) != 1 {
		t.Fatalf("expected one cookie, got %d", len(cookies))
	}
	c := cookies[0]
	if c.Name != SessionCookieName {
		t.Fatalf("cookie name = %q", c.Name)
	}
	if c.Value != "" {
		t.Fatalf("cookie value = %q, want empty", c.Value)
	}
	if c.MaxAge >= 0 {
		t.Fatalf("cookie MaxAge = %d, want negative", c.MaxAge)
	}
}

// TestIssueRequiresAccount documents that an empty account id is a
// programming error: callers must always supply the owning account.
func TestIssueRequiresAccount(t *testing.T) {
	t.Parallel()
	_, store := newTestStore(t)
	if _, err := store.Issue(context.Background(), ""); err == nil {
		t.Fatal("Issue with empty account id must return an error")
	}
}

// flipLastNibble flips the last hex character of a "<sid>.<tag>"
// token in a way that keeps the structural shape intact. It is used
// to simulate signature tampering.
func flipLastNibble(t *testing.T, token string) string {
	t.Helper()
	if token == "" {
		t.Fatal("flipLastNibble: empty token")
	}
	last := token[len(token)-1]
	// Build a target hex digit different from `last`.
	candidates := []byte("0123456789abcdef")
	var swap byte
	for _, c := range candidates {
		if c != last {
			swap = c
			break
		}
	}
	flipped := token[:len(token)-1] + string(swap)
	// Sanity: the flipped tag must still decode as hex so we are
	// exercising the HMAC check, not the structural validator.
	if _, err := hex.DecodeString(flipped[strings.IndexByte(flipped, '.')+1:]); err != nil {
		t.Fatalf("flipLastNibble produced invalid hex: %v", err)
	}
	return flipped
}
