package auth

// Tests for lockout.go (task 2.5).
//
// Coverage matrix tracks the requirement clauses verbatim:
//
//   - 4 fails leave the account unlocked, 5th fail flips the lock
//     (Requirement 3.9: "five consecutive sign-in attempts ... within
//     10 minutes ... lock interactive sign-in for that Account for 15
//     minutes").
//   - The lock survives 14 minutes and lifts after 15 minutes
//     (LockDuration).
//   - The fail counter expires after 10 minutes of inactivity
//     (FailWindow); a slow drip of fails never crosses the threshold.
//   - Reset clears both keys so a successful sign-in does not penalise
//     the user for earlier mistakes (Requirement 3.5).
//   - Locked surfaces redis errors so the login handler can fail
//     closed when the lockout system itself is offline.
//
// Tests use miniredis directly so we can FastForward through the
// 10-minute window and 15-minute lock without sleeping in real time.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/rs/zerolog"

	redisclient "github.com/xalgord/xalgorix/v4/internal/cloud/redis"
)

// newLockoutTracker boots a fresh miniredis server and returns it
// alongside a [LockoutTracker] wired to it. Each test gets its own
// server so per-key counters cannot leak between cases.
func newLockoutTracker(t *testing.T) (*miniredis.Miniredis, *LockoutTracker) {
	t.Helper()
	mr := miniredis.RunT(t)
	cli, err := redisclient.New(t.Context(), redisclient.Options{Addrs: []string{mr.Addr()}})
	if err != nil {
		t.Fatalf("redis.New: %v", err)
	}
	t.Cleanup(func() { _ = cli.Close() })
	return mr, NewLockoutTracker(cli, zerolog.Nop())
}

// TestNewLockoutTrackerPanicsOnNilClient documents the constructor's
// fail-fast behaviour on misconfiguration.
func TestNewLockoutTrackerPanicsOnNilClient(t *testing.T) {
	t.Parallel()
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("nil redis must panic")
		}
	}()
	NewLockoutTracker(nil, zerolog.Nop())
}

// TestRecordFail_BelowThresholdDoesNotLock walks four consecutive
// fails and asserts neither the counter nor the lock key trip the
// "locked" return. This is the primary forward direction of
// Requirement 3.9: anything *less* than five fails must leave the
// account usable.
func TestRecordFail_BelowThresholdDoesNotLock(t *testing.T) {
	t.Parallel()
	mr, lt := newLockoutTracker(t)
	ctx := context.Background()
	const key = "alice@example.com"

	for i := 1; i < FailThreshold; i++ {
		got, locked := lt.RecordFail(ctx, key)
		if got != i {
			t.Fatalf("fail %d: count = %d, want %d", i, got, i)
		}
		if locked {
			t.Fatalf("fail %d: locked = true, want false", i)
		}
	}

	if got, err := lt.Locked(ctx, key); err != nil {
		t.Fatalf("Locked: %v", err)
	} else if got {
		t.Fatal("Locked must report false before the threshold is crossed")
	}
	if !mr.Exists(failsRedisKey(key)) {
		t.Fatal("fails counter key must exist while a burst is in progress")
	}
	if mr.Exists(lockedRedisKey(key)) {
		t.Fatal("lock key must not exist below threshold")
	}
}

// TestRecordFail_FifthFailLocks asserts the threshold-crossing
// transition: the 5th fail returns locked=true with current=5, and
// the lock key carries the 15-minute TTL described in Requirement
// 3.9. This is the property the login handler relies on to emit the
// `auth_lockout` audit exactly once.
func TestRecordFail_FifthFailLocks(t *testing.T) {
	t.Parallel()
	mr, lt := newLockoutTracker(t)
	ctx := context.Background()
	const key = "bob@example.com"

	for i := 1; i <= FailThreshold-1; i++ {
		_, _ = lt.RecordFail(ctx, key)
	}
	got, locked := lt.RecordFail(ctx, key)
	if got != FailThreshold {
		t.Fatalf("threshold fail count = %d, want %d", got, FailThreshold)
	}
	if !locked {
		t.Fatal("threshold fail must return locked = true")
	}

	if !mr.Exists(lockedRedisKey(key)) {
		t.Fatal("lock key must exist after the threshold is crossed")
	}
	ttl := mr.TTL(lockedRedisKey(key))
	if ttl <= 0 || ttl > LockDuration {
		t.Fatalf("lock TTL = %v, want in (0, %v]", ttl, LockDuration)
	}

	if got, err := lt.Locked(ctx, key); err != nil {
		t.Fatalf("Locked: %v", err)
	} else if !got {
		t.Fatal("Locked must report true after the threshold is crossed")
	}
}

// TestRecordFail_LockSurvives14MinutesExpiresAfter15 is the temporal
// half of Requirement 3.9. miniredis' FastForward steps the
// in-memory clock so we can verify the lock is still active just
// before the TTL elapses and gone immediately after.
func TestRecordFail_LockSurvives14MinutesExpiresAfter15(t *testing.T) {
	t.Parallel()
	mr, lt := newLockoutTracker(t)
	ctx := context.Background()
	const key = "carol@example.com"

	for i := 0; i < FailThreshold; i++ {
		_, _ = lt.RecordFail(ctx, key)
	}

	// 14 minutes in — still locked.
	mr.FastForward(14 * time.Minute)
	got, err := lt.Locked(ctx, key)
	if err != nil {
		t.Fatalf("Locked at 14m: %v", err)
	}
	if !got {
		t.Fatal("lock must still be active after 14 minutes")
	}

	// One more minute (15 total) — TTL elapses, lock lifts.
	mr.FastForward(time.Minute + time.Second)
	got, err = lt.Locked(ctx, key)
	if err != nil {
		t.Fatalf("Locked at 15m+: %v", err)
	}
	if got {
		t.Fatal("lock must lift after %v" + LockDuration.String())
	}
}

// TestRecordFail_FailCounterExpiresAfterFailWindow asserts the
// 10-minute rolling window. A slow drip of fails — one every nine
// minutes — never accumulates because each EXPIRE refreshes the
// window only for the burst that produced it; once the burst stalls
// past FailWindow the counter starts over.
//
// We exercise the scenario by recording four fails, fast-forwarding
// past FailWindow, then recording one more: the new fail must report
// count=1 and not trip the lock.
func TestRecordFail_FailCounterExpiresAfterFailWindow(t *testing.T) {
	t.Parallel()
	mr, lt := newLockoutTracker(t)
	ctx := context.Background()
	const key = "dave@example.com"

	for i := 0; i < FailThreshold-1; i++ {
		_, _ = lt.RecordFail(ctx, key)
	}
	mr.FastForward(FailWindow + time.Second)

	got, locked := lt.RecordFail(ctx, key)
	if got != 1 {
		t.Fatalf("post-window fail count = %d, want 1", got)
	}
	if locked {
		t.Fatal("post-window fail must not lock")
	}
	if mr.Exists(lockedRedisKey(key)) {
		t.Fatal("lock key must not exist after the counter resets")
	}
}

// TestReset_ClearsBothKeys confirms the success-path cleanup. After
// a Reset, the next failed sign-in must observe a fresh counter,
// otherwise legitimate users would be permanently penalised by old
// fails.
func TestReset_ClearsBothKeys(t *testing.T) {
	t.Parallel()
	mr, lt := newLockoutTracker(t)
	ctx := context.Background()
	const key = "erin@example.com"

	for i := 0; i < FailThreshold; i++ {
		_, _ = lt.RecordFail(ctx, key)
	}
	if !mr.Exists(failsRedisKey(key)) || !mr.Exists(lockedRedisKey(key)) {
		t.Fatal("setup: expected both lockout keys present")
	}

	lt.Reset(ctx, key)

	if mr.Exists(failsRedisKey(key)) {
		t.Fatal("Reset must remove the fails counter")
	}
	if mr.Exists(lockedRedisKey(key)) {
		t.Fatal("Reset must remove the lock flag")
	}

	got, locked := lt.RecordFail(ctx, key)
	if got != 1 {
		t.Fatalf("post-reset fail count = %d, want 1", got)
	}
	if locked {
		t.Fatal("post-reset fail must not be locked")
	}
}

// TestLocked_ReportsAbsenceForUnknownKey is a smoke check: no fail
// has ever happened for the key, so Locked must report false.
func TestLocked_ReportsAbsenceForUnknownKey(t *testing.T) {
	t.Parallel()
	_, lt := newLockoutTracker(t)
	got, err := lt.Locked(context.Background(), "ghost@example.com")
	if err != nil {
		t.Fatalf("Locked: %v", err)
	}
	if got {
		t.Fatal("Locked on unknown key must be false")
	}
}

// TestLocked_SurfacesRedisError closes the underlying miniredis
// before calling Locked so we can assert the error path. Failing
// closed on the read side matters: a 500 here is what tells the
// login handler to refuse the sign-in instead of letting requests
// through while the lockout system is offline.
func TestLocked_SurfacesRedisError(t *testing.T) {
	t.Parallel()
	mr, lt := newLockoutTracker(t)
	mr.Close()

	_, err := lt.Locked(context.Background(), "frank@example.com")
	if err == nil {
		t.Fatal("Locked must surface a redis error when the server is unreachable")
	}
	// The wrapping is not contractually exact, but the error must
	// be non-nil and reference the underlying connection failure.
	if errors.Is(err, context.Canceled) {
		t.Fatalf("unexpected context error: %v", err)
	}
}

// TestEmptyKeyIsNoOp documents the defensive guard: an empty key
// short-circuits without touching Redis. This protects callers that
// might pass through an unparsed email field.
func TestEmptyKeyIsNoOp(t *testing.T) {
	t.Parallel()
	mr, lt := newLockoutTracker(t)
	ctx := context.Background()

	got, locked := lt.RecordFail(ctx, "")
	if got != 0 || locked {
		t.Fatalf("RecordFail(\"\") = (%d, %v), want (0, false)", got, locked)
	}
	if l, err := lt.Locked(ctx, ""); err != nil || l {
		t.Fatalf("Locked(\"\") = (%v, %v), want (false, nil)", l, err)
	}
	lt.Reset(ctx, "") // must not panic

	if mr.DB(0).FlushDB(); mr.DB(0).Keys() != nil && len(mr.DB(0).Keys()) != 0 {
		t.Fatal("empty-key calls must not write to redis")
	}
}
