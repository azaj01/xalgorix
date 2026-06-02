// Copyright (c) Xalgorix.
// SPDX-License-Identifier: AGPL-3.0-only

package targets

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"

	cloudredis "github.com/xalgord/xalgorix/v4/internal/cloud/redis"
)

// startCooldown boots an in-memory Redis server, wires the
// Cloud_Platform Redis facade against it, and returns the server (so
// individual tests can advance virtual time with FastForward) together
// with a [CooldownTracker]. Each test gets its own server so failure
// counters and lock sentinels cannot leak between cases.
func startCooldown(t *testing.T) (*miniredis.Miniredis, *CooldownTracker) {
	t.Helper()
	mr := miniredis.RunT(t)
	cli, err := cloudredis.New(t.Context(), cloudredis.Options{Addrs: []string{mr.Addr()}})
	if err != nil {
		t.Fatalf("cloudredis.New(miniredis): %v", err)
	}
	t.Cleanup(func() {
		if cerr := cli.Close(); cerr != nil {
			t.Logf("client close: %v", cerr)
		}
	})
	return mr, NewCooldownTracker(cli)
}

// TestRecordFailTwoFailsDoNotLock asserts that the first two failures
// inside a fresh window do NOT trip the lockout. This is the "no false
// positive" half of Requirement 7.5: a single intermittent DNS hiccup
// followed by a recovery must not lock the customer out for an hour.
func TestRecordFailTwoFailsDoNotLock(t *testing.T) {
	t.Parallel()
	_, tr := startCooldown(t)
	ctx := t.Context()
	const targetID = "tgt-001"

	for i := 1; i <= 2; i++ {
		locked, err := tr.RecordFail(ctx, targetID)
		if err != nil {
			t.Fatalf("RecordFail #%d: %v", i, err)
		}
		if locked {
			t.Fatalf("RecordFail #%d returned locked=true; only the 3rd failure must lock", i)
		}
	}

	// Belt-and-braces: the lock sentinel must not exist after fewer than
	// three failures, and Locked must report false.
	locked, err := tr.Locked(ctx, targetID)
	if err != nil {
		t.Fatalf("Locked: %v", err)
	}
	if locked {
		t.Fatal("Locked returned true after 2 failures; expected false")
	}
}

// TestRecordFailThirdFailLocks asserts that the third failure flips the
// lockout. This is the positive half of Requirement 7.5.
func TestRecordFailThirdFailLocks(t *testing.T) {
	t.Parallel()
	_, tr := startCooldown(t)
	ctx := t.Context()
	const targetID = "tgt-002"

	for i := 1; i <= 2; i++ {
		if _, err := tr.RecordFail(ctx, targetID); err != nil {
			t.Fatalf("RecordFail #%d: %v", i, err)
		}
	}

	locked, err := tr.RecordFail(ctx, targetID)
	if err != nil {
		t.Fatalf("RecordFail #3: %v", err)
	}
	if !locked {
		t.Fatal("RecordFail #3 returned locked=false; the 3rd failure must lock")
	}

	// Locked must now agree on a fresh round-trip — verifiers consult it
	// before doing any work so the answer must persist past the call
	// that set it.
	stillLocked, err := tr.Locked(ctx, targetID)
	if err != nil {
		t.Fatalf("Locked: %v", err)
	}
	if !stillLocked {
		t.Fatal("Locked returned false after 3rd failure; expected true")
	}
}

// TestLockTTLExpires confirms that the lockout naturally clears after
// the one-hour window elapses without further failures. miniredis'
// FastForward drives virtual time so the test runs in microseconds.
func TestLockTTLExpires(t *testing.T) {
	t.Parallel()
	mr, tr := startCooldown(t)
	ctx := t.Context()
	const targetID = "tgt-003"

	for i := 1; i <= 3; i++ {
		if _, err := tr.RecordFail(ctx, targetID); err != nil {
			t.Fatalf("RecordFail #%d: %v", i, err)
		}
	}
	locked, err := tr.Locked(ctx, targetID)
	if err != nil {
		t.Fatalf("Locked (pre-expiry): %v", err)
	}
	if !locked {
		t.Fatal("Locked must be true immediately after the 3rd failure")
	}

	// One nanosecond shy of the TTL the lock must still be held — this
	// guards against an off-by-one in the TTL stamp.
	mr.FastForward(cooldownWindow - time.Second)
	locked, err = tr.Locked(ctx, targetID)
	if err != nil {
		t.Fatalf("Locked (just before expiry): %v", err)
	}
	if !locked {
		t.Fatal("Locked must remain true 1s before TTL elapses")
	}

	// Cross the TTL and the sentinel must be evicted.
	mr.FastForward(2 * time.Second)
	locked, err = tr.Locked(ctx, targetID)
	if err != nil {
		t.Fatalf("Locked (post-expiry): %v", err)
	}
	if locked {
		t.Fatal("Locked must be false after the 1-hour window elapses")
	}
}

// TestResetClearsLockAndCounter confirms that a successful verification
// wipes both the running failure counter and any active lockout. The
// requirement reads "consecutive" failures; a single success therefore
// returns the Target to a clean slate.
func TestResetClearsLockAndCounter(t *testing.T) {
	t.Parallel()
	_, tr := startCooldown(t)
	ctx := t.Context()
	const targetID = "tgt-004"

	for i := 1; i <= 3; i++ {
		if _, err := tr.RecordFail(ctx, targetID); err != nil {
			t.Fatalf("RecordFail #%d: %v", i, err)
		}
	}
	locked, err := tr.Locked(ctx, targetID)
	if err != nil {
		t.Fatalf("Locked: %v", err)
	}
	if !locked {
		t.Fatal("Locked must be true before Reset")
	}

	if err := tr.Reset(ctx, targetID); err != nil {
		t.Fatalf("Reset: %v", err)
	}

	// Lock cleared.
	locked, err = tr.Locked(ctx, targetID)
	if err != nil {
		t.Fatalf("Locked (post-reset): %v", err)
	}
	if locked {
		t.Fatal("Locked must be false after Reset")
	}

	// Counter cleared too — the next two failures must NOT lock; only a
	// fresh third failure should. If Reset had spared the counter, the
	// very first follow-up failure would re-trip the lock.
	for i := 1; i <= 2; i++ {
		l, err := tr.RecordFail(ctx, targetID)
		if err != nil {
			t.Fatalf("RecordFail post-reset #%d: %v", i, err)
		}
		if l {
			t.Fatalf("RecordFail post-reset #%d locked unexpectedly; counter not cleared", i)
		}
	}
}

// TestResetIdempotent guards the documented contract that Reset on a
// pristine Target is a no-op rather than an error.
func TestResetIdempotent(t *testing.T) {
	t.Parallel()
	_, tr := startCooldown(t)
	ctx := t.Context()
	const targetID = "tgt-005"

	if err := tr.Reset(ctx, targetID); err != nil {
		t.Fatalf("Reset on fresh target: %v", err)
	}
	if err := tr.Reset(ctx, targetID); err != nil {
		t.Fatalf("Reset second call: %v", err)
	}
}

// TestEmptyTargetIDRejected protects each public method from blank
// target ids that would otherwise hash all callers into the same Redis
// slot — a worst-case denial-of-service against the cool-down ledger.
func TestEmptyTargetIDRejected(t *testing.T) {
	t.Parallel()
	_, tr := startCooldown(t)
	ctx := t.Context()

	if _, err := tr.RecordFail(ctx, ""); err == nil {
		t.Fatal("RecordFail with empty id must error")
	}
	if _, err := tr.Locked(ctx, ""); err == nil {
		t.Fatal("Locked with empty id must error")
	}
	if err := tr.Reset(ctx, ""); err == nil {
		t.Fatal("Reset with empty id must error")
	}
}

// TestRecordFailCounterTTLBoundsWindow ensures the failure counter is
// itself stamped with the one-hour TTL, so a Target that fails once and
// then sits quiet for the rest of the day starts the next attempt with
// a clean budget. Without the TTL stamp on the counter the verifier
// would treat a 6-month-old failure as recent.
func TestRecordFailCounterTTLBoundsWindow(t *testing.T) {
	t.Parallel()
	mr, tr := startCooldown(t)
	ctx := t.Context()
	const targetID = "tgt-006"

	if _, err := tr.RecordFail(ctx, targetID); err != nil {
		t.Fatalf("RecordFail: %v", err)
	}

	// Fast-forward past the window; the counter must have evicted.
	mr.FastForward(cooldownWindow + time.Second)

	// Two follow-up failures must still NOT lock — the previous failure
	// fell out of the window.
	for i := 1; i <= 2; i++ {
		locked, err := tr.RecordFail(ctx, targetID)
		if err != nil {
			t.Fatalf("RecordFail post-window #%d: %v", i, err)
		}
		if locked {
			t.Fatalf("RecordFail post-window #%d locked; window did not slide", i)
		}
	}
}

// TestNewCooldownTrackerReturnsUsable is a smoke check that the
// constructor is wired correctly. We exercise it through a real
// miniredis-backed client because the type carries no behaviour
// distinct from its dependency.
func TestNewCooldownTrackerReturnsUsable(t *testing.T) {
	t.Parallel()
	mr := miniredis.RunT(t)
	cli, err := cloudredis.New(context.Background(), cloudredis.Options{Addrs: []string{mr.Addr()}})
	if err != nil {
		t.Fatalf("cloudredis.New: %v", err)
	}
	t.Cleanup(func() { _ = cli.Close() })

	tr := NewCooldownTracker(cli)
	if tr == nil {
		t.Fatal("NewCooldownTracker returned nil")
	}
	if _, err := tr.Locked(context.Background(), "tgt-smoke"); err != nil {
		t.Fatalf("Locked on fresh tracker: %v", err)
	}
}
