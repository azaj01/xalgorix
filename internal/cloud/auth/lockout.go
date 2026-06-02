package auth

// File lockout.go implements task 2.5 of the xalgorix-saas spec — the
// account-level sign-in lockout primitive that backs `POST /auth/login`.
//
// Behaviour mirrors design.md → "Authentication → Lockout":
//
//   - Per-key failure counter in Redis at `lockout:fails:{key}` with a
//     10-minute TTL. INCR is atomic, so two concurrent failed sign-ins
//     can never both observe the threshold transition.
//   - On the FailThreshold-th (5th) failure within the rolling window
//     LockoutTracker.RecordFail also writes `lockout:locked:{key}` with
//     a 15-minute TTL. While that key exists Locked returns true and
//     the login handler MUST short-circuit with HTTP 423 before ever
//     calling Verify (Requirements 3.5, 3.9).
//   - Reset is invoked after a successful authentication so a user who
//     finally remembers their password is not penalised by stale fail
//     counts left over from earlier mistakes.
//
// `key` is an opaque identifier chosen by the caller; the login handler
// uses the lower-cased, trimmed email so attackers cannot evade the
// lockout by varying capitalisation. The tracker treats `key` as opaque
// — emails, account UUIDs, or `<email>@<ip>` composites all work.
//
// The signatures follow the task description exactly:
//
//	RecordFail(ctx, key string) (currentFails int, locked bool)
//	Locked(ctx, key string) (bool, error)
//	Reset(ctx, key string)
//
// Redis errors during RecordFail and Reset are logged via the injected
// zerolog.Logger and the call returns conservatively (RecordFail returns
// `(0, false)` so the caller does not falsely emit `auth_lockout`; Reset
// is best-effort by definition because the user has already authenticated
// successfully). Locked surfaces errors so the login handler can reply
// with HTTP 500 rather than silently letting a request through when the
// lockout system itself is unavailable — failing closed on the read path
// is the safer choice for an authentication primitive.
//
// Requirements: 3.5, 3.9.

import (
	"context"
	"errors"
	"fmt"
	"time"

	goredis "github.com/redis/go-redis/v9"
	"github.com/rs/zerolog"

	redisclient "github.com/xalgord/xalgorix/v4/internal/cloud/redis"
)

// Lockout tuning constants. They match Requirement 3.9 verbatim and are
// exported as constants so tests, dashboards, and documentation can
// reference the same values that ship in production.
const (
	// FailWindow is the rolling window over which consecutive failed
	// sign-ins accumulate. Once the failure counter is created in
	// Redis it expires after this duration of inactivity.
	FailWindow = 10 * time.Minute
	// FailThreshold is the number of failed sign-ins within FailWindow
	// that trips a lockout. The 5th failure is the threshold-crossing
	// call; subsequent failures within the lock window are absorbed by
	// the Locked short-circuit in the login handler.
	FailThreshold = 5
	// LockDuration is how long sign-in is denied after the threshold
	// is crossed. The lock key carries this TTL so it is automatically
	// reaped without any reaper process.
	LockDuration = 15 * time.Minute
)

// Redis key prefixes. Centralising them avoids drift between the
// implementation and the per-key tests below, and makes the audit
// surface easy to spot in `redis-cli MONITOR` output.
const (
	failsKeyPrefix  = "lockout:fails:"
	lockedKeyPrefix = "lockout:locked:"
)

// LockoutTracker is the Redis-backed sign-in lockout primitive. It is
// safe for concurrent use; all of its mutating operations are atomic
// at the Redis layer (INCR for the counter, SET with TTL for the lock
// itself). Construct one per process via NewLockoutTracker.
type LockoutTracker struct {
	redis  *redisclient.Client
	logger zerolog.Logger
}

// NewLockoutTracker constructs a LockoutTracker. It panics if redis is
// nil, which is a programming error that must surface at boot rather
// than at the first failed sign-in.
func NewLockoutTracker(redis *redisclient.Client, logger zerolog.Logger) *LockoutTracker {
	if redis == nil {
		panic("auth: NewLockoutTracker requires a non-nil redis client")
	}
	return &LockoutTracker{redis: redis, logger: logger}
}

// RecordFail records one failed sign-in attempt for key and returns the
// updated failure count and whether the account is now locked.
//
// `locked` is true exactly when this call caused the failure counter
// to reach FailThreshold (meaning the lock key was just written) or
// when an earlier call already pushed the counter past the threshold
// within the same window. The login handler uses the equality
// `currentFails == FailThreshold` to detect the threshold-crossing
// transition and emit a single `auth_lockout` audit event; later
// failures within the window are absorbed by the Locked short-circuit
// and never reach RecordFail in normal flow.
//
// Redis errors are logged and the call returns `(0, false)` so the
// caller falls back to the safer behaviour of not over-counting fails
// or emitting a phantom audit. The login handler treats this as the
// usual "wrong password" path and returns HTTP 401.
func (lt *LockoutTracker) RecordFail(ctx context.Context, key string) (int, bool) {
	if key == "" {
		return 0, false
	}
	rdb := lt.redis.Underlying()

	// INCR + EXPIRE in a single round-trip. INCR is atomic so two
	// concurrent fails can never both observe the same `current`
	// value; the EXPIRE refreshes the rolling window on every fail
	// which is the behaviour Requirement 3.9 ("within 10 minutes")
	// implies — the window is per-burst, not per-creation.
	pipe := rdb.TxPipeline()
	incr := pipe.Incr(ctx, failsRedisKey(key))
	pipe.Expire(ctx, failsRedisKey(key), FailWindow)
	if _, err := pipe.Exec(ctx); err != nil {
		lt.logger.Error().
			Err(err).
			Str("event", "auth_lockout_redis_error").
			Str("op", "RecordFail.incr").
			Msg("auth: lockout counter unavailable; failing open")
		return 0, false
	}

	current := int(incr.Val())
	if current < FailThreshold {
		return current, false
	}

	// Threshold reached or exceeded: ensure the lock key exists with a
	// fresh 15-minute TTL. SET (not SETNX) intentionally refreshes the
	// TTL so a determined attacker cannot keep the counter pegged at
	// FailThreshold while letting the lock TTL drain. Using a plain
	// SET also makes the call idempotent under retries.
	if err := rdb.Set(ctx, lockedRedisKey(key), "1", LockDuration).Err(); err != nil {
		lt.logger.Error().
			Err(err).
			Str("event", "auth_lockout_redis_error").
			Str("op", "RecordFail.set_lock").
			Int("current_fails", current).
			Msg("auth: lockout lock key write failed")
		// Counter advanced but lock didn't materialise. Return the
		// current count so the caller can still report progress, but
		// flag locked=false so we don't emit a phantom audit on a
		// state we couldn't actually persist.
		return current, false
	}
	return current, true
}

// Locked reports whether key is currently subject to a sign-in lock.
// It returns the boolean state and a non-nil error only when Redis
// itself is unavailable; in that case the login handler MUST refuse
// the sign-in (failing closed) rather than letting a request through
// the gate while the gate keeper is offline.
func (lt *LockoutTracker) Locked(ctx context.Context, key string) (bool, error) {
	if key == "" {
		return false, nil
	}
	err := lt.redis.Underlying().Get(ctx, lockedRedisKey(key)).Err()
	if err == nil {
		return true, nil
	}
	if errors.Is(err, goredis.Nil) {
		return false, nil
	}
	return false, fmt.Errorf("auth: read lockout state: %w", err)
}

// Reset clears both the failure counter and the lock key for key. It
// is invoked after a successful authentication so legitimate users
// are not penalised by leftover counts from earlier mistakes, and is
// a no-op when neither key exists.
//
// Reset is best-effort: a Redis failure here means the user has
// already authenticated, so the worst case is that the next failed
// sign-in observes one extra fail in the counter. Errors are logged
// for operator visibility but never returned.
func (lt *LockoutTracker) Reset(ctx context.Context, key string) {
	if key == "" {
		return
	}
	rdb := lt.redis.Underlying()
	if err := rdb.Del(ctx, failsRedisKey(key), lockedRedisKey(key)).Err(); err != nil {
		lt.logger.Error().
			Err(err).
			Str("event", "auth_lockout_redis_error").
			Str("op", "Reset").
			Msg("auth: lockout reset failed; counters may persist")
	}
}

// failsRedisKey returns the Redis key for the failure counter.
func failsRedisKey(key string) string { return failsKeyPrefix + key }

// lockedRedisKey returns the Redis key for the lock flag.
func lockedRedisKey(key string) string { return lockedKeyPrefix + key }
