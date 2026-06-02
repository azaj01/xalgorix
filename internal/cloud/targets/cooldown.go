// Copyright (c) Xalgorix.
// SPDX-License-Identifier: AGPL-3.0-only

package targets

import (
	"context"
	"errors"
	"fmt"
	"time"

	cloudredis "github.com/xalgord/xalgorix/v4/internal/cloud/redis"
)

// Verification cooldown is the rate-limit half of the target ownership flow
// described in design.md → "Cooldown" and pinned by Requirement 7.5: three
// consecutive verification failures inside a one-hour window must trigger a
// one-hour lockout per Target before the API_Server accepts another check.
//
// The ledger lives in Redis rather than Postgres because (a) every API
// replica needs to see the same counter without coordinating through the
// database, (b) TTL semantics are exactly what we want — Redis evicts the
// counter for us when the window elapses — and (c) the writes are
// fire-and-forget from the verifier's hot path.
//
// Two keys per Target back the implementation:
//
//   - `verify_cooldown:fails:{targetID}` — INCR-driven counter; the first
//     failure inside an empty window stamps a 60-minute TTL. The counter
//     therefore measures failures within a sliding one-hour window of the
//     first failure, matching the requirement's "three failures within
//     1 hour" wording.
//
//   - `verify_cooldown:locked:{targetID}` — sentinel that exists for 60
//     minutes after the third failure. Verifiers consult this key first; if
//     present, they refuse the attempt and the API surface returns the
//     `target_verification_cooldown` error envelope (HTTP 429,
//     design.md → Error Codes table).
//
// On a successful verification the verifier calls [CooldownTracker.Reset]
// so a single legitimate success wipes the counter and unblocks future
// retries — `consecutive` in the requirement is interpreted as
// "consecutive failures since the last success", which is the only reading
// that matches a daily re-check job that may legitimately fail once and
// then recover.

const (
	// cooldownFailKeyPrefix is the namespace used for the per-target
	// failure counter. Centralising the literal here keeps the Redis
	// keyspace audit (see docs/runbooks once Phase 18 lands) honest.
	cooldownFailKeyPrefix = "verify_cooldown:fails:"

	// cooldownLockKeyPrefix is the namespace used for the per-target
	// lockout sentinel. Verifiers read this key with [CooldownTracker.Locked]
	// before issuing a check.
	cooldownLockKeyPrefix = "verify_cooldown:locked:"

	// cooldownWindow is both the rolling failure window AND the lockout
	// duration. Requirement 7.5 specifies one hour for both, so a single
	// constant is the truthful representation; if the two ever diverge,
	// split this into `cooldownWindow` and `cooldownLockTTL`.
	cooldownWindow = time.Hour

	// cooldownFailThreshold is the number of failures that must accumulate
	// inside cooldownWindow before the Target is locked out. Requirement
	// 7.5 fixes this at three.
	cooldownFailThreshold = 3
)

// errEmptyTargetID is returned by every CooldownTracker method when handed
// a blank target id. Bubbling a typed sentinel rather than panicking keeps
// the verifier — which receives target ids from URL paths — defensive
// against malformed routes without crashing the API replica.
var errEmptyTargetID = errors.New("targets/cooldown: target id must not be empty")

// CooldownTracker enforces the per-target verification cooldown ledger
// described in design.md → "Cooldown". A single instance is safe for
// concurrent use because the underlying [cloudredis.Client] maintains its
// own connection pool; callers are expected to construct one tracker per
// process and share it across verifiers.
type CooldownTracker struct {
	// rdb is the Cloud_Platform Redis facade. We hold the wrapper rather
	// than the raw `redis.UniversalClient` so future migrations (sentinel
	// → cluster, ACL rotations) keep going through the central ping/close
	// surface in `internal/cloud/redis`.
	rdb *cloudredis.Client
}

// NewCooldownTracker returns a [CooldownTracker] backed by rdb. It does
// not perform any I/O; the Redis facade has already PINGed the server
// during its own construction (see `internal/cloud/redis.New`).
//
// Passing a nil client is a programmer error and will panic on first use;
// the constructor accepts nil only to keep wiring code that defers
// initialisation simple.
func NewCooldownTracker(rdb *cloudredis.Client) *CooldownTracker {
	return &CooldownTracker{rdb: rdb}
}

// RecordFail records a single verification failure for targetID and
// returns whether the Target is now locked out.
//
// Algorithm:
//
//  1. INCR `verify_cooldown:fails:{targetID}` — Redis returns the new
//     value, atomically created with value 1 if the key did not exist.
//  2. When the new value is exactly 1 — i.e. this is the first failure of
//     a fresh window — stamp a 60-minute TTL on the counter so the window
//     slides in lockstep with the lockout duration.
//  3. When the new value reaches the threshold (default 3), set the
//     lockout sentinel `verify_cooldown:locked:{targetID}` with the same
//     60-minute TTL and return `(true, nil)`.
//
// Calling RecordFail while the Target is already locked still extends the
// failure counter but does not reset the lockout TTL — the sentinel
// outlives any number of trailing failures because its expiry is always
// bounded by the original lockout window. This matches the requirement's
// intent of "1-hour cool-down" rather than "1 hour after the most recent
// failure".
//
// The function returns an error when targetID is empty or when any Redis
// command fails. Wrapped errors carry the operation name so logs surface
// the failure path without further plumbing.
//
// Implements Requirement 7.5.
func (t *CooldownTracker) RecordFail(ctx context.Context, targetID string) (bool, error) {
	if targetID == "" {
		return false, errEmptyTargetID
	}
	rdb := t.rdb.Underlying()
	failKey := cooldownFailKeyPrefix + targetID

	n, err := rdb.Incr(ctx, failKey).Result()
	if err != nil {
		return false, fmt.Errorf("targets/cooldown: incr fails: %w", err)
	}
	// Only the first INCR of a fresh window stamps a TTL. Re-stamping on
	// every call would turn the counter into a pure rolling window and
	// drift past the one-hour bound the requirement specifies.
	if n == 1 {
		if err := rdb.Expire(ctx, failKey, cooldownWindow).Err(); err != nil {
			return false, fmt.Errorf("targets/cooldown: expire fails: %w", err)
		}
	}
	if n >= int64(cooldownFailThreshold) {
		lockKey := cooldownLockKeyPrefix + targetID
		// SET (not SETNX) so the third failure always lands a fresh 60m
		// TTL even if the sentinel was previously evicted by an admin
		// FLUSHDB or a race against a manual reset.
		if err := rdb.Set(ctx, lockKey, "1", cooldownWindow).Err(); err != nil {
			return false, fmt.Errorf("targets/cooldown: set lock: %w", err)
		}
		return true, nil
	}
	return false, nil
}

// Locked reports whether targetID is currently inside its one-hour
// lockout window. It is the cheap pre-flight check verifiers issue before
// performing any DNS/HTTP work — by short-circuiting locked Targets at
// the door we keep the cool-down from being ablated by retries.
//
// Locked is a single EXISTS round-trip and is safe to call from request
// handlers under the per-request deadline.
func (t *CooldownTracker) Locked(ctx context.Context, targetID string) (bool, error) {
	if targetID == "" {
		return false, errEmptyTargetID
	}
	rdb := t.rdb.Underlying()
	lockKey := cooldownLockKeyPrefix + targetID

	n, err := rdb.Exists(ctx, lockKey).Result()
	if err != nil {
		return false, fmt.Errorf("targets/cooldown: exists lock: %w", err)
	}
	return n > 0, nil
}

// Reset clears both the failure counter and the lockout sentinel for
// targetID. It is intended to be called by the verifier on a successful
// ownership check so a single recovery resets the consecutive-failure
// budget — matching the requirement's "consecutive" wording.
//
// Reset is idempotent: deleting keys that do not exist is not an error.
// Both keys are deleted in a single DEL command to avoid leaving the
// failure counter alive while the lock is gone (or vice-versa) in the
// presence of a partial network failure mid-call.
func (t *CooldownTracker) Reset(ctx context.Context, targetID string) error {
	if targetID == "" {
		return errEmptyTargetID
	}
	rdb := t.rdb.Underlying()
	failKey := cooldownFailKeyPrefix + targetID
	lockKey := cooldownLockKeyPrefix + targetID

	if err := rdb.Del(ctx, failKey, lockKey).Err(); err != nil {
		return fmt.Errorf("targets/cooldown: del cooldown keys: %w", err)
	}
	return nil
}
