// Package auth implements the runtime-editable Profile_Store and the
// pluggable OAuth_Driver registry that together back the
// provider-catalog-and-oauth feature.
//
// This file declares Token_Sink — the in-process per-key mutex
// registry that coalesces concurrent token-refresh attempts before
// they ever contend for the on-disk flock held by Profile_Store.Put.
//
// The two-layer design is deliberate: the file flock is the
// inter-process / cross-restart correctness boundary (Requirement
// 4.3), but inside a single process N goroutines hitting the same
// expiring profile would otherwise all observe the same expiry, all
// POST the token endpoint, and only one of N rotated refresh tokens
// would survive the resulting last-write-wins race. The sink puts an
// in-memory mutex in front of that flock so concurrent in-process
// callers of the same <provider>:<profileId> serialize cheaply (no
// syscalls), and only the eventual Put contends for the file lock.
package auth

import "sync"

// TokenSink is a per-"<provider>:<profileId>" mutex registry layered
// on top of the file-level flock owned by Profile_Store. Its single
// responsibility is to ensure that, within one process, at most one
// goroutine at a time attempts an upstream refresh for any given
// profile key — the second caller blocks on acquire, then re-reads
// the freshly-persisted profile after the holder releases.
//
// The struct intentionally exposes no public methods. Callers are
// expected to be Driver.Refresh implementations inside this package
// (see refreshWithSink in driver.go, introduced by task 3.3) which
// follow the canonical pattern documented on acquire below.
//
// Validates: Requirements 10.1, 10.2, 10.3.
type TokenSink struct {
	// mu guards the locks map itself. It is held only for the
	// brief lookup-or-insert against the map; it is NEVER held
	// while waiting on a per-key mutex, otherwise a slow refresh
	// would block every other key's acquire as well.
	mu sync.Mutex

	// locks maps "<provider>:<profileId>" → the per-key mutex.
	// Entries are created lazily on first acquire and live for
	// the lifetime of the TokenSink. The memory cost is bounded
	// by the number of distinct profile keys ever refreshed,
	// which in practice is small (one per signed-in account).
	locks map[string]*sync.Mutex
}

// newTokenSink constructs an empty TokenSink with an initialized
// locks map. It is unexported because the only legitimate owner is
// Profile_Store, which instantiates exactly one sink in NewStore.
func newTokenSink() *TokenSink {
	return &TokenSink{locks: make(map[string]*sync.Mutex)}
}

// acquire returns the per-key mutex for the given canonical
// "<provider>:<profileId>" key, lazily creating it on first use, and
// returns it ALREADY LOCKED. The caller MUST defer Unlock on the
// returned mutex.
//
// The canonical refresh pattern (used by every Driver.Refresh) is:
//
//	m := store.sink.acquire(p.Key())
//	defer m.Unlock()
//	// Re-read the profile under the in-process mutex — another
//	// caller may have already refreshed and persisted while we
//	// were waiting (Requirement 10.2).
//	fresh, _, _ := store.Get(ctx, p.Key())
//	if !needsRefresh(fresh) {
//	    return fresh, nil
//	}
//	newP, err := upstreamRefresh(ctx, fresh)
//	// ... persist newP via store.Put while still holding m
//	// (Requirement 10.3).
//
// acquire is safe for concurrent use from any number of goroutines.
//
// Validates: Requirements 10.1, 10.2, 10.3.
func (t *TokenSink) acquire(key string) *sync.Mutex {
	// Look up or insert the per-key mutex under t.mu. Releasing
	// t.mu BEFORE Lock'ing m is essential: holding t.mu across a
	// Lock would let one slow-refresh per-key mutex block every
	// other key's acquire and defeat the whole point of having a
	// per-key map.
	t.mu.Lock()
	m, ok := t.locks[key]
	if !ok {
		m = &sync.Mutex{}
		t.locks[key] = m
	}
	t.mu.Unlock()

	m.Lock()
	return m
}
