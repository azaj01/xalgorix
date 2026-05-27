// Package auth — TokenSink behavior tests covering the
// Requirement 10.1–10.4 protocol from the design doc.
//
// These tests exercise refreshWithSink (driver.go) directly with a
// real *Store backed by t.TempDir() so the sink + Profile_Store
// interaction is the same one each per-flow Driver.Refresh routes
// through. The "stub Refresh" the task brief calls for is the
// `exchange` closure passed to refreshWithSink — every per-flow
// driver builds the same closure shape (POST tokenEndpoint, parse
// JSON, return rotated Profile).
package auth

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xalgord/xalgorix/v4/internal/providers"
)

// stubCatalog is a minimal CatalogResolver good enough for
// Profile_Store.Put's Requirement 4.8 catalog gate. The sink tests
// only need a single "openai" entry so Put admits the seeded
// Profile without reaching out to a real *providers.Service.
type stubCatalog struct {
	entries map[string]providers.Entry
}

func (s *stubCatalog) IsEmpty() bool { return len(s.entries) == 0 }

func (s *stubCatalog) Get(_ context.Context, id string) (providers.Entry, bool, error) {
	e, ok := s.entries[id]
	return e, ok, nil
}

// newSinkTestStore constructs a real *Store rooted at t.TempDir()
// pre-seeded with one Catalog_Entry the seeded profiles can
// reference. Returned Store has its sink already wired by NewStore.
func newSinkTestStore(t *testing.T) *Store {
	t.Helper()
	dir := t.TempDir()
	cat := &stubCatalog{entries: map[string]providers.Entry{
		"openai": {
			ID:          "openai",
			DisplayName: "OpenAI",
			BaseURL:     "https://api.openai.com/v1",
			HeaderStyle: "openai",
		},
	}}
	s, err := NewStore(filepath.Join(dir, "auth-profiles.json"), cat)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	return s
}

// seedOAuthProfile writes a stale-but-valid OAuth_Profile under
// "openai:default" so the sink tests have a real on-disk record to
// re-read inside refreshWithSink.
func seedOAuthProfile(t *testing.T, s *Store, accessToken string) {
	t.Helper()
	p := Profile{
		Provider:     "openai",
		ProfileID:    "default",
		Type:         OAuth,
		AccessToken:  accessToken,
		RefreshToken: "rt-" + accessToken,
		ExpiresAt:    time.Now().Add(30 * time.Second).UTC(),
		Scopes:       []string{"chat"},
		TokenType:    "Bearer",
	}
	if err := s.Put(context.Background(), p); err != nil {
		t.Fatalf("seed Put: %v", err)
	}
}

// TestTokenSink_CoalescesConcurrentRefreshes exercises Property 20
// from the design: N=100 goroutines all attempting to refresh the
// same expiring OAuth_Profile observe exactly one upstream POST
// (the first acquirer) and every caller returns with the same fresh
// AccessToken read back from the Profile_Store.
//
// The exchange closure mimics how each per-flow Driver.Refresh body
// behaves under the sink protocol: it short-circuits when the
// freshly-read profile already carries the rotated token (the
// "Requirement 10.2 re-read" branch in driver.go) and otherwise
// POSTs upstream — bumping the atomic counter we assert against.
//
// Validates: Requirements 10.1, 10.2, 10.3.
func TestTokenSink_CoalescesConcurrentRefreshes(t *testing.T) {
	ctx := context.Background()
	store := newSinkTestStore(t)
	seedOAuthProfile(t, store, "stale")

	const N = 100
	const freshToken = "fresh-token-set-by-someone"

	var upstreamCalls atomic.Int64

	exchange := func(current Profile) (Profile, error) {
		// Requirement 10.2 short-circuit: a previous caller has
		// already rotated the token while this goroutine was
		// waiting on the sink. Returning current unchanged
		// avoids a redundant upstream POST.
		if current.AccessToken == freshToken {
			return current, nil
		}
		upstreamCalls.Add(1)
		// Small sleep so concurrent goroutines actually pile up
		// on the sink rather than racing through serially.
		time.Sleep(2 * time.Millisecond)
		next := current
		next.AccessToken = freshToken
		next.RefreshToken = "rt-" + freshToken
		next.ExpiresAt = time.Now().Add(time.Hour).UTC()
		return next, nil
	}

	results := make([]Profile, N)
	errs := make([]error, N)
	start := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(N)
	for i := 0; i < N; i++ {
		i := i
		go func() {
			defer wg.Done()
			<-start
			p, err := refreshWithSink(ctx, store, "openai:default", exchange)
			results[i] = p
			errs[i] = err
		}()
	}
	close(start)
	wg.Wait()

	if got := upstreamCalls.Load(); got != 1 {
		t.Fatalf("expected exactly 1 upstream POST, got %d (sink failed to coalesce)", got)
	}

	for i, err := range errs {
		if err != nil {
			t.Fatalf("caller %d returned unexpected error: %v", i, err)
		}
		if results[i].AccessToken != freshToken {
			t.Fatalf("caller %d: AccessToken = %q, want %q", i, results[i].AccessToken, freshToken)
		}
	}

	// And the on-disk profile should agree with what every caller
	// observed: the rotated token, persisted under the sink as
	// Requirement 10.3 demands.
	final, ok, err := store.Get(ctx, "openai:default")
	if err != nil {
		t.Fatalf("post-refresh Get: %v", err)
	}
	if !ok {
		t.Fatalf("profile vanished after refresh")
	}
	if final.AccessToken != freshToken {
		t.Fatalf("on-disk AccessToken = %q, want %q", final.AccessToken, freshToken)
	}
}

// TestTokenSink_SecondCallerReReadsAfterRelease asserts the
// Requirement 10.2 contract directly: the second caller of
// refreshWithSink for the same key MUST observe the freshly
// persisted token after the first caller releases the sink, not the
// stale token it would have read at goroutine start.
//
// The flow uses two channels (started, release) to pin the timing
// without depending on the test scheduler:
//
//   - goroutine A enters exchange, signals "started", blocks on
//     "release" — at this point the sink mutex is held and the
//     stale profile is the on-disk state.
//   - goroutine B is then launched; it calls refreshWithSink, which
//     blocks on TokenSink.acquire because A still holds it.
//   - the test closes "release"; A's exchange persists "freshA";
//     refreshWithSink's defer releases the sink; B unblocks,
//     re-reads the now-fresh profile, and its exchange records
//     the token it actually saw.
//
// Validates: Requirements 10.1, 10.2, 10.3.
func TestTokenSink_SecondCallerReReadsAfterRelease(t *testing.T) {
	ctx := context.Background()
	store := newSinkTestStore(t)
	seedOAuthProfile(t, store, "stale")

	started := make(chan struct{})
	release := make(chan struct{})

	var aResult Profile
	var aErr error
	aDone := make(chan struct{})
	go func() {
		defer close(aDone)
		aResult, aErr = refreshWithSink(ctx, store, "openai:default", func(current Profile) (Profile, error) {
			close(started)
			<-release
			next := current
			next.AccessToken = "freshA"
			next.RefreshToken = "rt-freshA"
			next.ExpiresAt = time.Now().Add(time.Hour).UTC()
			return next, nil
		})
	}()

	// Wait for A to be inside its exchange (and therefore holding
	// the per-key sink mutex on the seeded profile's key).
	<-started

	var bSawToken string
	var bResult Profile
	var bErr error
	bDone := make(chan struct{})
	go func() {
		defer close(bDone)
		bResult, bErr = refreshWithSink(ctx, store, "openai:default", func(current Profile) (Profile, error) {
			bSawToken = current.AccessToken
			// B short-circuits — the first caller already
			// rotated the token, so no upstream POST is
			// needed. This is the canonical R10.2 branch.
			return current, nil
		})
	}()

	// Give B time to reach TokenSink.acquire and block. 50ms is
	// generous on every developer machine and CI runner the
	// project targets, including under -race.
	time.Sleep(50 * time.Millisecond)
	close(release)

	<-aDone
	<-bDone

	if aErr != nil {
		t.Fatalf("A: unexpected error: %v", aErr)
	}
	if bErr != nil {
		t.Fatalf("B: unexpected error: %v", bErr)
	}
	if aResult.AccessToken != "freshA" {
		t.Fatalf("A: AccessToken = %q, want %q", aResult.AccessToken, "freshA")
	}
	if bSawToken != "freshA" {
		t.Fatalf("B: exchange saw stale token %q, expected freshA — sink did not enforce R10.2 re-read", bSawToken)
	}
	if bResult.AccessToken != "freshA" {
		t.Fatalf("B: result AccessToken = %q, want %q", bResult.AccessToken, "freshA")
	}
}

// TestTokenSink_InvalidGrantSetsRequiresReauth covers Property 21:
// an upstream invalid_grant response causes refreshWithSink to (a)
// return ErrReauthRequired so the HTTP layer can map it to 401, and
// (b) flip Profile.RequiresReauth = true on disk so the dashboard
// can surface the re-auth prompt. Both the bare ErrInvalidGrant and
// a fmt.Errorf-wrapped variant are exercised so refreshWithSink's
// errors.Is lookup is verified end-to-end.
//
// Validates: Requirement 10.4.
func TestTokenSink_InvalidGrantSetsRequiresReauth(t *testing.T) {
	cases := []struct {
		name string
		err  error
	}{
		{name: "bare", err: ErrInvalidGrant},
		{name: "wrapped", err: fmt.Errorf("upstream rejected refresh: %w", ErrInvalidGrant)},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			store := newSinkTestStore(t)
			seedOAuthProfile(t, store, "stale")

			got, err := refreshWithSink(ctx, store, "openai:default", func(_ Profile) (Profile, error) {
				return Profile{}, tc.err
			})
			if !errors.Is(err, ErrReauthRequired) {
				t.Fatalf("expected ErrReauthRequired, got %v", err)
			}
			if !got.RequiresReauth {
				t.Fatalf("returned profile.RequiresReauth = false, want true")
			}

			persisted, ok, gerr := store.Get(ctx, "openai:default")
			if gerr != nil {
				t.Fatalf("post-refresh Get: %v", gerr)
			}
			if !ok {
				t.Fatalf("profile vanished after invalid_grant")
			}
			if !persisted.RequiresReauth {
				t.Fatalf("on-disk RequiresReauth = false, want true (R10.4 not persisted)")
			}
			// The stored credentials should not have been
			// touched — invalid_grant only flips the flag,
			// it does not blank the tokens (the dashboard
			// surfaces the re-auth UX with the existing
			// metadata still visible).
			if persisted.AccessToken != "stale" {
				t.Fatalf("AccessToken mutated on invalid_grant: got %q, want %q", persisted.AccessToken, "stale")
			}
		})
	}
}
