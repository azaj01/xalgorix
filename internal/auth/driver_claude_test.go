// Package auth — driver_claude_test verifies the claude_cli_reuse
// driver against Requirements 9.1, 9.2, 9.3.
//
// Properties covered (cross-referenced from design.md):
//
//   - Property 19 (read-only import): R9.3 →
//     TestClaude_DoesNotMutateSource recomputes SHA-256 + mtime of
//     the source credential file before and after Complete and
//     asserts equality across ≥ 100 randomized credential bodies.
//
//   - Happy path (R9.1) → TestClaude_ImportFromCLIPath constructs a
//     credential file, runs Complete, and asserts the persisted
//     OAuth_Profile carries the same access/refresh tokens and a
//     valid ExpiresAt.
//
//   - Missing-file path (R9.2) → TestClaude_MissingFileReturns404
//     overrides claudeCredentialPathFn to return a path that does
//     not exist and asserts Complete returns ErrNotFound, which the
//     HTTP layer maps to 404 "claude cli credentials not found".
//
// Validates: Requirements 9.1, 9.2, 9.3.
package auth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/xalgord/xalgorix/v4/internal/providers"
)

// claudeStubCatalog admits a single Catalog_Entry under a known id
// so Profile_Store.Put accepts the imported profile (Requirement
// 4.8 catalog gate). Like setupStubCatalog, named distinctly from
// the package-scoped stubCatalog declared in sink_test.go to avoid
// a same-package type collision.
type claudeStubCatalog struct {
	id    string
	entry providers.Entry
}

func (s *claudeStubCatalog) IsEmpty() bool { return false }

func (s *claudeStubCatalog) Get(_ context.Context, id string) (providers.Entry, bool, error) {
	if id != s.id {
		return providers.Entry{}, false, nil
	}
	return s.entry, true, nil
}

// claudeTestFixture bundles the driver, the on-disk Profile_Store,
// the Catalog_Entry, the temp credential-file path, and the
// previous claudeCredentialPathFn value (restored on cleanup).
type claudeTestFixture struct {
	t          *testing.T
	driver     *claudeReuseDriver
	store      *Store
	entry      providers.Entry
	credPath   string
	origPathFn func() string
}

// newClaudeTestFixture constructs a Catalog_Entry, a fresh Store, a
// driver, and overrides claudeCredentialPathFn to return credPath.
// Tests write the actual credential file body into credPath
// themselves so each test controls the exact JSON shape.
func newClaudeTestFixture(t *testing.T) *claudeTestFixture {
	t.Helper()

	dir := t.TempDir()
	credPath := filepath.Join(dir, "claude-credentials.json")

	entry := providers.Entry{
		ID:          "claude-cli",
		DisplayName: "Claude CLI",
		BaseURL:     "https://api.anthropic.com",
		HeaderStyle: "anthropic",
		Flow:        "claude_cli_reuse",
		Scopes:      []string{"read"},
	}
	cat := &claudeStubCatalog{id: entry.ID, entry: entry}

	storePath := filepath.Join(dir, "auth-profiles.json")
	store, err := NewStore(storePath, cat)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	// Override the package-level claudeCredentialPathFn so the
	// driver reads our temp fixture rather than the operator's
	// real ~/.claude/.credentials.json. Restore on cleanup so
	// later tests in the same package see the original value.
	orig := claudeCredentialPathFn
	claudeCredentialPathFn = func() string { return credPath }
	t.Cleanup(func() { claudeCredentialPathFn = orig })

	return &claudeTestFixture{
		t:          t,
		driver:     newClaudeReuseDriver(store, nil),
		store:      store,
		entry:      entry,
		credPath:   credPath,
		origPathFn: orig,
	}
}

// writeCredFile persists a CLI-shaped credential JSON body to the
// fixture's temp credPath. The mode mirrors the upstream CLI's
// 0o600 so production fidelity is preserved.
func (f *claudeTestFixture) writeCredFile(body string) {
	f.t.Helper()
	if err := os.WriteFile(f.credPath, []byte(body), 0o600); err != nil {
		f.t.Fatalf("WriteFile %q: %v", f.credPath, err)
	}
}

// ----------------------------------------------------------------------
// TestClaude_ImportFromCLIPath — Requirement 9.1
// ----------------------------------------------------------------------

// TestClaude_ImportFromCLIPath writes a CLI-shaped credential file
// containing access/refresh tokens and an RFC3339 expiry, runs
// Complete, and asserts the persisted profile carries those same
// tokens and a non-zero ExpiresAt.
//
// Validates: Requirement 9.1.
func TestClaude_ImportFromCLIPath(t *testing.T) {
	f := newClaudeTestFixture(t)

	body := `{
		"accessToken": "at",
		"refreshToken": "rt",
		"expiresAt": "2026-12-31T00:00:00Z"
	}`
	f.writeCredFile(body)

	got, err := f.driver.Complete(context.Background(), f.entry, CompleteInput{})
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}

	if got.Provider != f.entry.ID {
		t.Fatalf("Provider = %q, want %q", got.Provider, f.entry.ID)
	}
	if got.Type != OAuth {
		t.Fatalf("Type = %q, want %q", got.Type, OAuth)
	}
	if got.AccessToken != "at" {
		t.Fatalf("AccessToken = %q, want %q", got.AccessToken, "at")
	}
	if got.RefreshToken != "rt" {
		t.Fatalf("RefreshToken = %q, want %q", got.RefreshToken, "rt")
	}
	wantExp := time.Date(2026, 12, 31, 0, 0, 0, 0, time.UTC)
	if !got.ExpiresAt.Equal(wantExp) {
		t.Fatalf("ExpiresAt = %v, want %v", got.ExpiresAt, wantExp)
	}

	// Confirm persistence — the driver returns the post-Put
	// view, but we re-read for paranoia.
	stored, ok, err := f.store.Get(context.Background(), got.Key())
	if err != nil {
		t.Fatalf("store.Get: %v", err)
	}
	if !ok {
		t.Fatalf("profile %q not persisted", got.Key())
	}
	if stored.AccessToken != "at" || stored.RefreshToken != "rt" {
		t.Fatalf("persisted tokens = (%q, %q), want (\"at\", \"rt\")", stored.AccessToken, stored.RefreshToken)
	}
}

// ----------------------------------------------------------------------
// TestClaude_MissingFileReturns404 — Requirement 9.2
// ----------------------------------------------------------------------

// TestClaude_MissingFileReturns404 overrides
// claudeCredentialPathFn to return a path that definitely does
// not exist on disk and asserts Complete returns ErrNotFound. The
// HTTP layer maps ErrNotFound to 404 "claude cli credentials not
// found" per Requirement 9.2.
//
// Validates: Requirement 9.2.
func TestClaude_MissingFileReturns404(t *testing.T) {
	f := newClaudeTestFixture(t)

	// Point at a path inside t.TempDir() that we never create.
	// Using a sub-directory ensures Open returns ENOENT regardless
	// of the parent directory's permissions.
	missing := filepath.Join(filepath.Dir(f.credPath), "missing", "credentials.json")
	claudeCredentialPathFn = func() string { return missing }

	_, err := f.driver.Complete(context.Background(), f.entry, CompleteInput{})
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("Complete: err = %v; want ErrNotFound", err)
	}
}

// ----------------------------------------------------------------------
// TestClaude_DoesNotMutateSource — Requirement 9.3 / Property 19
// ----------------------------------------------------------------------

// TestClaude_DoesNotMutateSource asserts that Complete is read-only
// against the source credential file: SHA-256 + mtime measured
// before the call equal SHA-256 + mtime measured after the call.
// The assertion runs ≥ 100 iterations against randomized credential
// bodies so a regression that mutates the file under specific
// content shapes is caught.
//
// Validates: Requirement 9.3 (Property 19).
func TestClaude_DoesNotMutateSource(t *testing.T) {
	const N = 128 // > 100 per the task brief

	f := newClaudeTestFixture(t)
	rng := rand.New(rand.NewSource(0xC1AC1E_9_3))

	for i := 0; i < N; i++ {
		body := randomCredentialBody(rng, i)
		f.writeCredFile(body)

		// Sleep a hair so the mtime resolution on coarser
		// filesystems (e.g., HFS+'s 1s granularity) doesn't
		// mask a same-second mutation. 5ms is sufficient on
		// modern Linux ext4/xfs/btrfs (nanosecond mtime) and
		// imperceptible to the test wall-clock.
		time.Sleep(5 * time.Millisecond)

		preHash, preMTime := hashAndMTime(t, f.credPath)

		_, err := f.driver.Complete(context.Background(), f.entry, CompleteInput{})
		if err != nil {
			t.Fatalf("iter %d: Complete: %v", i, err)
		}

		postHash, postMTime := hashAndMTime(t, f.credPath)
		if preHash != postHash {
			t.Fatalf("iter %d: SHA-256 changed: pre=%s post=%s", i, preHash, postHash)
		}
		if !preMTime.Equal(postMTime) {
			t.Fatalf("iter %d: mtime changed: pre=%v post=%v", i, preMTime, postMTime)
		}

		// Each iteration's profile lands at the same key
		// (provider:default), so we don't need to clean up
		// between iterations — Put is an upsert.
	}
}

// ----------------------------------------------------------------------
// Helpers
// ----------------------------------------------------------------------

// hashAndMTime returns the SHA-256 digest (hex) and modification
// time of path. Test fatals on any IO error so the assertion sites
// stay focused on the equality check.
func hashAndMTime(t *testing.T, path string) (string, time.Time) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %q: %v", path, err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %q: %v", path, err)
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), fi.ModTime()
}

// randomCredentialBody emits a CLI-shaped credential JSON body with
// randomized access/refresh tokens, expiry, and key shape (camelCase
// vs snake_case) so the property test exercises both decode paths
// the driver supports. The tokens are deterministic given the rng
// seed and iteration index, keeping failures reproducible.
func randomCredentialBody(rng *rand.Rand, iter int) string {
	access := fmt.Sprintf("at-%08x-%d", rng.Uint32(), iter)
	refresh := fmt.Sprintf("rt-%08x-%d", rng.Uint32(), iter)

	// Half the iterations emit RFC3339 expiry; the other half
	// emit epoch milliseconds. Both shapes have shipped in the
	// upstream CLI in the wild (see driver_claude.go's tolerant
	// decoder).
	useRFC := rng.Intn(2) == 0
	// Half the iterations emit camelCase keys, the other half
	// snake_case, to exercise both branches of the tolerant
	// decoder.
	useCamel := rng.Intn(2) == 0

	var atKey, rtKey, expKey, ttKey string
	if useCamel {
		atKey, rtKey, expKey, ttKey = "accessToken", "refreshToken", "expiresAt", "tokenType"
	} else {
		atKey, rtKey, expKey, ttKey = "access_token", "refresh_token", "expires_at", "token_type"
	}

	var expVal string
	if useRFC {
		// 2026-01-01..2027-01-01 window
		t := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC).Add(time.Duration(rng.Intn(365*24)) * time.Hour)
		expVal = `"` + t.Format(time.RFC3339) + `"`
	} else {
		// Epoch milliseconds for some valid future time.
		ms := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC).UnixMilli() + int64(rng.Intn(365*24*3600))*1000
		expVal = fmt.Sprintf("%d", ms)
	}

	return fmt.Sprintf(`{
		"%s": "%s",
		"%s": "%s",
		"%s": %s,
		"%s": "Bearer"
	}`, atKey, access, rtKey, refresh, expKey, expVal, ttKey)
}
