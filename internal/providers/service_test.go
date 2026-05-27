// Package providers — unit + property-based tests for Catalog_Service.
//
// These tests cover Properties 1, 2, 3, 4, 6, 7 from the design's
// "Correctness Properties" section, plus the file-mode and on-disk
// shape invariants. Every property-style test runs ≥ 100 iterations
// against a deterministic math/rand/v2 seed so failures are
// reproducible without changing the seed.
//
// Validates: Requirements 1.1, 1.2, 1.3, 1.4, 1.5, 1.6, 1.7, 1.8,
//            3.1, 3.2, 3.4
package providers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	mathrand "math/rand/v2"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

// entriesEqual compares two Entry values structurally. The Entry
// struct contains []string slices (Models, Scopes) so the language's
// == operator is not available; reflect.DeepEqual is the standard
// stand-in for "structurally identical, including slice elements".
func entriesEqual(a, b Entry) bool { return reflect.DeepEqual(a, b) }

// ----- helpers ---------------------------------------------------------------

// newRand returns a deterministic *math/rand/v2 PRNG. The seed is
// fixed so a failing iteration index always reproduces with the same
// generated input — there is no time-based seeding to chase.
func newRand() *mathrand.Rand {
	return mathrand.New(mathrand.NewPCG(0xC0FFEE_15_C0DE, 0xB16B00B5_BADF00D))
}

// randID returns a string that satisfies idRE: starts with [a-z0-9],
// followed by 0..63 chars from [a-z0-9_-].
func randID(r *mathrand.Rand) string {
	const head = "abcdefghijklmnopqrstuvwxyz0123456789"
	const tail = "abcdefghijklmnopqrstuvwxyz0123456789_-"
	n := 1 + r.IntN(20) // 1..20 chars to leave room for suffixes
	out := make([]byte, n)
	out[0] = head[r.IntN(len(head))]
	for i := 1; i < n; i++ {
		out[i] = tail[r.IntN(len(tail))]
	}
	return string(out)
}

// randHeaderStyle returns one of the three allowlisted header styles.
func randHeaderStyle(r *mathrand.Rand) string {
	v := []string{"openai", "anthropic", "gemini"}
	return v[r.IntN(len(v))]
}

// randEntry builds a structurally-valid Entry with random id and
// header style. The id is short enough to allow callers to append a
// disambiguating suffix without breaking the 64-char regex bound.
func randEntry(r *mathrand.Rand) Entry {
	return Entry{
		ID:          randID(r),
		DisplayName: fmt.Sprintf("Display %d", r.IntN(1_000_000)),
		BaseURL:     fmt.Sprintf("https://example%d.com/v1", r.IntN(1000)),
		HeaderStyle: randHeaderStyle(r),
	}
}

// newServiceInTempDir constructs a Service rooted at <tempdir>/data
// so the parent directory is created by EnsureSecureDir (mode 0o700)
// rather than inheriting whatever t.TempDir() set up.
func newServiceInTempDir(t *testing.T, opts ...Option) (*Service, string) {
	t.Helper()
	tmp := t.TempDir()
	dir := filepath.Join(tmp, "data")
	path := filepath.Join(dir, "providers.json")
	svc, err := NewService(path, opts...)
	if err != nil {
		t.Fatalf("NewService(%q): %v", path, err)
	}
	return svc, path
}

// ----- TestService_FileModes -------------------------------------------------

// TestService_FileModes asserts that after a successful Create the
// providers.json file is mode 0o600 and its parent directory is mode
// 0o700, matching the on-disk security contract from R1.1.
//
// Validates: Requirement 1.1
func TestService_FileModes(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX file modes do not apply on Windows")
	}
	svc, path := newServiceInTempDir(t)
	dir := filepath.Dir(path)

	if err := svc.Create(context.Background(), Entry{
		ID:          "openai",
		DisplayName: "OpenAI",
		BaseURL:     "https://api.openai.com/v1",
		HeaderStyle: "openai",
	}); err != nil {
		t.Fatalf("Create: %v", err)
	}

	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %q: %v", path, err)
	}
	if got := fi.Mode().Perm(); got != 0o600 {
		t.Errorf("providers.json mode = %#o, want 0o600", got)
	}

	di, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("stat %q: %v", dir, err)
	}
	if got := di.Mode().Perm(); got != 0o700 {
		t.Errorf("data dir mode = %#o, want 0o700", got)
	}
}

// ----- TestService_CRUD_RoundTrip --------------------------------------------

// TestService_CRUD_RoundTrip is the randomized table-driven test for
// Property 1: for any valid Entry e, Create(e); Get(e.id) == e and
// Create(e); Update(e.id, e'); Get(e.id) == e' and finally
// Create(e); Delete(e.id); Get(e.id) == not found.
//
// Validates: Requirements 1.2, 1.5, 1.6 (Property 1)
func TestService_CRUD_RoundTrip(t *testing.T) {
	const iterations = 128 // ≥ 100 per the task brief
	r := newRand()
	ctx := context.Background()
	svc, _ := newServiceInTempDir(t)

	used := make(map[string]struct{}, iterations)
	for i := 0; i < iterations; i++ {
		e := randEntry(r)
		// Disambiguate so consecutive iterations don't collide on id.
		// "%s-%d" keeps the result inside the 64-char regex bound
		// because randID returns ≤ 20 chars and the suffix is ≤ 5.
		e.ID = fmt.Sprintf("%s-%d", e.ID, i)
		if !idRE.MatchString(e.ID) {
			t.Fatalf("iter %d: synthesized id %q does not match idRE", i, e.ID)
		}
		if _, dup := used[e.ID]; dup {
			t.Fatalf("iter %d: duplicate id %q", i, e.ID)
		}
		used[e.ID] = struct{}{}

		// Create
		if err := svc.Create(ctx, e); err != nil {
			t.Fatalf("iter %d: Create(%+v): %v", i, e, err)
		}
		got, ok, err := svc.Get(ctx, e.ID)
		if err != nil || !ok {
			t.Fatalf("iter %d: Get after Create ok=%v err=%v", i, ok, err)
		}
		if !entriesEqual(got, e) {
			t.Fatalf("iter %d: Get after Create = %+v, want %+v", i, got, e)
		}

		// Update with a different DisplayName + HeaderStyle.
		ePrime := e
		ePrime.DisplayName = e.DisplayName + " (updated)"
		ePrime.HeaderStyle = randHeaderStyle(r)
		if err := svc.Update(ctx, e.ID, ePrime); err != nil {
			t.Fatalf("iter %d: Update: %v", i, err)
		}
		got, ok, err = svc.Get(ctx, e.ID)
		if err != nil || !ok {
			t.Fatalf("iter %d: Get after Update ok=%v err=%v", i, ok, err)
		}
		if !entriesEqual(got, ePrime) {
			t.Fatalf("iter %d: Get after Update = %+v, want %+v", i, got, ePrime)
		}

		// Delete
		if err := svc.Delete(ctx, e.ID); err != nil {
			t.Fatalf("iter %d: Delete: %v", i, err)
		}
		_, ok, err = svc.Get(ctx, e.ID)
		if err != nil {
			t.Fatalf("iter %d: Get after Delete err=%v", i, err)
		}
		if ok {
			t.Fatalf("iter %d: Get after Delete ok=true; want false", i)
		}
	}
}

// ----- TestService_RejectsBadID ---------------------------------------------

// TestService_RejectsBadID asserts Service.Create rejects every id
// that does not match idRE with ErrIDInvalid. The fixed table covers
// known-bad shapes (empty, leading dash/underscore, uppercase, dot,
// space, over-length); the randomized leg generates 100 additional
// strings whose shapes do not match the regex.
//
// Validates: Requirement 1.2 (Property 1, negative side)
func TestService_RejectsBadID(t *testing.T) {
	svc, _ := newServiceInTempDir(t)
	ctx := context.Background()

	fixed := []string{
		"",
		"-foo",
		"_foo",
		"FOO",
		"with space",
		"with.dot",
		"Foo",
		"a/b",
		strings.Repeat("a", 65), // exceeds 64-char bound
	}
	for _, id := range fixed {
		e := Entry{ID: id, DisplayName: "X", BaseURL: "https://x.example", HeaderStyle: "openai"}
		err := svc.Create(ctx, e)
		if !errors.Is(err, ErrIDInvalid) {
			t.Errorf("fixed id %q: Create err = %v, want ErrIDInvalid", id, err)
		}
	}

	r := newRand()
	const iterations = 128
	for i := 0; i < iterations; i++ {
		// Generate a random ASCII string and reject if it accidentally
		// matches idRE — the test is specifically about the rejection
		// path, so we filter those out and re-spin.
		var s string
		for try := 0; try < 32; try++ {
			n := 1 + r.IntN(70)
			buf := make([]byte, n)
			for k := 0; k < n; k++ {
				// printable ASCII range, biased toward chars that
				// will fail the regex (dots, slashes, uppercase).
				buf[k] = byte(33 + r.IntN(94))
			}
			s = string(buf)
			if !idRE.MatchString(s) {
				break
			}
		}
		if idRE.MatchString(s) {
			// Couldn't synthesize an invalid string in 32 tries —
			// extremely unlikely but skip the iteration rather than
			// flake the test.
			continue
		}
		e := Entry{ID: s, DisplayName: "X", BaseURL: "https://x.example", HeaderStyle: "openai"}
		err := svc.Create(ctx, e)
		if !errors.Is(err, ErrIDInvalid) {
			t.Errorf("random id %q (iter %d): Create err = %v, want ErrIDInvalid", s, i, err)
		}
	}
}

// ----- TestService_RejectsBadHeaderStyle ------------------------------------

// TestService_RejectsBadHeaderStyle asserts Service.Create rejects
// every headerStyle outside the allowlist. Empty maps to
// ErrHeaderStyleRequired; non-empty-but-invalid maps to
// ErrHeaderStyleInvalid. Property 3.
//
// Validates: Requirement 1.6 (Property 3)
func TestService_RejectsBadHeaderStyle(t *testing.T) {
	svc, _ := newServiceInTempDir(t)
	ctx := context.Background()

	// Empty maps to ErrHeaderStyleRequired — a separate sentinel from
	// ErrHeaderStyleInvalid because the messaging differs.
	emptyEntry := Entry{ID: "x", DisplayName: "X", BaseURL: "https://x.example", HeaderStyle: ""}
	if err := svc.Create(ctx, emptyEntry); !errors.Is(err, ErrHeaderStyleRequired) {
		t.Errorf("empty headerStyle: Create err = %v, want ErrHeaderStyleRequired", err)
	}

	fixedBad := []string{
		"GPT", "openai-style", "claude", "google-vertex", "x",
		"bedrock", "azure", "OpenAI", "GEMINI",
	}
	for i, h := range fixedBad {
		id := fmt.Sprintf("fx%d", i)
		e := Entry{ID: id, DisplayName: "X", BaseURL: "https://x.example", HeaderStyle: h}
		err := svc.Create(ctx, e)
		if !errors.Is(err, ErrHeaderStyleInvalid) {
			t.Errorf("fixed headerStyle %q: Create err = %v, want ErrHeaderStyleInvalid", h, err)
		}
	}

	r := newRand()
	const iterations = 128
	for i := 0; i < iterations; i++ {
		// Generate a random non-empty string and skip if it lands on
		// one of the three allowlisted values.
		n := 1 + r.IntN(15)
		buf := make([]byte, n)
		for k := 0; k < n; k++ {
			buf[k] = byte('a' + r.IntN(26))
		}
		h := string(buf)
		switch h {
		case "openai", "anthropic", "gemini":
			continue
		}
		id := fmt.Sprintf("rd%d", i)
		e := Entry{ID: id, DisplayName: "X", BaseURL: "https://x.example", HeaderStyle: h}
		err := svc.Create(ctx, e)
		if !errors.Is(err, ErrHeaderStyleInvalid) {
			t.Errorf("random headerStyle %q (iter %d): Create err = %v, want ErrHeaderStyleInvalid", h, i, err)
		}
	}
}

// ----- TestService_EmptyOnMissingFile ----------------------------------------

// TestService_EmptyOnMissingFile asserts NewService against a path
// whose file does not exist returns an empty in-memory snapshot
// without erroring and without creating the file (R1.3).
//
// Validates: Requirement 1.3
func TestService_EmptyOnMissingFile(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "nope", "providers.json")

	svc, err := NewService(path)
	if err != nil {
		t.Fatalf("NewService on missing file: %v", err)
	}
	out, err := svc.List(context.Background())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(out) != 0 {
		t.Errorf("List returned %d entries on missing file; want 0", len(out))
	}
	if !svc.IsEmpty() {
		t.Error("IsEmpty = false on missing file; want true")
	}
	if _, err := os.Stat(path); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("file %q created during NewService; stat err = %v", path, err)
	}
}

// ----- TestService_AtomicWrites_FaultInjection ------------------------------

// TestService_AtomicWrites_FaultInjection asserts that a write
// failure during the temp-file phase does not corrupt the destination.
// We seed a known-good catalog, make the parent directory read-only
// so the next OpenFile-of-temp-file syscall fails with EACCES, attempt
// a Create that must error, then verify the on-disk file is byte-
// identical to before the failed call. Property 2.
//
// Validates: Requirement 1.4 (Property 2)
func TestService_AtomicWrites_FaultInjection(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("chmod-based fault injection not portable to Windows")
	}
	if os.Geteuid() == 0 {
		t.Skip("fault injection requires non-root user (chmod 0o500 has no effect for root)")
	}

	svc, path := newServiceInTempDir(t)
	dir := filepath.Dir(path)
	ctx := context.Background()

	// Establish a known-good catalog as the on-disk baseline.
	good := Entry{
		ID:          "openai",
		DisplayName: "OpenAI",
		BaseURL:     "https://api.openai.com/v1",
		HeaderStyle: "openai",
	}
	if err := svc.Create(ctx, good); err != nil {
		t.Fatalf("seed Create: %v", err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read seed file: %v", err)
	}

	// Inject the fault: clear write+execute on the parent directory
	// so the temp-file OpenFile syscall in storage.WriteAtomic fails.
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatalf("chmod dir 0o500: %v", err)
	}
	t.Cleanup(func() {
		// Restore so t.TempDir cleanup can remove the tree.
		_ = os.Chmod(dir, 0o700)
	})

	bad := Entry{
		ID:          "groq",
		DisplayName: "Groq",
		BaseURL:     "https://api.groq.com",
		HeaderStyle: "openai",
	}
	if err := svc.Create(ctx, bad); err == nil {
		t.Fatal("Create with read-only parent should have failed")
	}

	// Restore directory permissions for the post-state read.
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatalf("restore dir 0o700: %v", err)
	}

	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read post-fault file: %v", err)
	}
	if !bytes.Equal(before, after) {
		t.Errorf("on-disk catalog mutated by failed write\nbefore: %s\nafter:  %s", before, after)
	}

	// The atomic-write contract says the temp file is removed on any
	// pre-rename failure; assert no orphaned ".tmp.*" siblings.
	tmpMatches, err := filepath.Glob(filepath.Join(dir, "*.tmp.*"))
	if err != nil {
		t.Fatalf("glob temp files: %v", err)
	}
	if len(tmpMatches) > 0 {
		t.Errorf("orphaned temp files after failed write: %v", tmpMatches)
	}

	// In-memory snapshot must also be intact — the design promises
	// the candidate map is discarded on flush failure.
	got, err := svc.List(ctx)
	if err != nil {
		t.Fatalf("post-fault List: %v", err)
	}
	if len(got) != 1 || got[0].ID != "openai" {
		t.Errorf("in-memory snapshot mutated despite write failure: %+v", got)
	}
}

// ----- TestService_CorruptFile_TreatsAsEmptyAndRefusesWrites -----------------

// TestService_CorruptFile_TreatsAsEmptyAndRefusesWrites asserts that
// a malformed providers.json puts the service into the bad state:
// List returns the empty slice and every mutation returns
// ErrCatalogCorrupt. Property 4. The randomized leg samples 100
// distinct corrupt byte sequences to widen coverage.
//
// Validates: Requirement 1.7 (Property 4)
func TestService_CorruptFile_TreatsAsEmptyAndRefusesWrites(t *testing.T) {
	corruptBlobs := [][]byte{
		[]byte("not json"),
		[]byte("{"),
		[]byte("[}"),
		[]byte(`{"version":1,"entries":[}]`), // syntactically broken
		[]byte(`[{"id":"openai","headerStyle":"openai"`),
		[]byte("\x00\x01\x02 garbage"),
		// An array containing an entry with empty id — the loader
		// flips bad=true on this case too.
		[]byte(`[{"id":"","displayName":"x","baseURL":"u","headerStyle":"openai"}]`),
	}

	r := newRand()
	for i := 0; i < 100; i++ {
		// Random bytes are extremely unlikely to be valid JSON.
		n := 4 + r.IntN(64)
		buf := make([]byte, n)
		for k := 0; k < n; k++ {
			buf[k] = byte(r.IntN(256))
		}
		// Skip the unlikely case that the random buffer happens to
		// be valid JSON for []Entry — re-validate by attempting
		// the same Unmarshal the loader will run.
		var probe []Entry
		if json.Unmarshal(buf, &probe) == nil {
			continue
		}
		corruptBlobs = append(corruptBlobs, buf)
	}

	ctx := context.Background()
	for idx, blob := range corruptBlobs {
		t.Run(fmt.Sprintf("blob_%d", idx), func(t *testing.T) {
			tmp := t.TempDir()
			dir := filepath.Join(tmp, "data")
			if err := os.MkdirAll(dir, 0o700); err != nil {
				t.Fatalf("mkdir: %v", err)
			}
			path := filepath.Join(dir, "providers.json")
			if err := os.WriteFile(path, blob, 0o600); err != nil {
				t.Fatalf("seed corrupt file: %v", err)
			}

			svc, err := NewService(path)
			if err != nil {
				t.Fatalf("NewService on corrupt file: %v", err)
			}

			// IsEmpty should report true while bad is set so callers
			// (LLM client) keep working.
			if !svc.IsEmpty() {
				t.Error("IsEmpty = false on corrupt; want true")
			}
			out, err := svc.List(ctx)
			if err != nil {
				t.Errorf("List on corrupt: %v", err)
			}
			if len(out) != 0 {
				t.Errorf("List on corrupt returned %d entries; want 0", len(out))
			}

			valid := Entry{
				ID:          "openai",
				DisplayName: "OpenAI",
				BaseURL:     "https://api.openai.com/v1",
				HeaderStyle: "openai",
			}
			if err := svc.Create(ctx, valid); !errors.Is(err, ErrCatalogCorrupt) {
				t.Errorf("Create on corrupt: err = %v, want ErrCatalogCorrupt", err)
			}
			if err := svc.Update(ctx, "openai", valid); !errors.Is(err, ErrCatalogCorrupt) {
				t.Errorf("Update on corrupt: err = %v, want ErrCatalogCorrupt", err)
			}
			if err := svc.Delete(ctx, "openai"); !errors.Is(err, ErrCatalogCorrupt) {
				t.Errorf("Delete on corrupt: err = %v, want ErrCatalogCorrupt", err)
			}

			// Get returns (zero, false, nil) while bad is set so
			// read paths in internal/auth keep working.
			_, ok, err := svc.Get(ctx, "openai")
			if err != nil {
				t.Errorf("Get on corrupt: err = %v, want nil", err)
			}
			if ok {
				t.Error("Get on corrupt returned ok=true; want false")
			}
		})
	}
}

// ----- TestService_NoBakedInDefaults -----------------------------------------

// TestService_NoBakedInDefaults asserts that NewService against a
// nonexistent file returns an empty catalog AND does NOT create the
// file. This is the binary-side guarantee from R1.8: no providers
// are baked into the compiled artifact, so a clean install lands
// on an empty catalog without any latent on-disk state.
//
// Validates: Requirement 1.8
func TestService_NoBakedInDefaults(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "fresh", "providers.json")

	svc, err := NewService(path)
	if err != nil {
		t.Fatalf("NewService(fresh path): %v", err)
	}

	out, err := svc.List(context.Background())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(out) != 0 {
		t.Errorf("fresh install lists %d entries; want 0 (no baked defaults)", len(out))
	}
	if !svc.IsEmpty() {
		t.Error("IsEmpty = false on fresh install; want true")
	}
	if _, err := os.Stat(path); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("NewService created the catalog file at %q; want absent (stat err = %v)", path, err)
	}
	// The parent directory must also remain absent — the constructor
	// is read-only against the on-disk filesystem when the file is
	// missing.
	if _, err := os.Stat(filepath.Dir(path)); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("NewService created parent dir %q; want absent (stat err = %v)", filepath.Dir(path), err)
	}
}

// ----- TestImportOpenclaw_MergeAndSkipExisting -------------------------------

// TestImportOpenclaw_MergeAndSkipExisting is the randomized merge
// property: for any local catalog C and any openclaw document D,
// after ImportOpenclaw the resulting catalog R satisfies
//   for every id i:  (i ∈ C ⇒ R[i] = C[i]) ∧ (i ∈ D\C ⇒ R[i] = D[i])
// and the per-id outcome list reports "skipped/id_exists" exactly
// for the intersection and "imported" exactly for the new entries.
// Property 6.
//
// Validates: Requirements 3.1, 3.2 (Property 6)
func TestImportOpenclaw_MergeAndSkipExisting(t *testing.T) {
	const iterations = 110 // ≥ 100 per the brief

	// One TLS server reused across iterations; each iteration swaps
	// the response body via the closure-captured upstreamBody slice.
	var upstreamBody []byte
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(upstreamBody)
	}))
	defer ts.Close()
	httpClient := ts.Client()

	r := newRand()
	ctx := context.Background()

	for i := 0; i < iterations; i++ {
		// Fresh service per iteration so the local catalog state is
		// isolated and the property-test failure index points at a
		// reproducible per-iteration scenario.
		tmp := t.TempDir()
		path := filepath.Join(tmp, "data", "providers.json")
		svc, err := NewService(path, WithHTTPClient(httpClient))
		if err != nil {
			t.Fatalf("iter %d: NewService: %v", i, err)
		}

		// Pre-populate local catalog with 0..4 entries.
		nLocal := r.IntN(5)
		localEntries := make(map[string]Entry, nLocal)
		for j := 0; j < nLocal; j++ {
			e := randEntry(r)
			e.ID = fmt.Sprintf("loc%d-%d", i, j)
			if err := svc.Create(ctx, e); err != nil {
				t.Fatalf("iter %d: seed Create: %v", i, err)
			}
			localEntries[e.ID] = e
		}

		// Build the upstream document: a mix of overlapping (with
		// local) and unique ids. We track expected outcomes per id.
		nUpstream := r.IntN(6) // 0..5
		upstream := make([]Entry, 0, nUpstream)
		seen := make(map[string]struct{}, nUpstream)
		expected := make(map[string]string, nUpstream) // id → action
		// Snapshot local ids for collision picking.
		localIDList := make([]string, 0, len(localEntries))
		for id := range localEntries {
			localIDList = append(localIDList, id)
		}

		for j := 0; j < nUpstream; j++ {
			e := randEntry(r)
			// 50% chance to collide with an existing local id when
			// the local set is non-empty — covers Property 6's
			// id-collision branch.
			if len(localIDList) > 0 && r.IntN(2) == 0 {
				e.ID = localIDList[r.IntN(len(localIDList))]
			} else {
				e.ID = fmt.Sprintf("up%d-%d", i, j)
			}
			// Dedup within the upstream document itself.
			if _, dup := seen[e.ID]; dup {
				continue
			}
			seen[e.ID] = struct{}{}
			upstream = append(upstream, e)

			if _, exists := localEntries[e.ID]; exists {
				expected[e.ID] = "skipped"
			} else {
				expected[e.ID] = "imported"
			}
		}

		body, err := json.Marshal(upstream)
		if err != nil {
			t.Fatalf("iter %d: marshal upstream: %v", i, err)
		}
		upstreamBody = body

		result, err := svc.ImportOpenclaw(ctx, ts.URL)
		if err != nil {
			t.Fatalf("iter %d: ImportOpenclaw: %v", i, err)
		}

		// Outcome cardinality — one outcome per upstream id we sent.
		if len(result.Outcomes) != len(upstream) {
			t.Errorf("iter %d: outcomes len = %d, want %d", i, len(result.Outcomes), len(upstream))
		}
		for _, oc := range result.Outcomes {
			want, ok := expected[oc.ID]
			if !ok {
				t.Errorf("iter %d: unexpected outcome id %q", i, oc.ID)
				continue
			}
			if oc.Action != want {
				t.Errorf("iter %d: id %q action = %q, want %q", i, oc.ID, oc.Action, want)
			}
			if want == "skipped" && oc.Reason != "id_exists" {
				t.Errorf("iter %d: id %q skipped reason = %q, want id_exists", i, oc.ID, oc.Reason)
			}
			if want == "imported" && oc.Reason != "" {
				t.Errorf("iter %d: id %q imported reason = %q, want empty", i, oc.ID, oc.Reason)
			}
		}

		// In-memory invariant: local entries unchanged, new upstream
		// entries present with their upstream values.
		listed, err := svc.List(ctx)
		if err != nil {
			t.Fatalf("iter %d: List after import: %v", i, err)
		}
		got := make(map[string]Entry, len(listed))
		for _, e := range listed {
			got[e.ID] = e
		}
		for id, e := range localEntries {
			if !entriesEqual(got[id], e) {
				t.Errorf("iter %d: local id %q mutated by import: got %+v want %+v", i, id, got[id], e)
			}
		}
		for _, ue := range upstream {
			if _, wasLocal := localEntries[ue.ID]; wasLocal {
				continue
			}
			if !entriesEqual(got[ue.ID], ue) {
				t.Errorf("iter %d: upstream id %q not imported: got %+v want %+v", i, ue.ID, got[ue.ID], ue)
			}
		}
	}
}

// ----- TestImportOpenclaw_UpstreamErrorPreservesLocal ------------------------

// TestImportOpenclaw_UpstreamErrorPreservesLocal asserts that for any
// non-2xx upstream status, the on-disk catalog is byte-identical
// before and after the call and the returned error is ErrUpstream
// carrying the upstream status. Property 7.
//
// Validates: Requirement 3.4 (Property 7)
func TestImportOpenclaw_UpstreamErrorPreservesLocal(t *testing.T) {
	// Small set of representative non-2xx statuses. Property 7
	// quantifies over s ∈ [300, 599]; we sample a deterministic
	// subset that covers each class boundary.
	statuses := []int{300, 301, 400, 401, 403, 404, 408, 422, 500, 502, 503, 504, 599}

	for _, status := range statuses {
		status := status
		t.Run(fmt.Sprintf("status_%d", status), func(t *testing.T) {
			ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(status)
				_, _ = w.Write([]byte(fmt.Sprintf(`{"error":"status %d"}`, status)))
			}))
			defer ts.Close()

			svc, path := newServiceInTempDir(t, WithHTTPClient(ts.Client()))
			ctx := context.Background()

			// Seed the local catalog with one known entry so we have
			// a concrete on-disk byte string to compare against.
			seed := Entry{
				ID:          "openai",
				DisplayName: "OpenAI",
				BaseURL:     "https://api.openai.com/v1",
				HeaderStyle: "openai",
			}
			if err := svc.Create(ctx, seed); err != nil {
				t.Fatalf("seed Create: %v", err)
			}
			before, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read pre-import: %v", err)
			}

			_, err = svc.ImportOpenclaw(ctx, ts.URL)
			if err == nil {
				t.Fatal("ImportOpenclaw on upstream error returned nil err")
			}
			var ue ErrUpstream
			if !errors.As(err, &ue) {
				t.Fatalf("ImportOpenclaw err = %v (%T), want ErrUpstream", err, err)
			}
			if ue.StatusCode != status {
				t.Errorf("ErrUpstream.StatusCode = %d, want %d", ue.StatusCode, status)
			}
			if ue.Body == "" {
				t.Error("ErrUpstream.Body empty; want upstream body to be preserved")
			}

			after, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read post-import: %v", err)
			}
			if !bytes.Equal(before, after) {
				t.Errorf("on-disk catalog modified by failed import (status %d)\nbefore: %s\nafter:  %s", status, before, after)
			}

			// The in-memory snapshot must also be intact.
			got, err := svc.List(ctx)
			if err != nil {
				t.Fatalf("List post-import: %v", err)
			}
			if len(got) != 1 || !entriesEqual(got[0], seed) {
				t.Errorf("in-memory snapshot mutated despite upstream error: %+v", got)
			}
		})
	}
}
