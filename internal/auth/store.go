// Package auth — Profile_Store implementation backing the runtime-
// editable credential store at ~/.xalgorix/data/auth-profiles.json.
//
// Store is the in-process owner of the on-disk profile file. It is
// stateless with respect to a snapshot: List/Get re-read the JSON
// file from disk on every call (auth-profiles.json is small and
// updated frequently by token refresh), and Put/Delete acquire an
// exclusive flock for the read-modify-write cycle (Requirement 4.3)
// before flushing through internal/storage.WriteAtomic
// (Requirement 4.4).
//
// Locking model — why a sentinel lockfile:
//
//	The natural approach of flocking auth-profiles.json directly
//	races against storage.WriteAtomic, which renames a temp file
//	over the destination. After a rename the destination's inode
//	has changed, so any flock held by a concurrent writer was on
//	the now-detached inode and excludes nothing from the new file.
//	Sample race:
//
//	  A: open auth-profiles.json   (inode X)
//	  A: flock(X, LOCK_EX)         (held)
//	  A: WriteAtomic               (rename → inode Y at the path)
//	  A: close                     (releases flock on detached X)
//	  B: open auth-profiles.json   (gets inode Y — never locked)
//	  B: flock(Y, LOCK_EX)         (succeeds immediately)
//	  B: writes blow away A's data
//
//	The fix — used here — is to flock a sentinel file
//	"auth-profiles.json.lock" whose inode is stable (never renamed).
//	Every writer flocks the sentinel; the data file rename happens
//	inside that critical section. On Linux flock serializes both
//	across processes AND across file descriptors within the same
//	process, so the sentinel covers both correctness boundaries
//	without an additional sync.Mutex.
//
// Validates: Requirements 4.1, 4.2, 4.3, 4.4, 4.5, 4.6, 4.7, 4.8.
package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"syscall"
	"time"

	"github.com/xalgord/xalgorix/v4/internal/storage"
)

// profileIDRE matches the same shape Catalog_Entry.id uses
// (Requirement 4.2). Re-declared here, rather than imported from
// internal/providers, because providers.idRE is unexported and the
// auth package owns its own validation surface.
var profileIDRE = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)

// flockDeadline caps how long a single read-modify-write blocks on
// the sentinel lock before returning ErrLockTimeout
// (Requirement 4.3). A 5s deadline is plenty for normal contention
// (the in-process TokenSink already coalesces most refresh storms);
// hitting it usually indicates either a stuck other process or a
// deadlock bug.
const flockDeadline = 5 * time.Second

// Store is the runtime-editable profile store.
//
// Field layout matches the design's component sketch exactly so the
// driver registry (task 3.3) and the resolver wiring (task 4.1) can
// rely on the struct shape. The sink field is declared here per the
// design but instantiation belongs to task 3.2 — this task creates
// the field and leaves it nil. WithSink (added by task 3.2) will
// populate it without changing this constructor's signature.
type Store struct {
	path    string
	log     *log.Logger
	catalog CatalogResolver
	sink    *TokenSink
}

// Option configures a Store at construction time. The pattern lets
// future tasks (the sink wiring in 3.2, the registry wiring in
// 5.4) inject dependencies without reshuffling NewStore's
// signature.
type Option func(*Store)

// WithLogger overrides the default *log.Logger used for structured
// log output (corruption warnings, lock-contention diagnostics).
// Tests pass a logger backed by a bytes.Buffer to assert specific
// log lines fire.
func WithLogger(lg *log.Logger) Option {
	return func(s *Store) {
		if lg != nil {
			s.log = lg
		}
	}
}

// NewStore constructs a Store rooted at path. The catalog resolver
// is required: Store.Put consults it on every write to reject
// unknown providers per Requirement 4.8. NewStore does NOT create
// the JSON file; it materializes on the first successful write.
//
// The parent directory is also NOT pre-created here — the first
// flush calls storage.EnsureSecureDir, which mkdir-p's the path
// with mode 0o700. This avoids touching the filesystem at startup
// when the store is never going to be written to.
func NewStore(path string, cat CatalogResolver, opts ...Option) (*Store, error) {
	if path == "" {
		return nil, fmt.Errorf("auth: NewStore: empty path")
	}
	if cat == nil {
		return nil, fmt.Errorf("auth: NewStore: nil CatalogResolver")
	}
	s := &Store{
		path:    path,
		log:     log.Default(),
		catalog: cat,
	}
	for _, opt := range opts {
		if opt != nil {
			opt(s)
		}
	}
	// Token_Sink is owned by the Store: it layers an in-process
	// per-"<provider>:<profileId>" mutex on top of the file flock
	// so concurrent in-process refreshes coalesce before
	// contending for the file lock (Requirements 10.1–10.3).
	// refreshWithSink in driver.go calls store.sink.acquire(key)
	// and relies on this field being non-nil on every Store
	// constructed via NewStore.
	s.sink = newTokenSink()
	return s, nil
}

// List returns every profile sorted by canonical "<provider>:<id>"
// key. Reads the file on every call — there is no in-memory cache
// — so concurrent writers across processes always see a fresh
// snapshot.
//
// A missing or empty file yields an empty slice, never an error,
// so the dashboard can render "no profiles yet" instead of an
// error envelope on a fresh install.
func (s *Store) List(ctx context.Context) ([]Profile, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	profs, err := s.read()
	if err != nil {
		return nil, err
	}
	out := make([]Profile, 0, len(profs))
	for _, p := range profs {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key() < out[j].Key() })
	return out, nil
}

// Get returns the profile stored under key (or zero, false, nil
// when absent). The (Profile, bool, error) signature mirrors
// providers.Service.Get so callers using a CatalogResolver-shaped
// helper can apply the same lookup pattern to both stores.
func (s *Store) Get(ctx context.Context, key string) (Profile, bool, error) {
	if err := ctx.Err(); err != nil {
		return Profile{}, false, err
	}
	profs, err := s.read()
	if err != nil {
		return Profile{}, false, err
	}
	p, ok := profs[key]
	return p, ok, nil
}

// Put inserts-or-updates the supplied Profile. Validation order:
//
//  1. Provider must be non-empty (ErrProviderRequired).
//  2. ProfileID must satisfy profileIDRE (ErrProfileIDInvalid).
//  3. Type must be APIKey or OAuth (ErrProfileTypeInvalid).
//  4. Provider must resolve in the catalog (ErrUnknownProvider per
//     Requirement 4.8). The catalog lookup happens BEFORE we take
//     the file lock so a 400-class request never holds the lock.
//
// Put then takes the exclusive flock on the sentinel, re-reads the
// current on-disk state, overlays the new entry, and flushes via
// storage.WriteAtomic. UpdatedAt is rewritten with the current
// wall clock so the caller can rely on the field reflecting the
// last successful Put.
//
// Orphan-tolerance contract (M2): the catalog lookup at step 4
// happens OUTSIDE the file flock by design. The dashboard's
// "Delete provider" button can race with a concurrent profile Put
// — Service.Delete commits before we re-read the catalog under
// our flock — and that race window is observable as an orphan
// profile referencing a no-longer-extant catalog entry. Read
// paths (List / Get) tolerate orphans by returning them
// unchanged; the resolver (internal/llm/resolver.go) and the
// per-scan picker (internal/web/scan_resolve.go) treat a missing
// catalog entry the same way they treat any other unresolvable
// id — surface as an error to the dashboard and let the operator
// reconcile. We do NOT acquire the catalog's lock at Put time
// because doing so would couple the two stores' write paths
// (introducing a deadlock surface) for a benign edge case the
// resolver already handles defensively.
func (s *Store) Put(ctx context.Context, p Profile) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if p.Provider == "" {
		return ErrProviderRequired
	}
	if !profileIDRE.MatchString(p.ProfileID) {
		return fmt.Errorf("%w: got %q", ErrProfileIDInvalid, p.ProfileID)
	}
	if p.Type != APIKey && p.Type != OAuth {
		return fmt.Errorf("%w: got %q", ErrProfileTypeInvalid, p.Type)
	}

	// Catalog gate (R4.8). Done outside the flock because a 400
	// "unknown provider" response should never block a concurrent
	// legitimate writer.
	if _, ok, err := s.catalog.Get(ctx, p.Provider); err != nil {
		return fmt.Errorf("auth: catalog lookup: %w", err)
	} else if !ok {
		return fmt.Errorf("%w: %q", ErrUnknownProvider, p.Provider)
	}

	return s.withLock(func() error {
		profs, err := s.read()
		if err != nil {
			return err
		}
		p.UpdatedAt = time.Now().UTC()
		profs[p.Key()] = p
		return s.flush(profs)
	})
}

// Delete removes the profile stored under key and returns the
// removed Profile (or ErrProfileNotFound when key is absent). The
// returned Profile lets the HTTP layer render a "deleted X" message
// with full context per Requirement 4.7.
func (s *Store) Delete(ctx context.Context, key string) (Profile, error) {
	if err := ctx.Err(); err != nil {
		return Profile{}, err
	}
	var removed Profile
	err := s.withLock(func() error {
		profs, rerr := s.read()
		if rerr != nil {
			return rerr
		}
		p, ok := profs[key]
		if !ok {
			return fmt.Errorf("%w: %q", ErrProfileNotFound, key)
		}
		removed = p
		delete(profs, key)
		return s.flush(profs)
	})
	if err != nil {
		return Profile{}, err
	}
	return removed, nil
}

// read loads the current profile set from disk. Missing/empty file
// → empty map (no error) so callers don't have to special-case a
// fresh install. A malformed file returns an error rather than
// silently overwriting on the next Put — losing real credentials
// to a parse-then-clobber bug would be far worse than surfacing a
// 503 to the operator.
//
// Profiles with empty Provider or ProfileID in the on-disk file
// are skipped (with a log line) rather than indexed under an
// invalid key, matching how providers.Service handles a blank id.
func (s *Store) read() (map[string]Profile, error) {
	data, err := os.ReadFile(s.path)
	switch {
	case err == nil:
		if len(data) == 0 {
			return map[string]Profile{}, nil
		}
		var profs []Profile
		if jerr := json.Unmarshal(data, &profs); jerr != nil {
			return nil, fmt.Errorf("auth: parse %q: %w", s.path, jerr)
		}
		out := make(map[string]Profile, len(profs))
		for _, p := range profs {
			if p.Provider == "" || p.ProfileID == "" {
				s.log.Printf("auth: skipping profile with empty provider/profileId in %q", s.path)
				continue
			}
			out[p.Key()] = p
		}
		return out, nil
	case errors.Is(err, os.ErrNotExist):
		return map[string]Profile{}, nil
	default:
		return nil, fmt.Errorf("auth: read %q: %w", s.path, err)
	}
}

// flush serializes the supplied profile map deterministically (sort
// by canonical key) and writes it through storage.WriteAtomic.
// Sorting produces byte-identical output for identical logical
// state, which makes diffing on-disk snapshots in tests
// straightforward.
func (s *Store) flush(next map[string]Profile) error {
	dir := filepath.Dir(s.path)
	if err := storage.EnsureSecureDir(dir); err != nil {
		return fmt.Errorf("auth: ensure dir: %w", err)
	}
	profs := make([]Profile, 0, len(next))
	for _, p := range next {
		profs = append(profs, p)
	}
	sort.Slice(profs, func(i, j int) bool { return profs[i].Key() < profs[j].Key() })
	data, err := json.MarshalIndent(profs, "", "  ")
	if err != nil {
		return fmt.Errorf("auth: marshal: %w", err)
	}
	if err := storage.WriteAtomic(s.path, data); err != nil {
		return fmt.Errorf("auth: write atomic: %w", err)
	}
	return nil
}

// withLock acquires an exclusive flock on the sentinel file
// adjacent to the profile JSON ("<path>.lock"), runs fn while
// holding the lock, and releases on return.
//
// Why a sentinel rather than the data file: see the package-level
// comment. In short, storage.WriteAtomic renames over the data
// file on every flush, which detaches whatever inode the lock was
// taken on. The sentinel's inode is stable across renames, so a
// flock on it actually excludes concurrent writers.
//
// Validates: Requirement 4.3 (5s deadline → ErrLockTimeout).
func (s *Store) withLock(fn func() error) error {
	dir := filepath.Dir(s.path)
	if err := storage.EnsureSecureDir(dir); err != nil {
		return fmt.Errorf("auth: ensure dir: %w", err)
	}
	lockPath := s.path + ".lock"

	// O_RDWR|O_CREATE so we can re-use the same sentinel on
	// every call. Mode 0o600 mirrors the data file mode
	// (Requirement 4.1) — the sentinel itself never holds
	// credentials but the operator threat model treats every
	// file in ~/.xalgorix/data as private to the dashboard
	// owner.
	f, err := os.OpenFile(lockPath, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return fmt.Errorf("auth: open lock %q: %w", lockPath, err)
	}
	defer f.Close()

	if err := acquireExclusiveFlock(int(f.Fd()), flockDeadline); err != nil {
		return err
	}
	// Explicit unlock is defensive — closing the fd also releases
	// — but it makes the critical section visible in stack traces
	// and limits the lock-held window to the precise scope of fn.
	defer func() { _ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN) }()

	return fn()
}

// acquireExclusiveFlock issues a non-blocking LOCK_EX in a poll
// loop, sleeping with exponential backoff (capped at 100ms) until
// either the lock is acquired or deadline elapses. On timeout it
// returns ErrLockTimeout so the HTTP layer can surface 503 Service
// Unavailable; on any other syscall failure it wraps the underlying
// errno so log readers see the cause.
//
// Validates: Requirement 4.3.
func acquireExclusiveFlock(fd int, deadline time.Duration) error {
	end := time.Now().Add(deadline)
	backoff := 5 * time.Millisecond
	for {
		err := syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			return nil
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) {
			return fmt.Errorf("auth: flock: %w", err)
		}
		if !time.Now().Before(end) {
			return ErrLockTimeout
		}
		time.Sleep(backoff)
		if backoff < 100*time.Millisecond {
			backoff *= 2
		}
	}
}
