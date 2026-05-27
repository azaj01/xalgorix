// Package providers — Service implementation backing the runtime-
// editable LLM provider catalog at ~/.xalgorix/data/providers.json.
//
// Service is the in-process owner of the on-disk catalog. It loads
// the JSON file at construction, holds the parsed snapshot under an
// RWMutex for fast reads, and routes every mutation through the
// shared internal/storage.WriteAtomic primitive (temp-file +
// fsync + rename-over-destination, mode 0o600) so a partially
// written catalog is never observable on disk (Requirement 1.4).
//
// Design notes encoded here:
//
//   - A missing providers.json is treated as an empty catalog
//     WITHOUT creating the file (Requirement 1.3). The file only
//     comes into existence on the first successful write — typically
//     the first Create call from the dashboard.
//
//   - A malformed providers.json flips Service.bad = true. While
//     bad is set, List returns [] (Requirement 1.7) and every write
//     returns ErrCatalogCorrupt so the operator can repair or remove
//     the file before mutations resume. The HTTP layer (Wave E task
//     5.1) maps ErrCatalogCorrupt to 503 Service Unavailable.
//
//   - All four CRUD methods take a context.Context for parity with
//     the HTTP handlers and the CatalogResolver interface consumed
//     by internal/auth (Wave C task 3.1). The context is reserved
//     for future cancellation hooks; today it is honored only at
//     the entry of each method.
//
//   - Validation policy is split between this file and types.go:
//     types.validateEntry covers field presence + headerStyle
//     allowlist, and Service.Create / Service.Update enforce idRE
//     here so the regex check happens against the same input the
//     allowlist check sees.
package providers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"sync"

	"github.com/xalgord/xalgorix/v4/internal/storage"
)

// Service is the runtime-editable catalog backed by a single JSON
// file on disk. Field layout matches the design's component sketch
// exactly so future tasks (the openclaw merge in 2.3, the resolver
// wiring in 4.1) can rely on the same struct shape.
//
// Validates: Requirements 1.1, 1.2, 1.3, 1.4, 1.7, 2.1, 2.2.
type Service struct {
	path string             // absolute path to providers.json
	mu   sync.RWMutex       // guards snap and bad
	snap map[string]Entry   // id → entry, in-memory snapshot
	bad  bool               // true when the file failed JSON validation
	log  *log.Logger        // structured-log destination; never nil
	http *http.Client       // injected for ImportOpenclaw (Wave B task 2.3)
}

// Option configures a Service at construction. The pattern lets
// later tasks (the openclaw importer in 2.3, the web server wiring
// in 5.4) inject a logger or a stubbed http.Client without
// changing NewService's signature.
type Option func(*Service)

// WithLogger overrides the default *log.Logger used for structured
// log output (currently just the corrupt-file warning). Tests pass
// a logger backed by a bytes.Buffer to assert the warning fires.
func WithLogger(lg *log.Logger) Option {
	return func(s *Service) {
		if lg != nil {
			s.log = lg
		}
	}
}

// WithHTTPClient overrides the default *http.Client used by the
// openclaw importer (Wave B task 2.3). The constructor uses
// http.DefaultClient when no override is supplied so tests can swap
// in a stub transport without touching production wiring.
func WithHTTPClient(c *http.Client) Option {
	return func(s *Service) {
		if c != nil {
			s.http = c
		}
	}
}

// NewService loads the catalog from path. Behavioral contract:
//
//   - A missing file (os.IsNotExist) yields an empty in-memory
//     snapshot and Service.bad = false. The file is NOT created
//     (Requirement 1.3); it materializes on the first successful
//     write.
//
//   - A file present-but-empty also yields an empty snapshot. This
//     mirrors how Profile_Store handles a freshly truncated file.
//
//   - A file present-but-malformed flips Service.bad = true and
//     emits one structured log line. List returns [] while bad is
//     set, and all writes return ErrCatalogCorrupt (Requirement 1.7).
//     NewService still returns a non-nil Service with no error in
//     this case so the dashboard can render the corrupt-file warning
//     and offer the repair UX rather than failing to start.
//
//   - Any other read error (permissions, IO) is returned as-is so
//     the operator can see the underlying cause at startup.
func NewService(path string, opts ...Option) (*Service, error) {
	if path == "" {
		return nil, fmt.Errorf("providers: NewService: empty path")
	}
	s := &Service{
		path: path,
		snap: map[string]Entry{},
		log:  log.Default(),
		http: http.DefaultClient,
	}
	for _, opt := range opts {
		if opt != nil {
			opt(s)
		}
	}

	data, err := os.ReadFile(path)
	switch {
	case err == nil:
		// Empty file is treated as an empty catalog. This avoids
		// flagging a freshly created (but not yet written) file as
		// corrupt during the write window between create and rename.
		if len(data) == 0 {
			return s, nil
		}
		var entries []Entry
		if jerr := json.Unmarshal(data, &entries); jerr != nil {
			// Structured log line per Requirement 1.7 — the operator
			// must be able to find this in the dashboard log stream.
			s.log.Printf("providers: catalog file %q failed JSON validation: %v; refusing writes until repaired", path, jerr)
			s.bad = true
			return s, nil
		}
		for _, e := range entries {
			if e.ID == "" {
				// A blank id in the on-disk file is structurally
				// invalid — surface this the same way as a JSON
				// parse failure so the operator notices and the
				// service refuses writes.
				s.log.Printf("providers: catalog entry with empty id in %q; refusing writes until repaired", path)
				s.bad = true
				s.snap = map[string]Entry{}
				return s, nil
			}
			s.snap[e.ID] = e
		}
		return s, nil
	case errors.Is(err, os.ErrNotExist):
		// Requirement 1.3: missing file → empty catalog, no file creation.
		return s, nil
	default:
		return nil, fmt.Errorf("providers: read %q: %w", path, err)
	}
}

// IsEmpty reports whether the catalog currently has zero entries.
// This is the gate the LLM client uses to decide Legacy_Fallback
// (Requirements 2.1, 2.2). When bad is set IsEmpty also reports
// true because the in-memory snapshot is empty in that state.
func (s *Service) IsEmpty() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.snap) == 0
}

// List returns every catalog entry sorted by id. While Service.bad
// is set List returns an empty slice (Requirement 1.7) so callers
// keep functioning even when the file is corrupt.
func (s *Service) List(ctx context.Context) ([]Entry, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.bad {
		return []Entry{}, nil
	}
	out := make([]Entry, 0, len(s.snap))
	for _, e := range s.snap {
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// Get returns the entry for id (or zero, false, nil when absent).
// Like List, Get returns the empty/false tuple while bad is set so
// read paths in internal/auth and internal/llm keep working even if
// the file is corrupt.
//
// The (Entry, bool, error) signature matches the CatalogResolver
// interface declared in internal/auth (Wave C task 3.1) so
// *Service satisfies CatalogResolver without an adapter.
func (s *Service) Get(ctx context.Context, id string) (Entry, bool, error) {
	if err := ctx.Err(); err != nil {
		return Entry{}, false, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.bad {
		return Entry{}, false, nil
	}
	e, ok := s.snap[id]
	if !ok {
		return Entry{}, false, nil
	}
	return e, true, nil
}

// Create inserts a new entry. Returns ErrIDInvalid when id fails
// idRE, ErrIDExists when an entry with the same id is already
// present, validation errors from validateEntry on bad shape, and
// ErrCatalogCorrupt when the on-disk file failed JSON validation at
// startup (Requirement 1.7).
func (s *Service) Create(ctx context.Context, e Entry) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !idRE.MatchString(e.ID) {
		return fmt.Errorf("%w: %q", ErrIDInvalid, e.ID)
	}
	if err := validateEntry(e); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.bad {
		return ErrCatalogCorrupt
	}
	if _, exists := s.snap[e.ID]; exists {
		return fmt.Errorf("%w: %q", ErrIDExists, e.ID)
	}

	next := cloneSnap(s.snap)
	next[e.ID] = e
	if err := s.flushLocked(next); err != nil {
		return err
	}
	s.snap = next
	return nil
}

// Update replaces the entry stored under id. The id from the URL
// path is the source of truth; if e.ID is non-empty it must match
// id (ErrIDMismatch otherwise) so callers cannot rename an entry
// through Update. Returns ErrNotFound when id is absent.
func (s *Service) Update(ctx context.Context, id string, e Entry) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !idRE.MatchString(id) {
		return fmt.Errorf("%w: %q", ErrIDInvalid, id)
	}
	if e.ID == "" {
		// Allow callers (especially HTTP) to omit the id from the
		// body since the canonical id lives in the URL path.
		e.ID = id
	}
	if e.ID != id {
		return ErrIDMismatch
	}
	if err := validateEntry(e); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.bad {
		return ErrCatalogCorrupt
	}
	if _, exists := s.snap[id]; !exists {
		return fmt.Errorf("%w: %q", ErrNotFound, id)
	}

	next := cloneSnap(s.snap)
	next[id] = e
	if err := s.flushLocked(next); err != nil {
		return err
	}
	s.snap = next
	return nil
}

// Delete removes the entry stored under id. Returns ErrNotFound
// when id is absent and ErrCatalogCorrupt when the file failed JSON
// validation at startup.
func (s *Service) Delete(ctx context.Context, id string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !idRE.MatchString(id) {
		return fmt.Errorf("%w: %q", ErrIDInvalid, id)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.bad {
		return ErrCatalogCorrupt
	}
	if _, exists := s.snap[id]; !exists {
		return fmt.Errorf("%w: %q", ErrNotFound, id)
	}

	next := cloneSnap(s.snap)
	delete(next, id)
	if err := s.flushLocked(next); err != nil {
		return err
	}
	s.snap = next
	return nil
}

// flushLocked serializes snap deterministically and writes it
// through internal/storage.WriteAtomic. The caller must hold s.mu
// for write. The on-disk format is a JSON array sorted by id so
// repeated writes of the same logical state produce byte-identical
// files (helpful for diffing and test assertions).
//
// Validates: Requirements 1.1, 1.4.
func (s *Service) flushLocked(next map[string]Entry) error {
	dir := filepath.Dir(s.path)
	if err := storage.EnsureSecureDir(dir); err != nil {
		return fmt.Errorf("providers: ensure dir: %w", err)
	}
	entries := make([]Entry, 0, len(next))
	for _, e := range next {
		entries = append(entries, e)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].ID < entries[j].ID })
	data, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		return fmt.Errorf("providers: marshal: %w", err)
	}
	if err := storage.WriteAtomic(s.path, data); err != nil {
		return fmt.Errorf("providers: write atomic: %w", err)
	}
	return nil
}

// cloneSnap returns a shallow copy of m. Used by every mutation so
// the on-disk write is built against a candidate map that can be
// discarded if the write fails — leaving the in-memory snapshot
// untouched on error.
func cloneSnap(m map[string]Entry) map[string]Entry {
	out := make(map[string]Entry, len(m)+1)
	for k, v := range m {
		out[k] = v
	}
	return out
}
