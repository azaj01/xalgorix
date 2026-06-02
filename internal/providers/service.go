// Package providers — read-only Service wrapper around Builtin().
//
// v4.4.22 dropped the runtime-editable JSON catalog. Service is now
// a thin façade over Builtin() so the rest of the codebase
// (internal/auth.Store, internal/llm.NewCompositeResolver, the web
// handlers) keeps the same Read-API surface — List, Get, IsEmpty —
// without needing to know the catalog is compiled-in.
package providers

import (
	"context"
	"sort"
)

// Service exposes the compiled-in catalog through the same
// (List, Get, IsEmpty) surface the v4.4.21 file-backed catalog
// offered. There is no mutation surface.
//
// A nil *Service is treated as an empty catalog by every method —
// the zero value is safe to call against.
type Service struct {
	entries []Entry
	index   map[string]Entry
}

// NewService constructs the read-only Service backed by Builtin().
// The constructor takes no path: the catalog ships compiled-in.
func NewService() *Service {
	src := Builtin()
	idx := make(map[string]Entry, len(src))
	for _, e := range src {
		idx[e.ID] = e
	}
	return &Service{entries: src, index: idx}
}

// IsEmpty reports whether the catalog has zero entries. Always
// false for the compiled-in Service; callers retain the helper so
// existing branches that gate "legacy fallback when catalog empty"
// keep compiling unchanged.
func (s *Service) IsEmpty() bool {
	if s == nil {
		return true
	}
	return len(s.entries) == 0
}

// List returns every catalog entry in alphabetical-by-ID order,
// matching the Builtin() guarantee. The returned slice is a copy
// so callers cannot mutate the underlying snapshot.
func (s *Service) List(ctx context.Context) ([]Entry, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if s == nil {
		return []Entry{}, nil
	}
	out := make([]Entry, len(s.entries))
	copy(out, s.entries)
	sort.SliceStable(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// Get returns the entry for id (case-insensitive trim) plus a
// (entry, found, error) tuple matching the historical signature.
// The error is reserved for ctx cancellation so future async
// callers continue to honor request lifetimes.
func (s *Service) Get(ctx context.Context, id string) (Entry, bool, error) {
	if err := ctx.Err(); err != nil {
		return Entry{}, false, err
	}
	if s == nil {
		return Entry{}, false, nil
	}
	if e, ok := s.index[id]; ok {
		return e, true, nil
	}
	// Fall back through LookupBuiltin to honor case-insensitive
	// matching for callers that pass operator input directly.
	if e, ok := LookupBuiltin(id); ok {
		return e, true, nil
	}
	return Entry{}, false, nil
}
