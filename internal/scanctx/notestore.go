package scanctx

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// NoteStore provides per-session note storage with optional disk persistence,
// replacing the global store in notes.go.
type NoteStore struct {
	mu          sync.RWMutex
	store       map[string]string
	persistPath string // path to notes.json (empty = no persistence)

	// writeMu serializes writeFile calls so two concurrent Set() callers
	// cannot interleave snapshots on disk. We hold this *only* across the
	// disk write — the data lock (mu) is released first to avoid blocking
	// readers behind I/O.
	writeMu sync.Mutex
}

// NewNoteStore creates an empty note store.
func NewNoteStore() *NoteStore {
	return &NoteStore{
		store: make(map[string]string),
	}
}

// SetPersistPath configures disk persistence for notes.
//
// Path_Policy note (Requirement 8.3): NoteStore lives in package scanctx,
// which sandbox imports. To avoid an import cycle we cannot call
// sandbox.Default().CheckResolve from here. The persist path is constructed
// as filepath.Join(dir, "notes.json") — there is no user-supplied path
// component, so the boundary is preserved by construction provided callers
// hand us a directory inside the Allow_List. In production the only caller
// is internal/tools/notes (which routes its own writes through
// sandbox.CheckResolve); the directory passed to NoteStore is the per-scan
// ScanDir, which is an Allow_List descendant by construction.
func (ns *NoteStore) SetPersistPath(dir string) {
	ns.mu.Lock()
	defer ns.mu.Unlock()
	if dir != "" {
		ns.persistPath = filepath.Join(dir, "notes.json")
	} else {
		ns.persistPath = ""
	}
}

// Set adds or updates a note.
// The disk write is performed outside the lock to prevent blocking readers.
func (ns *NoteStore) Set(key, value string) {
	ns.mu.Lock()
	ns.store[key] = value
	data, path := ns.marshalSnapshot()
	ns.mu.Unlock()

	// Write to disk outside the lock — non-blocking for concurrent readers
	ns.writeFile(data, path)
}

// Get returns a note by key, or ("", false) if not found.
func (ns *NoteStore) Get(key string) (string, bool) {
	ns.mu.RLock()
	defer ns.mu.RUnlock()
	v, ok := ns.store[key]
	return v, ok
}

// GetAll returns a copy of all notes.
func (ns *NoteStore) GetAll() map[string]string {
	ns.mu.RLock()
	defer ns.mu.RUnlock()
	result := make(map[string]string, len(ns.store))
	for k, v := range ns.store {
		result[k] = v
	}
	return result
}

// Count returns the number of stored notes.
func (ns *NoteStore) Count() int {
	ns.mu.RLock()
	defer ns.mu.RUnlock()
	return len(ns.store)
}

// Reset clears all notes.
func (ns *NoteStore) Reset() {
	ns.mu.Lock()
	ns.store = make(map[string]string)
	ns.mu.Unlock()
}

// LoadFromDisk loads notes from the persist path.
func (ns *NoteStore) LoadFromDisk() int {
	ns.mu.Lock()
	defer ns.mu.Unlock()

	if ns.persistPath == "" {
		return 0
	}

	data, err := os.ReadFile(ns.persistPath)
	if err != nil {
		return 0
	}

	loaded := make(map[string]string)
	if err := json.Unmarshal(data, &loaded); err != nil {
		log.Printf("[notestore] Warning: failed to parse %s: %v", ns.persistPath, err)
		return 0
	}

	count := 0
	for k, v := range loaded {
		if _, exists := ns.store[k]; !exists {
			ns.store[k] = v
			count++
		}
	}

	if count > 0 {
		log.Printf("[notestore] Loaded %d notes from: %s", count, ns.persistPath)
	}
	return count
}

// FormatForContext returns a compact summary suitable for LLM context injection.
func (ns *NoteStore) FormatForContext() string {
	ns.mu.RLock()
	defer ns.mu.RUnlock()

	if len(ns.store) == 0 {
		return ""
	}

	var b strings.Builder
	b.WriteString("=== YOUR SAVED NOTES (from add_note) ===\n")
	for k, v := range ns.store {
		if len(v) > 500 {
			v = v[:500] + "... (truncated)"
		}
		b.WriteString(fmt.Sprintf("• %s: %s\n", k, v))
	}
	b.WriteString("=== END NOTES ===")
	return b.String()
}

// marshalSnapshot serializes the current store. Must be called with mu held.
// Returns the serialized data and the persist path. If persistPath is empty,
// returns nil data (meaning no write is needed).
func (ns *NoteStore) marshalSnapshot() ([]byte, string) {
	if ns.persistPath == "" {
		return nil, ""
	}
	data, err := json.MarshalIndent(ns.store, "", "  ")
	if err != nil {
		log.Printf("[notestore] Warning: failed to marshal notes: %v", err)
		return nil, ""
	}
	return data, ns.persistPath
}

// writeFile persists serialized data to disk. Safe to call without holding
// the data lock (mu); writeMu serializes concurrent writers so two Set()s
// cannot race on the file.
//
// Path_Policy note (Requirement 8.3): safe by construction. The path
// originates from SetPersistPath which scopes it to dir + "notes.json"; in
// production dir is the per-scan ScanDir, an Allow_List descendant. We
// cannot call sandbox.Default().CheckResolve here because scanctx is
// imported by sandbox. User-supplied paths into the notes feature flow
// through internal/tools/notes, which calls CheckResolve directly.
func (ns *NoteStore) writeFile(data []byte, path string) {
	if data == nil || path == "" {
		return
	}
	ns.writeMu.Lock()
	defer ns.writeMu.Unlock()
	if err := os.WriteFile(path, data, 0600); err != nil {
		log.Printf("[notestore] Warning: failed to save notes to %s: %v", path, err)
	}
}
