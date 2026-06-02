// Package notes provides the notes tool for agent memory with disk persistence.
package notes

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/xalgord/xalgorix/v4/internal/sandbox"
	"github.com/xalgord/xalgorix/v4/internal/scanctx"
	"github.com/xalgord/xalgorix/v4/internal/tools"
)

// ── Per-instance note stores ──
var (
	noteStores   = make(map[string]*noteStore)
	noteStoresMu sync.RWMutex
)

type noteStore struct {
	mu sync.RWMutex
	// contextID is the owning ScanContext.ID for this store. Captured at
	// creation time so writeFile can look up the active ScanContext for
	// Path_Policy resolution (sc.ScanDir-relative roots).
	contextID   string
	store       map[string]string
	persistPath string
}

func getNoteStoreByID(id string) *noteStore {
	noteStoresMu.RLock()
	s, ok := noteStores[id]
	noteStoresMu.RUnlock()
	if ok {
		return s
	}

	noteStoresMu.Lock()
	defer noteStoresMu.Unlock()
	if s, ok := noteStores[id]; ok {
		return s
	}
	s = &noteStore{contextID: id, store: make(map[string]string)}
	noteStores[id] = s
	return s
}

// getNoteStore returns the note store for the default (CLI) scan context.
func getNoteStore() *noteStore {
	return getNoteStoreByID(scanctx.Default().ID)
}

func getNoteStoreForContext(contextID string) *noteStore {
	noteStoresMu.RLock()
	s, ok := noteStores[contextID]
	noteStoresMu.RUnlock()
	if ok {
		return s
	}
	noteStoresMu.Lock()
	defer noteStoresMu.Unlock()
	if s, ok := noteStores[contextID]; ok {
		return s
	}
	s = &noteStore{contextID: contextID, store: make(map[string]string)}
	noteStores[contextID] = s
	return s
}

// SetPersistPath configures the directory where notes.json will be saved.
func SetPersistPath(dir string) {
	s := getNoteStore()
	s.mu.Lock()
	defer s.mu.Unlock()
	if dir != "" {
		s.persistPath = filepath.Join(dir, "notes.json")
	} else {
		s.persistPath = ""
	}
}

// ResetNotes clears all notes for the active scan context.
func ResetNotes() {
	s := getNoteStore()
	s.mu.Lock()
	s.store = make(map[string]string)
	s.mu.Unlock()
}

// LoadFromDisk loads notes from the persist path if it exists.
func LoadFromDisk() int {
	s := getNoteStore()
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.persistPath == "" {
		return 0
	}

	data, err := os.ReadFile(s.persistPath)
	if err != nil {
		return 0
	}

	loaded := make(map[string]string)
	if err := json.Unmarshal(data, &loaded); err != nil {
		log.Printf("[notes] Warning: failed to parse %s: %v", s.persistPath, err)
		return 0
	}

	count := 0
	for k, v := range loaded {
		if _, exists := s.store[k]; !exists {
			s.store[k] = v
			count++
		}
	}

	if count > 0 {
		log.Printf("[notes] Loaded %d notes from disk: %s", count, s.persistPath)
	}
	return count
}

// marshalSnapshot serializes the current store. Must be called with s.mu held.
// Returns the serialized data and the persist path. If persistPath is empty,
// returns nil data (meaning no write is needed).
func (s *noteStore) marshalSnapshot() ([]byte, string) {
	if s.persistPath == "" {
		return nil, ""
	}
	data, err := json.MarshalIndent(s.store, "", "  ")
	if err != nil {
		log.Printf("[notes] Warning: failed to marshal notes: %v", err)
		return nil, ""
	}
	return data, s.persistPath
}

// writeFile persists serialized data to disk. Safe to call without holding s.mu.
//
// Every persistence write flows through sandbox.Default().CheckResolve so a
// misconfigured persistPath cannot escape the Allow_List (Requirement 8.3).
// The lookup uses the owning ScanContext's roots when available, falling
// back to the process Workspace_Root via sandbox.Resolve.
func (s *noteStore) writeFile(data []byte, path string) {
	if data == nil || path == "" {
		return
	}
	canonical, err := sandbox.Default().CheckResolve(scanctx.Get(s.contextID), "notes", path)
	if err != nil {
		log.Printf("[notes] Warning: refusing to save notes to %s: %v", path, err)
		return
	}
	if err := os.WriteFile(canonical, data, 0600); err != nil {
		log.Printf("[notes] Warning: failed to save notes to %s: %v", canonical, err)
	}
}

// Register adds note tools to the registry.
func Register(r *tools.Registry) {
	r.Register(&tools.Tool{
		Name:        "add_note",
		Description: "Add a note to persistent memory. Use this to track: discovered endpoints, parameters, tech stack, CSRF tokens, session cookies, exploit chain state, intermediate findings, and anything needed across multiple iterations. Notes persist for the entire scan AND survive context pruning. Use structured keys like 'csrf_token', 'admin_endpoint', 'sqli_confirmed', 'angular_version'.",
		Parameters: []tools.Parameter{
			{Name: "key", Description: "Unique key for the note (e.g., 'csrf_token', 'admin_endpoint', 'angular_version', 'exploit_chain_step1')", Required: true},
			{Name: "value", Description: "Note content", Required: true},
		},
		Execute: func(args map[string]string) (tools.Result, error) {
			return addNoteForContext(r.GetScanContextID(), args)
		},
	})

	r.Register(&tools.Tool{
		Name:        "read_notes",
		Description: "Read all notes or a specific note from memory.",
		Parameters: []tools.Parameter{
			{Name: "key", Description: "Key to read (omit for all notes)", Required: false},
		},
		Execute: func(args map[string]string) (tools.Result, error) {
			return readNotesForContext(r.GetScanContextID(), args)
		},
	})
}

//lint:ignore U1000 kept as a package-level compatibility wrapper for callers in this package.
func addNote(args map[string]string) (tools.Result, error) {
	return addNoteForContext(scanctx.Default().ID, args)
}

func addNoteForContext(contextID string, args map[string]string) (tools.Result, error) {
	key := args["key"]
	value := args["value"]

	if contextID == "" {
		contextID = scanctx.Default().ID
	}
	s := getNoteStoreForContext(contextID)
	s.mu.Lock()
	s.store[key] = value
	data, path := s.marshalSnapshot()
	s.mu.Unlock()

	// Write to disk outside the lock — non-blocking for concurrent readers
	s.writeFile(data, path)

	return tools.Result{Output: fmt.Sprintf("Note saved: %s", key)}, nil
}

//lint:ignore U1000 kept as a package-level compatibility wrapper for callers in this package.
func readNotes(args map[string]string) (tools.Result, error) {
	return readNotesForContext(scanctx.Default().ID, args)
}

func readNotesForContext(contextID string, args map[string]string) (tools.Result, error) {
	key := args["key"]

	if contextID == "" {
		contextID = scanctx.Default().ID
	}
	s := getNoteStoreForContext(contextID)
	s.mu.RLock()
	defer s.mu.RUnlock()

	if key != "" {
		v, ok := s.store[key]
		if !ok {
			return tools.Result{Output: fmt.Sprintf("No note found with key: %s", key)}, nil
		}
		return tools.Result{Output: v}, nil
	}

	if len(s.store) == 0 {
		return tools.Result{Output: "(no notes yet)"}, nil
	}

	var b strings.Builder
	for k, v := range s.store {
		b.WriteString(fmt.Sprintf("📝 %s:\n%s\n\n", k, v))
	}
	return tools.Result{Output: b.String()}, nil
}

// GetAllNotes returns all notes as a map for the active scan context.
func GetAllNotes() map[string]string {
	s := getNoteStore()
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make(map[string]string, len(s.store))
	for k, v := range s.store {
		result[k] = v
	}
	return result
}

// FormatForContext returns a compact summary of all notes for the active scan context.
func FormatForContext() string {
	s := getNoteStore()
	return formatStore(s)
}

// FormatForContextID returns a compact summary of notes for a specific scan context ID.
func FormatForContextID(contextID string) string {
	s := getNoteStoreForContext(contextID)
	return formatStore(s)
}

func formatStore(s *noteStore) string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if len(s.store) == 0 {
		return ""
	}

	var b strings.Builder
	b.WriteString("=== YOUR SAVED NOTES (from add_note) ===\n")
	for k, v := range s.store {
		if len(v) > 500 {
			v = v[:500] + "... (truncated)"
		}
		b.WriteString(fmt.Sprintf("• %s: %s\n", k, v))
	}
	b.WriteString("=== END NOTES ===")
	return b.String()
}

// SetPersistPathForContext configures disk persistence for a specific context.
func SetPersistPathForContext(contextID, dir string) {
	s := getNoteStoreForContext(contextID)
	s.mu.Lock()
	defer s.mu.Unlock()
	if dir != "" {
		s.persistPath = filepath.Join(dir, "notes.json")
	} else {
		s.persistPath = ""
	}
}

// ResetNotesForContext clears all notes for a specific context.
func ResetNotesForContext(contextID string) {
	s := getNoteStoreForContext(contextID)
	s.mu.Lock()
	s.store = make(map[string]string)
	s.mu.Unlock()
}

// LoadFromDiskForContext loads notes from disk for a specific context.
func LoadFromDiskForContext(contextID string) int {
	s := getNoteStoreForContext(contextID)
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.persistPath == "" {
		return 0
	}

	data, err := os.ReadFile(s.persistPath)
	if err != nil {
		return 0
	}

	loaded := make(map[string]string)
	if err := json.Unmarshal(data, &loaded); err != nil {
		log.Printf("[notes] Warning: failed to parse %s: %v", s.persistPath, err)
		return 0
	}

	count := 0
	for k, v := range loaded {
		if _, exists := s.store[k]; !exists {
			s.store[k] = v
			count++
		}
	}

	if count > 0 {
		log.Printf("[notes] Loaded %d notes from: %s (context=%s)", count, s.persistPath, contextID)
	}
	return count
}

// GetAllNotesForContext returns all notes for a specific context.
func GetAllNotesForContext(contextID string) map[string]string {
	s := getNoteStoreForContext(contextID)
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make(map[string]string, len(s.store))
	for k, v := range s.store {
		result[k] = v
	}
	return result
}

// CleanupContext removes the note store for a deactivated context.
func CleanupContext(contextID string) {
	noteStoresMu.Lock()
	defer noteStoresMu.Unlock()
	delete(noteStores, contextID)
}
