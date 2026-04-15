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

	"github.com/xalgord/xalgorix/v4/internal/tools"
)

var (
	mu          sync.RWMutex
	store       = make(map[string]string) // key → value
	persistPath string                    // path to notes.json on disk (empty = no persistence)
)

// SetPersistPath configures the directory where notes.json will be saved.
// Call this before starting a scan to enable disk-backed persistence.
func SetPersistPath(dir string) {
	mu.Lock()
	defer mu.Unlock()
	if dir != "" {
		persistPath = filepath.Join(dir, "notes.json")
	} else {
		persistPath = ""
	}
}

// ResetNotes clears all notes (called at scan start).
func ResetNotes() {
	mu.Lock()
	store = make(map[string]string)
	mu.Unlock()
}

// LoadFromDisk loads notes from the persist path if it exists.
// Used for resuming interrupted scans.
func LoadFromDisk() int {
	mu.Lock()
	defer mu.Unlock()

	if persistPath == "" {
		return 0
	}

	data, err := os.ReadFile(persistPath)
	if err != nil {
		return 0 // file doesn't exist yet — normal for new scans
	}

	loaded := make(map[string]string)
	if err := json.Unmarshal(data, &loaded); err != nil {
		log.Printf("[notes] Warning: failed to parse %s: %v", persistPath, err)
		return 0
	}

	// Merge loaded notes into store (don't overwrite existing keys from current scan)
	count := 0
	for k, v := range loaded {
		if _, exists := store[k]; !exists {
			store[k] = v
			count++
		}
	}

	if count > 0 {
		log.Printf("[notes] Loaded %d notes from disk: %s", count, persistPath)
	}
	return count
}

// saveToDisk persists the current store to disk. Must be called with mu held.
func saveToDisk() {
	if persistPath == "" {
		return
	}

	data, err := json.MarshalIndent(store, "", "  ")
	if err != nil {
		log.Printf("[notes] Warning: failed to marshal notes: %v", err)
		return
	}

	if err := os.WriteFile(persistPath, data, 0644); err != nil {
		log.Printf("[notes] Warning: failed to save notes to %s: %v", persistPath, err)
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
		Execute: addNote,
	})

	r.Register(&tools.Tool{
		Name:        "read_notes",
		Description: "Read all notes or a specific note from memory.",
		Parameters: []tools.Parameter{
			{Name: "key", Description: "Key to read (omit for all notes)", Required: false},
		},
		Execute: readNotes,
	})
}

func addNote(args map[string]string) (tools.Result, error) {
	key := args["key"]
	value := args["value"]

	mu.Lock()
	store[key] = value
	saveToDisk()
	mu.Unlock()

	return tools.Result{Output: fmt.Sprintf("Note saved: %s", key)}, nil
}

func readNotes(args map[string]string) (tools.Result, error) {
	key := args["key"]

	mu.RLock()
	defer mu.RUnlock()

	if key != "" {
		v, ok := store[key]
		if !ok {
			return tools.Result{Output: fmt.Sprintf("No note found with key: %s", key)}, nil
		}
		return tools.Result{Output: v}, nil
	}

	if len(store) == 0 {
		return tools.Result{Output: "(no notes yet)"}, nil
	}

	var b strings.Builder
	for k, v := range store {
		b.WriteString(fmt.Sprintf("📝 %s:\n%s\n\n", k, v))
	}
	return tools.Result{Output: b.String()}, nil
}

// GetAllNotes returns all notes as a map (for server-side access).
func GetAllNotes() map[string]string {
	mu.RLock()
	defer mu.RUnlock()
	result := make(map[string]string, len(store))
	for k, v := range store {
		result[k] = v
	}
	return result
}

// FormatForContext returns a compact summary of all notes, suitable for
// injection into the LLM context window (e.g., after pruning).
// Returns empty string if no notes exist.
func FormatForContext() string {
	mu.RLock()
	defer mu.RUnlock()

	if len(store) == 0 {
		return ""
	}

	var b strings.Builder
	b.WriteString("=== YOUR SAVED NOTES (from add_note) ===\n")
	for k, v := range store {
		// Truncate very long values to avoid bloating the context
		if len(v) > 500 {
			v = v[:500] + "... (truncated)"
		}
		b.WriteString(fmt.Sprintf("• %s: %s\n", k, v))
	}
	b.WriteString("=== END NOTES ===")
	return b.String()
}
