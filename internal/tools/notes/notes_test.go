package notes

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/tools"
)

func TestRegistryNotesAreIsolatedByScanContext(t *testing.T) {
	t.Cleanup(func() {
		CleanupContext("ctx-a")
		CleanupContext("ctx-b")
	})

	regA := tools.NewRegistry()
	regA.SetScanContextID("ctx-a")
	Register(regA)

	regB := tools.NewRegistry()
	regB.SetScanContextID("ctx-b")
	Register(regB)

	if _, err := regA.Execute("add_note", map[string]string{"key": "token", "value": "aaa"}); err != nil {
		t.Fatalf("add note A: %v", err)
	}
	if _, err := regB.Execute("add_note", map[string]string{"key": "token", "value": "bbb"}); err != nil {
		t.Fatalf("add note B: %v", err)
	}

	gotA, err := regA.Execute("read_notes", map[string]string{"key": "token"})
	if err != nil {
		t.Fatalf("read note A: %v", err)
	}
	gotB, err := regB.Execute("read_notes", map[string]string{"key": "token"})
	if err != nil {
		t.Fatalf("read note B: %v", err)
	}

	if gotA.Output != "aaa" || gotB.Output != "bbb" {
		t.Fatalf("context leak: A=%q B=%q", gotA.Output, gotB.Output)
	}
}

func TestValueOnlyEndpointInventoryGetsStableKey(t *testing.T) {
	const ctxID = "notes-value-only-inventory"
	t.Cleanup(func() { CleanupContext(ctxID) })
	reg := tools.NewRegistry()
	reg.SetScanContextID(ctxID)
	Register(reg)
	value := "Discovered endpoints: /login /api/health /public/build"
	if _, err := reg.Execute("add_note", map[string]string{"value": value}); err != nil {
		t.Fatalf("value-only note should be recovered: %v", err)
	}
	if got := GetAllNotesForContext(ctxID)["endpoint_inventory"]; got != value {
		t.Fatalf("endpoint inventory not saved: %q", got)
	}
}

func TestNotesDiskPersistenceIsContextSpecific(t *testing.T) {
	dir := t.TempDir()
	contextID := "persist-ctx"
	t.Cleanup(func() { CleanupContext(contextID) })

	SetPersistPathForContext(contextID, dir)
	if _, err := addNoteForContext(contextID, map[string]string{"key": "endpoint", "value": "/admin"}); err != nil {
		t.Fatalf("add note: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(dir, "notes.json"))
	if err != nil {
		t.Fatalf("read notes.json: %v", err)
	}
	if !strings.Contains(string(data), "/admin") {
		t.Fatalf("notes.json did not contain persisted note: %s", string(data))
	}

	ResetNotesForContext(contextID)
	if count, err := LoadFromDiskForContext(contextID); err != nil || count != 1 {
		t.Fatalf("LoadFromDiskForContext count = %d, want 1", count)
	}
	if got := GetAllNotesForContext(contextID)["endpoint"]; got != "/admin" {
		t.Fatalf("loaded note = %q", got)
	}
}
