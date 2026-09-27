package scanctx

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
)

// toolArchiveDir is the per-scan directory holding archived raw tool outputs.
const toolArchiveDir = "tool-outputs"

// archiveIDPattern validates retrieval ids (to_<seq>).
var archiveIDPattern = regexp.MustCompile(`^to_[0-9]{1,12}$`)

// ToolArchive persists the complete, untruncated raw output of tool results so
// the conversation can replace aged tool-result messages with tiny retrieval
// stubs without destroying any information: every archived byte stays
// retrievable by the agent via the read_tool_output tool (byte-identical).
//
// This is the backing store for bounded working context: the agent keeps a
// verbatim recent window and archives everything older. Files live under
// <ScanDir>/tool-outputs/ so they survive restarts.
type ToolArchive struct {
	mu   sync.Mutex
	dir  string
	next int
}

// NewToolArchive creates an archive rooted at <scanDir>/tool-outputs.
// A nil-safe empty archive is returned when scanDir is empty.
//
// Existing records are immutable across reopen: the sequence counter starts
// past the highest archived id. A reopened archive previously restarted the
// counter at zero and Archive's temp+rename silently replaced an existing
// record with different content under the same retrieval id — deterministic
// evidence loss whenever the archive outlives one process (resume/restart).
func NewToolArchive(scanDir string) *ToolArchive {
	if scanDir == "" {
		return &ToolArchive{}
	}
	a := &ToolArchive{dir: filepath.Join(scanDir, toolArchiveDir)}
	if entries, err := os.ReadDir(a.dir); err == nil {
		for _, e := range entries {
			if m := archiveIDPattern.FindStringSubmatch(e.Name()); m != nil {
				if n, err := strconv.Atoi(m[1]); err == nil && n > a.next {
					a.next = n
				}
			}
		}
	}
	return a
}

// enabled reports whether the archive has a backing directory.
func (a *ToolArchive) enabled() bool {
	return a != nil && a.dir != ""
}

// Archive stores content and returns its retrieval id (to_<seq>).
// Content below minBytes is not stored and returns "" (the caller keeps the
// message verbatim instead — small outputs are cheap to carry in-context).
func (a *ToolArchive) Archive(toolName, content string, minBytes int) string {
	if !a.enabled() || len(content) < minBytes {
		return ""
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.next++
	id := fmt.Sprintf("to_%06d", a.next)
	if err := os.MkdirAll(a.dir, 0o700); err != nil {
		return ""
	}
	// Belt-and-braces immutability: never overwrite an existing record, even if
	// the reopen scan raced a concurrent writer. Advance until the id is free.
	for target := filepath.Join(a.dir, id); ; {
		if _, err := os.Stat(target); os.IsNotExist(err) {
			break
		}
		a.next++
		id = fmt.Sprintf("to_%06d", a.next)
		target = filepath.Join(a.dir, id)
	}
	// The file body keeps the tool name as a header so a bare retrieval is
	// self-describing; the id alone never reveals target data.
	body := "tool: " + toolName + "\n\n" + content
	target := filepath.Join(a.dir, id)
	tmp := target + ".tmp"
	if err := os.WriteFile(tmp, []byte(body), 0o600); err != nil {
		return ""
	}
	if err := os.Rename(tmp, target); err != nil {
		_ = os.Remove(tmp)
		return ""
	}
	return id
}

// Get returns the archived content (tool header stripped) for an id.
func (a *ToolArchive) Get(id string) (string, bool) {
	if !a.enabled() {
		return "", false
	}
	id = strings.TrimSpace(id)
	if !archiveIDPattern.MatchString(id) {
		return "", false
	}
	// archiveIDPattern already restricts ids to "to_<digits>", which excludes
	// path separators and traversal sequences; the explicit check is belt-and-braces.
	if strings.ContainsAny(id, "/\\.") {
		return "", false
	}
	data, err := os.ReadFile(filepath.Join(a.dir, id))
	if err != nil {
		return "", false
	}
	s := string(data)
	// Strip the self-describing tool header written by Archive.
	if idx := strings.Index(s, "\n\n"); idx >= 0 && strings.HasPrefix(s, "tool: ") {
		s = s[idx+2:]
	}
	return s, true
}

// Count reports how many outputs have been archived.
func (a *ToolArchive) Count() int {
	if !a.enabled() {
		return 0
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.next
}
