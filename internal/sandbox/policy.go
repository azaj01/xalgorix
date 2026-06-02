package sandbox

import (
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/xalgord/xalgorix/v4/internal/config"
	"github.com/xalgord/xalgorix/v4/internal/safe"
	"github.com/xalgord/xalgorix/v4/internal/scanctx"
)

// Policy is the immutable Allow_List boundary check used by every
// Filesystem_Tool. Construct it once via Default() (process-global lazy
// singleton) for normal callers; tests inject their own roots via New.
//
// The zero value is not usable — always go through New or Default.
//
// Two boundary semantics are exposed:
//
//   - CheckResolve enforces the Allow_List for WRITES (R5.x / R8.x).
//     Writes must land inside cfg.Workspace, cfg.HomeDir, or /tmp.
//   - CheckRead enforces only the deny-list for READS. Reads succeed
//     anywhere on the filesystem unless the canonical path falls
//     under a deny-list root (~/.ssh, ~/.aws, /etc/shadow, etc.).
//     Tools that consume system wordlists, payload directories, and
//     other shared assets call CheckRead so the agent can find them
//     without having to copy them under the workspace.
type Policy struct {
	// roots holds canonical absolute prefixes used for write checks.
	// Each entry is the result of filepath.Abs + filepath.Clean, with
	// empty/duplicate entries dropped, sorted longest-first so the
	// prefix match is deterministic when one root is nested inside
	// another (e.g. /tmp/xalgorix vs /tmp).
	roots []string

	// readDeny holds canonical absolute prefixes that REVOKE the
	// default-allow read policy. Empty/duplicate entries are dropped
	// at construction time. Reads are otherwise permitted everywhere
	// the OS will read (so wordlists in /usr/share/seclists work).
	readDeny []string
}

// New constructs a Policy from the supplied Allow_List roots. Each
// root is canonicalized via filepath.Abs + filepath.Clean. Empty
// entries and duplicates (after canonicalization) are dropped, and
// the resulting slice is sorted by length descending so deeper roots
// match before their parents.
//
// New never touches the filesystem; missing roots are accepted and
// will simply never match. Use Default() in production code.
//
// The deny-list (passed via NewWithReadDeny / Default) is left empty
// here, which means CheckRead allows reads anywhere. Tests that want
// the default deny-list behavior should call NewWithReadDeny.
func New(roots ...string) *Policy {
	return NewWithReadDeny(roots, nil)
}

// NewWithReadDeny constructs a Policy with explicit write roots and
// read deny-list. Both slices are canonicalized + deduplicated +
// sorted longest-first. See New for the write-roots semantics; see
// CheckRead for the deny-list semantics.
func NewWithReadDeny(roots, readDeny []string) *Policy {
	return &Policy{
		roots:    canonicalizeRootList(roots),
		readDeny: canonicalizeRootList(readDeny),
	}
}

// canonicalizeRootList canonicalizes, dedups, and sorts a list of
// path roots. Used for both the write Allow_List and the read
// deny-list — both share the same lookup semantics.
func canonicalizeRootList(roots []string) []string {
	seen := make(map[string]struct{}, len(roots))
	canonical := make([]string, 0, len(roots))
	for _, raw := range roots {
		if strings.TrimSpace(raw) == "" {
			continue
		}
		abs, err := filepath.Abs(raw)
		if err != nil {
			// An Abs failure is almost impossible (it only fails when
			// os.Getwd fails), but if it does happen we skip the entry
			// rather than poisoning the policy with a relative root.
			continue
		}
		clean := filepath.Clean(abs)
		if _, ok := seen[clean]; ok {
			continue
		}
		seen[clean] = struct{}{}
		canonical = append(canonical, clean)
	}
	sort.SliceStable(canonical, func(i, j int) bool {
		return len(canonical[i]) > len(canonical[j])
	})
	return canonical
}

var (
	defaultPolicy *Policy
	defaultOnce   sync.Once
)

// Default returns the process-global Policy assembled from the active
// configuration. The Allow_List is composed of:
//
//   - the active Data_Dir (cfg.Workspace, which mirrors Data_Dir after
//     Task 3.1 lands; before then it is the legacy $CWD-derived
//     workspace),
//   - cfg.HomeDir (~/.xalgorix),
//   - "/tmp".
//
// The read deny-list comes from cfg.ReadDenyList (sensible defaults
// merged with XALGORIX_READ_DENY_LIST entries). Reads outside the
// Allow_List are permitted by default; only deny-list members are
// rejected.
//
// The first call must follow config.Get(); subsequent calls return the
// memoized instance. Tests that need a different policy should
// construct their own via New / NewWithReadDeny.
func Default() *Policy {
	defaultOnce.Do(func() {
		cfg := config.Get()
		// cfg.Workspace is the active Data_Dir (Task 3.1 reassigns
		// the field; before that landed it points at the legacy
		// $CWD-derived workspace). Either way it is the right
		// resolution root for Filesystem_Tool writes.
		var readDeny []string
		if cfg != nil {
			readDeny = cfg.ReadDenyList
		}
		defaultPolicy = NewWithReadDeny(
			[]string{cfg.Workspace, cfg.HomeDir, "/tmp"},
			readDeny,
		)
	})
	return defaultPolicy
}

// Roots returns a defensive copy of the Allow_List roots used by this
// Policy. The slice is safe to mutate; modifications do not affect the
// Policy's internal state. The order is the same longest-first order
// used by Check.
func (p *Policy) Roots() []string {
	if p == nil {
		return nil
	}
	out := make([]string, len(p.roots))
	copy(out, p.roots)
	return out
}

// ReadDenyRoots returns a defensive copy of the deny-list used by
// CheckRead. Returned for the health endpoint and for tests; the
// Policy's internal state is not mutated by callers.
func (p *Policy) ReadDenyRoots() []string {
	if p == nil {
		return nil
	}
	out := make([]string, len(p.readDeny))
	copy(out, p.readDeny)
	return out
}

// Resolve turns (sc, raw) into an absolute, canonical path WITHOUT
// performing the Allow_List check. Use Check or CheckResolve when the
// caller cares about boundary enforcement.
//
// Relative paths resolve under sc.ScanDir when sc is non-nil and its
// ScanDir is non-empty, otherwise under cfg.Workspace (which mirrors
// Workspace_Root / Data_Dir). Absolute inputs are honored as-is.
//
// Canonicalization rule (R5.2):
//
//   - if the joined path exists, filepath.EvalSymlinks chases the chain;
//   - if it does not, filepath.EvalSymlinks is applied to the parent
//     and joined with filepath.Base of the input so a symlinked
//     directory containing a not-yet-created leaf is honored;
//   - if EvalSymlinks fails for an unexpected reason (permissions,
//     I/O error), Resolve falls back to filepath.Clean(filepath.Abs(...)).
func (p *Policy) Resolve(sc *scanctx.ScanContext, raw string) (string, error) {
	if raw == "" {
		return "", fmt.Errorf("path policy: empty path")
	}

	base := resolutionBase(sc)

	var joined string
	if filepath.IsAbs(raw) {
		joined = raw
	} else {
		if base == "" {
			// No resolution root available — fall back to absolute-
			// from-CWD so we still produce a deterministic path.
			abs, err := filepath.Abs(raw)
			if err != nil {
				return "", fmt.Errorf("path policy: abs(%s): %w", raw, err)
			}
			joined = abs
		} else {
			joined = filepath.Join(base, raw)
		}
	}

	canonical, err := canonicalize(joined)
	if err != nil {
		return "", err
	}
	return canonical, nil
}

// Check applies the Allow_List boundary check to a canonical path.
// The input is canonicalized again (filepath.Abs + filepath.Clean) so
// callers that already have an absolute path (e.g. from Resolve) get
// idempotent behavior. The function is side-effect-free: it never
// touches the filesystem and never modifies counters or logs.
//
// Returns nil when canonical equals an Allow_List root or has that
// root + filepath.Separator as a prefix. Returns *PathRejectError
// otherwise; the returned error has Path and Roots populated, but the
// Tool and ScanCtxID fields remain empty — CheckResolve fills those.
func (p *Policy) Check(canonical string) error {
	abs, err := filepath.Abs(canonical)
	if err != nil {
		return fmt.Errorf("path policy: abs(%s): %w", canonical, err)
	}
	abs = filepath.Clean(abs)
	for _, root := range p.roots {
		if abs == root {
			return nil
		}
		if strings.HasPrefix(abs, root+string(filepath.Separator)) {
			return nil
		}
	}
	return &PathRejectError{
		Path:  abs,
		Roots: append([]string(nil), p.roots...),
	}
}

// CheckResolve is the common one-shot path used by Filesystem_Tools:
// Resolve + Check + (on reject) safe.IncPathReject + structured WARN
// log + populated *PathRejectError.
//
// toolName is the namespaced operation (e.g. "fileedit.replace",
// "python_action") used in both the log line and the returned error.
// On success the returned string is the canonical, allow-list-cleared
// path the caller can hand directly to os.Open / os.MkdirAll / etc.
//
// CheckResolve is the WRITE entry point. Use CheckRead for read paths
// — reads are permitted everywhere except deny-list members.
func (p *Policy) CheckResolve(sc *scanctx.ScanContext, toolName, raw string) (string, error) {
	canonical, err := p.Resolve(sc, raw)
	if err != nil {
		return "", err
	}
	if err := p.Check(canonical); err != nil {
		// Promote into a fully-populated PathRejectError, count it,
		// and emit the WARN log line described by R5.6 / R9.1.
		var rej *PathRejectError
		pre := &PathRejectError{}
		if errors.As(err, &pre) {
			rej = pre
		} else {
			rej = &PathRejectError{Path: canonical, Roots: p.Roots()}
		}
		rej.Tool = toolName
		rej.ScanCtxID = scanContextID(sc)

		safe.IncPathReject()
		log.Printf("[path-policy] reject tool=%s scan=%s path=%s roots=%v",
			rej.Tool, rej.ScanCtxID, rej.Path, p.roots)

		return "", rej
	}
	return canonical, nil
}

// CheckRead is the READ entry point used by Filesystem_Tools that need
// to consume files anywhere on the host (system wordlists, payload
// dirs, /etc/services, /usr/share/seclists, etc.). It returns the
// canonical path on success and a *PathRejectError ONLY when the path
// resolves into a deny-list root.
//
// Behavior summary:
//
//   - Reads inside the Allow_List succeed (same as CheckResolve).
//   - Reads outside the Allow_List succeed by default.
//   - Reads under any deny-list root fail with PathRejectError and
//     the same counter / log line as CheckResolve.
//
// toolName is forwarded to the rejection log line and the typed error.
// Callers should pass the same namespaced operation name they use for
// CheckResolve (e.g. "fileedit.view", "terminal_read").
func (p *Policy) CheckRead(sc *scanctx.ScanContext, toolName, raw string) (string, error) {
	canonical, err := p.Resolve(sc, raw)
	if err != nil {
		return "", err
	}
	if err := p.CheckReadCanonical(canonical); err != nil {
		var rej *PathRejectError
		pre := &PathRejectError{}
		if errors.As(err, &pre) {
			rej = pre
		} else {
			rej = &PathRejectError{Path: canonical, Roots: p.ReadDenyRoots()}
		}
		rej.Tool = toolName
		rej.ScanCtxID = scanContextID(sc)

		safe.IncPathReject()
		log.Printf("[path-policy] read-deny tool=%s scan=%s path=%s deny=%v",
			rej.Tool, rej.ScanCtxID, rej.Path, p.readDeny)

		return "", rej
	}
	return canonical, nil
}

// CheckReadCanonical applies only the deny-list portion of the read
// policy to an already-canonical path. Returns nil when the path is
// outside every deny-list root, or *PathRejectError otherwise. The
// returned error has Path and Roots populated (with the deny-list
// roots) but Tool / ScanCtxID empty — CheckRead fills those.
//
// Side-effect-free: never touches the filesystem, never increments
// counters, never logs.
func (p *Policy) CheckReadCanonical(canonical string) error {
	abs, err := filepath.Abs(canonical)
	if err != nil {
		return fmt.Errorf("path policy: abs(%s): %w", canonical, err)
	}
	abs = filepath.Clean(abs)
	for _, deny := range p.readDeny {
		if abs == deny {
			return &PathRejectError{
				Path:  abs,
				Roots: append([]string(nil), p.readDeny...),
			}
		}
		if strings.HasPrefix(abs, deny+string(filepath.Separator)) {
			return &PathRejectError{
				Path:  abs,
				Roots: append([]string(nil), p.readDeny...),
			}
		}
	}
	return nil
}

// resolutionBase picks the directory relative paths resolve against.
// Prefers the active scan context's ScanDir (so per-scan artifacts
// stay isolated), falling back to cfg.Workspace which mirrors
// Workspace_Root / Data_Dir.
func resolutionBase(sc *scanctx.ScanContext) string {
	if sc != nil && strings.TrimSpace(sc.ScanDir) != "" {
		return sc.ScanDir
	}
	cfg := config.Get()
	if cfg != nil {
		return cfg.Workspace
	}
	return ""
}

// scanContextID returns sc.ID when available, "" otherwise. Kept as a
// helper so call sites stay readable.
func scanContextID(sc *scanctx.ScanContext) string {
	if sc == nil {
		return ""
	}
	return sc.ID
}

// canonicalize implements the R5.2 canonicalization rule.
func canonicalize(path string) (string, error) {
	abs, absErr := filepath.Abs(path)
	if absErr != nil {
		return "", fmt.Errorf("path policy: abs(%s): %w", path, absErr)
	}
	abs = filepath.Clean(abs)

	if _, statErr := os.Lstat(abs); statErr == nil {
		// Path exists — chase the symlink chain end-to-end.
		if resolved, err := filepath.EvalSymlinks(abs); err == nil {
			return filepath.Clean(resolved), nil
		}
		// EvalSymlinks failed for a reason other than non-existence
		// (permissions, broken symlink, I/O). Fall back to the
		// abs+clean form so the boundary check still runs.
		return abs, nil
	}

	// Path does not exist. EvalSymlink the parent so a symlinked
	// directory containing a not-yet-created leaf is honored.
	parent := filepath.Dir(abs)
	leaf := filepath.Base(abs)
	if resolved, err := filepath.EvalSymlinks(parent); err == nil {
		return filepath.Clean(filepath.Join(resolved, leaf)), nil
	}
	return abs, nil
}
