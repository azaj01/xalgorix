// Package terminal provides the terminal_execute tool.
package terminal

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/xalgord/xalgorix/v4/internal/config"
	"github.com/xalgord/xalgorix/v4/internal/resources"
	"github.com/xalgord/xalgorix/v4/internal/scanctx"
	"github.com/xalgord/xalgorix/v4/internal/tools"
)

const maxOutputLen = 20000

// Per-command timeout tiers
const (
	defaultCmdTimeout = 10 * time.Minute // most commands
	heavyCmdTimeout   = 60 * time.Minute // nmap, nuclei, ffuf, gobuster, sqlmap, masscan
	hardMaxTimeout    = 2 * time.Hour    // absolute ceiling — nothing runs longer
)

// ── Per-instance terminal stores ──
var (
	termStores   = make(map[string]*termStore)
	termStoresMu sync.RWMutex
)

type termStore struct {
	mu              sync.Mutex
	processGroup    map[*exec.Cmd]context.CancelFunc
	activeCommand   string
	activeStartTime time.Time
	streamCallback  func(string)
	workDir         string
}

// getTermStoreByID returns the terminal store for a specific context ID.
// Creates a new store if one doesn't exist (double-checked locking).
func getTermStoreByID(id string) *termStore {
	termStoresMu.RLock()
	s, ok := termStores[id]
	termStoresMu.RUnlock()
	if ok {
		return s
	}

	termStoresMu.Lock()
	defer termStoresMu.Unlock()
	if s, ok := termStores[id]; ok {
		return s
	}
	s = &termStore{processGroup: make(map[*exec.Cmd]context.CancelFunc)}
	termStores[id] = s
	return s
}

// getTermStore returns the terminal store for the default (CLI) scan context.
func getTermStore() *termStore {
	return getTermStoreByID(scanctx.Default().ID)
}

func normalizeContextID(id string) string {
	if strings.TrimSpace(id) == "" {
		return scanctx.Default().ID
	}
	return id
}

// heavyToolPatterns are commands that get extended timeouts.
var heavyToolPatterns = []string{
	"nmap", "nuclei", "ffuf", "gobuster", "dirsearch", "feroxbuster",
	"sqlmap", "masscan", "wpscan", "joomscan", "dalfox", "katana",
	"gospider", "subfinder", "amass", "rustscan",
}

// isHeavyTool returns true if the command involves a resource-intensive tool.
// Used for both timeout selection and resource throttling (Layer 2).
func isHeavyTool(command string) bool {
	lower := strings.ToLower(command)
	for _, tool := range heavyToolPatterns {
		if strings.Contains(lower, tool) {
			return true
		}
	}
	return false
}

// computeTimeout decides how long a command is allowed to run.
func computeTimeout(command string) time.Duration {
	if isHeavyTool(command) {
		return heavyCmdTimeout
	}
	return defaultCmdTimeout
}

// setProcessLimits applies resource constraints to a child process:
// - Adjusts OOM score so the kernel kills scan tools before xalgorix
// - Sets RLIMIT_AS (virtual memory limit) for heavy tools
func setProcessLimits(cmd *exec.Cmd, heavy bool) {
	if cmd.Process == nil {
		return
	}
	pid := cmd.Process.Pid

	// ── OOM score adjustment ──
	// Score 500 = "kill me before most things, but not before 1000"
	// xalgorix itself stays at default (0), so kernel prefers killing children.
	oomPath := fmt.Sprintf("/proc/%d/oom_score_adj", pid)
	if err := os.WriteFile(oomPath, []byte("500"), 0644); err != nil {
		// Not fatal — best effort. Fails if not running as root.
		log.Printf("[RESOURCES] Cannot set OOM score for PID %d: %v", pid, err)
	}

	// ── Memory limit for heavy tools ──
	// Uses prlimit64 syscall to set RLIMIT_AS on the child process.
	// If the tool exceeds this, it gets ENOMEM / SIGSEGV — xalgorix survives.
	if heavy && resources.HeavyToolMemLimitBytes > 0 {
		newLimit := syscall.Rlimit{
			Cur: uint64(resources.HeavyToolMemLimitBytes),
			Max: uint64(resources.HeavyToolMemLimitBytes),
		}
		// prlimit64(pid, resource, new_rlimit*, old_rlimit*)
		_, _, errno := syscall.RawSyscall6(
			syscall.SYS_PRLIMIT64,
			uintptr(pid),
			uintptr(syscall.RLIMIT_AS),
			uintptr(unsafe.Pointer(&newLimit)),
			0, // old limit — don't need it
			0, 0,
		)
		if errno != 0 {
			log.Printf("[RESOURCES] Cannot set RLIMIT_AS for PID %d: %v", pid, errno)
		} else {
			log.Printf("[RESOURCES] Heavy tool PID %d: OOM score=500, mem limit=%d MB",
				pid, resources.HeavyToolMemLimitBytes/(1024*1024))
		}
	} else {
		log.Printf("[RESOURCES] PID %d: OOM score set to 500", pid)
	}
}

// ActiveProcessCount returns the number of currently running processes.
func ActiveProcessCount() int {
	return ActiveProcessCountForContext(scanctx.Default().ID)
}

// ActiveProcessCountForContext returns the number of running processes for one context.
func ActiveProcessCountForContext(contextID string) int {
	contextID = normalizeContextID(contextID)
	if sc := scanctx.Get(contextID); sc != nil && sc.Terminal != nil {
		return sc.Terminal.ActiveProcessCount()
	}
	s := getTermStoreByID(contextID)
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.processGroup)
}

// GetActiveCommand returns the currently running command and how long it's been running.
func GetActiveCommand() (string, time.Duration) {
	s := getTermStore()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.activeCommand == "" {
		return "", 0
	}
	return s.activeCommand, time.Since(s.activeStartTime)
}

// GetActiveCommandStartTime returns the start time of the active command.
func GetActiveCommandStartTime() time.Time {
	s := getTermStore()
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.activeStartTime
}

// TrackProcess registers a command to be tracked by the watchdog and killed on Stop.
func TrackProcess(cmd *exec.Cmd, cancel context.CancelFunc, commandStr string) {
	TrackProcessForContext(scanctx.Default().ID, cmd, cancel, commandStr)
}

// TrackProcessForContext registers a command against a specific scan context.
func TrackProcessForContext(contextID string, cmd *exec.Cmd, cancel context.CancelFunc, commandStr string) {
	contextID = normalizeContextID(contextID)
	s := getTermStoreByID(contextID)
	s.mu.Lock()
	s.processGroup[cmd] = cancel
	if len(commandStr) > 200 {
		s.activeCommand = commandStr[:200] + "..."
	} else {
		s.activeCommand = commandStr
	}
	s.activeStartTime = time.Now()
	s.mu.Unlock()

	if sc := scanctx.Get(contextID); sc != nil && sc.Terminal != nil {
		sc.Terminal.TrackProcess(cmd, cancel, commandStr)
	}
}

// UntrackProcess removes a command from tracking once it completes.
func UntrackProcess(cmd *exec.Cmd) {
	UntrackProcessForContext(scanctx.Default().ID, cmd)
}

// UntrackProcessForContext removes a command from a specific scan context.
func UntrackProcessForContext(contextID string, cmd *exec.Cmd) {
	contextID = normalizeContextID(contextID)
	s := getTermStoreByID(contextID)
	s.mu.Lock()
	delete(s.processGroup, cmd)
	if len(s.processGroup) == 0 {
		s.activeCommand = ""
	}
	s.mu.Unlock()

	if sc := scanctx.Get(contextID); sc != nil && sc.Terminal != nil {
		sc.Terminal.UntrackProcess(cmd)
	}
}

// ReapDeadProcesses checks all tracked processes and removes any that have
// already exited.
func ReapDeadProcesses() int {
	s := getTermStore()
	s.mu.Lock()
	defer s.mu.Unlock()

	reaped := 0
	for cmd, cancel := range s.processGroup {
		if cmd.ProcessState != nil && cmd.ProcessState.Exited() {
			log.Printf("[REAP] Removing dead process from tracker: pid=%d", cmd.Process.Pid)
			delete(s.processGroup, cmd)
			if cancel != nil {
				cancel()
			}
			reaped++
		}
	}

	if reaped > 0 && len(s.processGroup) == 0 {
		s.activeCommand = ""
	}
	return reaped
}

// SetStreamCallback sets a callback that receives partial output from running commands.
func SetStreamCallback(cb func(partialOutput string)) {
	s := getTermStore()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.streamCallback = cb
}

// ClearStreamCallback removes the stream callback.
func ClearStreamCallback() {
	s := getTermStore()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.streamCallback = nil
}

func streamCallbackForContext(contextID string) func(string) {
	contextID = normalizeContextID(contextID)
	if sc := scanctx.Get(contextID); sc != nil && sc.Terminal != nil {
		if cb := sc.Terminal.GetStreamCallback(); cb != nil {
			return cb
		}
	}
	s := getTermStoreByID(contextID)
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.streamCallback
}

// KillAllProcesses kills all running processes for the active scan context.
func KillAllProcesses() {
	KillAllProcessesForContext(scanctx.Default().ID)
}

// KillAllProcessesForContext kills all processes for one scan context.
func KillAllProcessesForContext(contextID string) {
	contextID = normalizeContextID(contextID)
	s := getTermStoreByID(contextID)
	s.mu.Lock()
	for cmd, cancel := range s.processGroup {
		if cmd != nil && cmd.Process != nil {
			if pgid, err := syscall.Getpgid(cmd.Process.Pid); err == nil {
				syscall.Kill(-pgid, syscall.SIGKILL)
			}
			cmd.Process.Kill()
		}
		if cancel != nil {
			cancel()
		}
	}
	s.processGroup = make(map[*exec.Cmd]context.CancelFunc)
	s.activeCommand = ""
	s.mu.Unlock()

	if sc := scanctx.Get(contextID); sc != nil && sc.Terminal != nil {
		sc.Terminal.KillAll()
	}
}

// SetWorkDir sets the working directory for terminal commands.
func SetWorkDir(dir string) {
	SetWorkDirForContext(scanctx.Default().ID, dir)
}

// SetWorkDirForContext sets the working directory for one scan context.
func SetWorkDirForContext(contextID, dir string) {
	contextID = normalizeContextID(contextID)
	s := getTermStoreByID(contextID)
	s.mu.Lock()
	s.workDir = dir
	s.mu.Unlock()

	if sc := scanctx.Get(contextID); sc != nil && sc.Terminal != nil {
		sc.Terminal.SetWorkDir(dir)
	}
}

// GetWorkDir returns the current working directory.
func GetWorkDir() string {
	return GetWorkDirForContext(scanctx.Default().ID)
}

// GetWorkDirForContext returns the current working directory for one scan context.
func GetWorkDirForContext(contextID string) string {
	contextID = normalizeContextID(contextID)
	if sc := scanctx.Get(contextID); sc != nil && sc.Terminal != nil {
		if wd := sc.Terminal.GetWorkDir(); wd != "" {
			return wd
		}
	}
	s := getTermStoreByID(contextID)
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.workDir
}

// CleanupContext removes the terminal store for a deactivated context.
func CleanupContext(contextID string) {
	KillAllProcessesForContext(contextID)
	termStoresMu.Lock()
	defer termStoresMu.Unlock()
	delete(termStores, contextID)
}

// Common command → package mappings for auto-install.
var packageMap = map[string]string{
	// DNS & networking
	"nslookup":   "dnsutils",
	"dig":        "dnsutils",
	"host":       "dnsutils",
	"whois":      "whois",
	"traceroute": "traceroute",
	"ping":       "iputils-ping",
	"nmap":       "nmap",
	"netcat":     "ncat",
	"nc":         "ncat",
	"socat":      "socat",
	"tcpdump":    "tcpdump",
	"ss":         "iproute2",
	"ip":         "iproute2",
	"arp":        "net-tools",
	"ifconfig":   "net-tools",
	"netstat":    "net-tools",
	// Web / HTTP
	"curl":   "curl",
	"wget":   "wget",
	"httpie": "httpie",
	"http":   "httpie",
	// SSL/TLS
	"openssl": "openssl",
	// Recon / enumeration (Go tools — resolved to go install in installPackage)
	"dirb":        "dirb",
	"gobuster":    "gobuster",
	"ffuf":        "ffuf",
	"subfinder":   "subfinder",
	"assetfinder": "assetfinder",
	"masscan":     "masscan",
	"wfuzz":       "wfuzz",
	"httpx":       "httpx",
	"dnsx":        "dnsx",
	"nuclei":      "nuclei",
	"katana":      "katana",
	"gospider":    "gospider",
	"gau":         "gau",
	"waybackurls": "waybackurls",
	"hakrawler":   "hakrawler",
	"naabu":       "naabu",
	"dalfox":      "dalfox",
	"paramspider": "paramspider",
	"feroxbuster": "feroxbuster",
	// Findomain — Rust binary, installed via package manager or cargo
	"findomain": "findomain",
	// Text processing
	"jq":        "jq",
	"xmllint":   "libxml2-utils",
	"html2text": "html2text",
	// Git
	"git": "git",
	// Python
	"python3":     "python3",
	"pip3":        "python3-pip",
	"pip":         "python3-pip",
	"scrapling":   "scrapling", // Handled by pipx in installPackage
	"python-venv": "python3-venv",
	// General
	"tree":    "tree",
	"unzip":   "unzip",
	"zip":     "zip",
	"file":    "file",
	"strings": "binutils",
	"xxd":     "xxd",
	"base64":  "coreutils",
	"awk":     "gawk",
	"sed":     "sed",
	"grep":    "grep",
	"find":    "findutils",
	"xargs":   "findutils",
	"bc":      "bc",
	// SQL
	"sqlmap": "sqlmap",
}

// decode decodes a base64 string
func decode(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(s)
}

// decodeHex decodes a hex string
func decodeHex(s string) ([]byte, error) {
	s = strings.ToLower(s)
	s = strings.TrimPrefix(s, "0x")
	return hex.DecodeString(s)
}

// Register adds terminal tools to the registry.
// The registry is captured in the closure so tool execution resolves the correct
// per-session terminal store via registry.GetScanContextID().
func Register(r *tools.Registry) {
	r.Register(&tools.Tool{
		Name:        "terminal_execute",
		Description: "Execute a shell command in the terminal. Returns stdout, stderr, and exit code. Automatically installs missing tools. Commands have a 10-minute timeout by default (30 minutes for heavy tools like nmap/nuclei). Use targeted scans to stay within limits.",
		Parameters: []tools.Parameter{
			{Name: "command", Description: "The shell command to execute", Required: true},
		},
		Execute: func(args map[string]string) (tools.Result, error) {
			return executeCommandForRegistry(r, args)
		},
	})
}

// toolExists checks if a tool is available in the expanded PATH
// (same directories as runShell uses). This is more reliable than
// exec.LookPath which only searches the Go process's own PATH.
func toolExists(name string) bool {
	// First try the standard PATH
	if _, err := exec.LookPath(name); err == nil {
		return true
	}

	// Then check expanded locations that runShell adds
	homeDir := os.Getenv("HOME")
	if homeDir == "" {
		homeDir = "/root"
	}
	goPath := os.Getenv("GOPATH")
	if goPath == "" {
		goPath = homeDir + "/go"
	}

	extraDirs := []string{
		goPath + "/bin",
		homeDir + "/go/bin",
		homeDir + "/.local/bin",
		homeDir + "/.cargo/bin",
		"/usr/local/bin",
		"/snap/bin",
	}

	for _, dir := range extraDirs {
		if _, err := os.Stat(filepath.Join(dir, name)); err == nil {
			return true
		}
	}
	return false
}

// executeCommandForRegistry resolves the correct terminal store via the registry's ScanContextID.
func executeCommandForRegistry(reg *tools.Registry, args map[string]string) (tools.Result, error) {
	return executeCommandWithContextID(reg.GetScanContextID(), args)
}

// executeCommand is the backward-compatible version using scanctx.Default().
//
//lint:ignore U1000 kept as a package-level compatibility wrapper for callers in this package.
func executeCommand(args map[string]string) (tools.Result, error) {
	return executeCommandWithContextID(scanctx.Default().ID, args)
}

func executeCommandWithContextID(contextID string, args map[string]string) (tools.Result, error) {
	command := args["command"]
	if command == "" {
		return tools.Result{}, fmt.Errorf("command is required")
	}

	// Block destructive commands
	if reason := isBlockedCommand(command); reason != "" {
		return tools.Result{Output: fmt.Sprintf("[BLOCKED] Destructive command rejected: %s. Xalgorix is read-only — it tests for vulnerabilities without causing damage.", reason)}, nil
	}

	// Pre-check: install missing tools BEFORE running the command.
	// Use the same expanded PATH as runShell so we find tools in ~/.cargo/bin, ~/go/bin, etc.
	var preInstalled []string
	toolsToCheck := extractCommands(command)
	for _, tool := range toolsToCheck {
		if !toolExists(tool) {
			pkg := resolvePackage(tool)
			if pkg != "" {
				installPackage(pkg)
				preInstalled = append(preInstalled, tool)
			}
		}
	}

	// Run the command using the correct context's store
	output, exitCode := runShellWithContext(contextID, command)

	// If it still fails with "command not found", try one more install+retry.
	// This catches tools not in extractCommands' list (e.g. piped commands).
	if exitCode == 127 || isCommandNotFound(output) {
		missingCmd := extractMissingCommand(output)
		if missingCmd != "" {
			pkg := resolvePackage(missingCmd)
			if pkg != "" {
				installOutput := installPackage(pkg)
				retryOutput, retryExit := runShellWithContext(contextID, command)
				combined := fmt.Sprintf("[auto-installed %s (%s)]\n%s\n%s",
					missingCmd, pkg, installOutput, retryOutput)
				if retryExit != 0 {
					combined += fmt.Sprintf("\n[exit code: %d]", retryExit)
				}
				return tools.Result{Output: combined}, nil
			}
		}
	}

	// Prepend install info if we installed anything
	if len(preInstalled) > 0 {
		output = fmt.Sprintf("[pre-installed: %s]\n%s", strings.Join(preInstalled, ", "), output)
	}

	return tools.Result{Output: output}, nil
}

func ensureVenv() {
	homeDir := os.Getenv("HOME")
	if homeDir == "" {
		homeDir = "/root"
	}
	venvPath := filepath.Join(homeDir, "venv")

	// Check if venv exists
	if _, err := os.Stat(venvPath); os.IsNotExist(err) {
		// Create venv
		fmt.Println("Creating Python virtual environment at ~/venv...")
		cmd := exec.Command("python3", "-m", "venv", venvPath)
		if err := cmd.Run(); err != nil {
			log.Printf("Warning: failed to create Python venv at %s: %v", venvPath, err)
		}
	}
}

// runShellWithContext executes a shell command using the terminal store for the
// given context ID. This ensures streaming callbacks and process tracking are
// routed through the correct per-session store instead of the global default.
func runShellWithContext(contextID string, command string) (string, int) {
	return runShellInternal(contextID, command)
}

//lint:ignore U1000 kept as a package-level compatibility wrapper for callers in this package.
func runShell(command string) (string, int) {
	return runShellInternal(scanctx.Default().ID, command)
}

func runShellInternal(contextID string, command string) (string, int) {
	contextID = normalizeContextID(contextID)
	// Ensure venv exists
	ensureVenv()

	homeDir := os.Getenv("HOME")
	if homeDir == "" {
		homeDir = "/root"
	}
	// Activate venv if it exists — use semicolon so failure doesn't block the command
	venvActivate := "source " + filepath.Join(homeDir, "venv", "bin", "activate") + " 2>/dev/null; "

	// Wrap command with venv activation
	command = venvActivate + command

	// Compute timeout based on command type
	timeout := computeTimeout(command)
	if timeout > hardMaxTimeout {
		timeout = hardMaxTimeout
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cfg := config.Get()

	// Set PATH to include common tool locations (dynamic - works for any user)
	goPath := os.Getenv("GOPATH")
	if goPath == "" {
		goPath = homeDir + "/go"
	}

	// Build dynamic PATH including all possible tool locations
	dynamicPath := goPath + "/bin:" + homeDir + "/go/bin:" + homeDir + "/.local/bin"
	dynamicPath += ":" + homeDir + "/.cargo/bin" // Rust tools (findomain, rustscan, feroxbuster)
	dynamicPath += ":/usr/local/bin:/snap/bin"   // Common install locations

	cmdEnv := append(os.Environ(),
		"PATH="+dynamicPath+":"+os.Getenv("PATH"),
		"GOPATH="+goPath,
	)

	cmd := exec.CommandContext(ctx, "bash", "-c", command)
	// Use goroutine-scoped workdir if set, otherwise default to config workspace
	if wd := GetWorkDirForContext(contextID); wd != "" {
		cmd.Dir = wd
	} else {
		cmd.Dir = cfg.Workspace
	}
	cmd.Env = cmdEnv

	// Create new process group for this command
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setpgid: true,
	}

	// Store a clean version of the command (strip venv activation prefix)
	cleanCmd := strings.TrimPrefix(command, venvActivate)

	// ── Layer 2: Pre-exec resource throttle ──
	// Before launching, check if the system has enough resources.
	// Heavy tools (nuclei, masscan, etc.) are gated more strictly.
	// If a heavy tool can't get resources within the timeout, abort it
	// to prevent the kernel OOM killer from nuking the whole server.
	heavy := isHeavyTool(command)
	if heavy {
		if !resources.WaitForResources(true, 2*time.Minute, cleanCmd) {
			return fmt.Sprintf("[THROTTLE] Refused to launch heavy tool %q — system resources exhausted after 2m wait", cleanCmd), -1
		}
	} else {
		resources.WaitForResources(false, 30*time.Second, cleanCmd)
	}

	// Use pipes for real-time output streaming
	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Sprintf("Failed to create stdout pipe: %v", err), -1
	}
	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		return fmt.Sprintf("Failed to create stderr pipe: %v", err), -1
	}

	// Start the command
	if err := cmd.Start(); err != nil {
		return fmt.Sprintf("Failed to start command: %v", err), -1
	}

	// ── Layer 3: Post-start process limits ──
	// Set OOM score and memory limits on the child process.
	setProcessLimits(cmd, heavy)

	TrackProcessForContext(contextID, cmd, cancel, cleanCmd)
	defer UntrackProcessForContext(contextID, cmd)

	// Read output in goroutines with periodic streaming
	// Buffers are capped at 5MB to prevent OOM on huge command output
	const maxBufSize = 5 * 1024 * 1024
	var stdout, stderr bytes.Buffer
	var stdoutOverflow, stderrOverflow bool
	var wg sync.WaitGroup

	// Stream stdout
	wg.Add(1)
	go func() {
		defer wg.Done()
		buf := make([]byte, 32768)
		lastStream := time.Now()
		for {
			n, err := stdoutPipe.Read(buf)
			if n > 0 {
				chunk := buf[:n]
				// Cap buffer size to prevent OOM
				if stdout.Len()+n > maxBufSize {
					if !stdoutOverflow {
						stdoutOverflow = true
					}
					// Keep only the last part — discard old data
					stdout.Reset()
					stdout.WriteString("[OUTPUT TRUNCATED — exceeded 5MB]\n")
				}
				stdout.Write(chunk)

				// Stream partial output every 10 seconds.
				cb := streamCallbackForContext(contextID)
				if cb != nil && time.Since(lastStream) > 10*time.Second {
					out := stdout.String()
					if len(out) > 2000 {
						out = "...\n" + out[len(out)-2000:]
					}
					cb(out)
					lastStream = time.Now()
				}
			}
			if err != nil {
				break
			}
		}
	}()

	// Stream stderr (also capped)
	wg.Add(1)
	go func() {
		defer wg.Done()
		buf := make([]byte, 32768)
		for {
			n, err := stderrPipe.Read(buf)
			if n > 0 {
				if stderr.Len()+n > maxBufSize {
					if !stderrOverflow {
						stderrOverflow = true
					}
					stderr.Reset()
					stderr.WriteString("[STDERR TRUNCATED — exceeded 5MB]\n")
				}
				stderr.Write(buf[:n])
			}
			if err != nil {
				break
			}
		}
	}()

	// Wait for output readers to finish
	wg.Wait()

	// Wait for command to finish
	err = cmd.Wait()
	// Note: process unregistration is handled by defer UntrackProcess(cmd) above

	exitCode := 0
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else if ctx.Err() == context.DeadlineExceeded {
			// Command was killed by timeout
			return fmt.Sprintf("[TIMEOUT] Command killed after %s. Use more targeted scans (fewer ports, specific paths, smaller scope) to stay within the time limit.\nPartial stdout:\n%s\nPartial stderr:\n%s",
				timeout.Round(time.Second), truncate(stdout.String()), truncate(stderr.String())), -1
		} else if ctx.Err() == context.Canceled {
			// Context was cancelled (Stop or watchdog kill)
			return fmt.Sprintf("Command cancelled.\nPartial stdout:\n%s\nPartial stderr:\n%s",
				truncate(stdout.String()), truncate(stderr.String())), -1
		}
	}

	return formatOutput(stdout.String(), stderr.String(), exitCode), exitCode
}

func isCommandNotFound(output string) bool {
	lower := strings.ToLower(output)
	return strings.Contains(lower, "command not found") ||
		strings.Contains(lower, "no such file or directory") ||
		strings.Contains(lower, "not found in") ||
		strings.Contains(lower, ": not found")
}

func extractMissingCommand(output string) string {
	// Patterns: "bash: line N: <cmd>: command not found"
	//           "<cmd>: command not found"
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		lower := strings.ToLower(line)
		if strings.Contains(lower, "command not found") || strings.Contains(lower, ": not found") {
			// Extract the command name — typically the word before ": command not found"
			parts := strings.Split(line, ":")
			for _, p := range parts {
				p = strings.TrimSpace(p)
				// Skip "bash", "line N", "STDERR", etc.
				if p != "" && !strings.HasPrefix(p, "bash") &&
					!strings.HasPrefix(p, "line ") &&
					!strings.HasPrefix(p, "STDERR") &&
					!strings.Contains(p, "command not found") &&
					!strings.Contains(p, "not found") &&
					!strings.HasPrefix(p, "/") {
					// Clean up — take last word (handles paths)
					words := strings.Fields(p)
					if len(words) > 0 {
						cmd := words[len(words)-1]
						// Validate it looks like a command
						if len(cmd) > 0 && len(cmd) < 50 && !strings.ContainsAny(cmd, " \t(){}[]") {
							return cmd
						}
					}
				}
			}
		}
	}
	return ""
}

func resolvePackage(cmd string) string {
	// Check our built-in map first
	if pkg, ok := packageMap[cmd]; ok {
		return pkg
	}
	// Don't blindly fall back — only return if we know the package
	return ""
}

func installPackage(pkg string) string {
	// Special handling for pipx-installed tools
	pipxTools := map[string]string{
		"scrapling": "scrapling",
	}

	// Special handling for Cargo (Rust) tools
	cargoTools := map[string]string{
		"feroxbuster": "feroxbuster",
	}

	// Special handling for Go-installed tools
	goTools := map[string]string{
		// ProjectDiscovery suite
		"nuclei":    "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
		"httpx":     "github.com/projectdiscovery/httpx/cmd/httpx@latest",
		"dnsx":      "github.com/projectdiscovery/dnsx/cmd/dnsx@latest",
		"subfinder": "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
		"katana":    "github.com/projectdiscovery/katana/cmd/katana@latest",
		"naabu":     "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest",
		// Web crawlers & URL discovery
		"gospider":    "github.com/jaeles-project/gospider@latest",
		"gau":         "github.com/lc/gau/v2/cmd/gau@latest",
		"waybackurls": "github.com/tomnomnom/waybackurls@latest",
		"hakrawler":   "github.com/hakluke/hakrawler@latest",
		// Fuzzing & enumeration
		"gobuster":    "github.com/OJ/gobuster/v3@latest",
		"ffuf":        "github.com/ffuf/ffuf/v2@latest",
		"assetfinder": "github.com/tomnomnom/assetfinder@latest",
		// Vulnerability scanners
		"dalfox": "github.com/hahwul/dalfox/v2@latest",
		// Parameter discovery
		"paramspider": "github.com/devanshbatham/paramspider@latest",
	}

	// npm-installed tools
	npmTools := map[string]string{
		"playwright-cli": "@anthropic-ai/playwright-cli",
	}

	homeDir := os.Getenv("HOME")
	if homeDir == "" {
		homeDir = "/root"
	}

	// pipx-installed tools (Python)
	if pipxPkg, ok := pipxTools[pkg]; ok {
		installCmd := fmt.Sprintf("pipx install %s 2>&1 || pip3 install %s 2>&1", pipxPkg, pipxPkg)
		ctx, cancel := context.WithTimeout(context.Background(), 600*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, "bash", "-c", installCmd)
		out, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Sprintf("[install %s via pipx/pip failed: %s]\n%s", pkg, err, truncate(string(out)))
		}
		return fmt.Sprintf("[installed %s via pipx successfully]", pkg)
	}

	// Cargo (Rust) tools
	if cargoPkg, ok := cargoTools[pkg]; ok {
		// Try apt first (faster), then cargo install as fallback
		installCmd := fmt.Sprintf("apt-get install -y -q %s 2>&1 || cargo install %s 2>&1", cargoPkg, cargoPkg)
		if os.Getuid() != 0 {
			installCmd = fmt.Sprintf("sudo apt-get install -y -q %s 2>&1 || cargo install %s 2>&1", cargoPkg, cargoPkg)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 600*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, "bash", "-c", installCmd)
		out, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Sprintf("[install %s via apt/cargo failed: %s]\n%s", pkg, err, truncate(string(out)))
		}
		return fmt.Sprintf("[installed %s successfully]", pkg)
	}

	if goPkg, ok := goTools[pkg]; ok {
		installCmd := fmt.Sprintf("GOBIN=%s/go/bin go install -v %s 2>&1", homeDir, goPkg)
		ctx, cancel := context.WithTimeout(context.Background(), 600*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, "bash", "-c", installCmd)
		out, err := cmd.CombinedOutput()

		// If default proxy fails, retry with GOPROXY=direct
		if err != nil {
			installCmd = fmt.Sprintf("GOBIN=%s/go/bin GOPROXY=direct go install -v %s 2>&1", homeDir, goPkg)
			cmd = exec.CommandContext(ctx, "bash", "-c", installCmd)
			out, err = cmd.CombinedOutput()
		}

		if err != nil {
			return fmt.Sprintf("[install %s failed: %s]\n%s", pkg, err, truncate(string(out)))
		}
		return fmt.Sprintf("[installed %s via go install successfully]", pkg)
	}

	// Special handling for npm-installed tools
	if npmPkg, ok := npmTools[pkg]; ok {
		installCmd := fmt.Sprintf("npm install -g %s 2>&1", npmPkg)
		ctx, cancel := context.WithTimeout(context.Background(), 600*time.Second) // 10 min for npm install
		defer cancel()
		cmd := exec.CommandContext(ctx, "bash", "-c", installCmd)
		out, err := cmd.CombinedOutput()
		if err != nil {
			// Try with sudo
			installCmd = "sudo " + installCmd
			cmd = exec.CommandContext(ctx, "bash", "-c", installCmd)
			out, err = cmd.CombinedOutput()
		}
		if err != nil {
			return fmt.Sprintf("[install %s via npm failed: %s]\n%s", pkg, err, truncate(string(out)))
		}
		return fmt.Sprintf("[installed %s via npm successfully]", pkg)
	}

	// Detect package manager and build install command
	var installCmd string

	if _, err := exec.LookPath("apt-get"); err == nil {
		installCmd = fmt.Sprintf("DEBIAN_FRONTEND=noninteractive apt-get install -y -q %s 2>&1", pkg)
	} else if _, err := exec.LookPath("dnf"); err == nil {
		installCmd = fmt.Sprintf("dnf install -y -q %s 2>&1", pkg)
	} else if _, err := exec.LookPath("yum"); err == nil {
		installCmd = fmt.Sprintf("yum install -y -q %s 2>&1", pkg)
	} else if _, err := exec.LookPath("pacman"); err == nil {
		installCmd = fmt.Sprintf("pacman -S --noconfirm %s 2>&1", pkg)
	} else if _, err := exec.LookPath("apk"); err == nil {
		installCmd = fmt.Sprintf("apk add --no-cache %s 2>&1", pkg)
	} else {
		return fmt.Sprintf("[cannot auto-install: no supported package manager found for %s]", pkg)
	}

	// Prefix with sudo if not running as root
	if os.Getuid() != 0 {
		installCmd = "sudo " + installCmd
	}

	ctx, cancel := context.WithTimeout(context.Background(), 600*time.Second) // 10 min for pkg install
	defer cancel()

	cmd := exec.CommandContext(ctx, "bash", "-c", installCmd)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Sprintf("[install %s failed: %s]\n%s", pkg, err, truncate(string(out)))
	}

	return fmt.Sprintf("[installed %s successfully]", pkg)
}

func formatOutput(stdout, stderr string, exitCode int) string {
	var b strings.Builder

	if stdout != "" {
		b.WriteString(truncate(stdout))
	}

	if stderr != "" {
		if b.Len() > 0 {
			b.WriteString("\n")
		}
		b.WriteString("STDERR:\n")
		b.WriteString(truncate(stderr))
	}

	if exitCode != 0 {
		b.WriteString(fmt.Sprintf("\n[exit code: %d]", exitCode))
	}

	return b.String()
}

func truncate(s string) string {
	if len(s) > maxOutputLen {
		half := maxOutputLen / 2
		return s[:half] + "\n\n... [TRUNCATED] ...\n\n" + s[len(s)-half:]
	}
	return s
}

// blockedPatterns contains destructive commands that must never be executed.
var blockedPatterns = []struct {
	pattern string
	reason  string
}{
	{"rm -rf /", "recursive delete of root filesystem"},
	{"rm -rf /*", "recursive delete of root filesystem"},
	{"rm -rf ~", "recursive delete of home directory"},
	{"rm -rf .", "recursive delete of current directory"},
	{"> /dev/sd", "overwriting disk device"},
	{"dd if=/dev/zero", "overwriting with zeros"},
	{"dd if=/dev/random", "overwriting with random data"},
	{"mkfs", "formatting filesystem"},
	{"shutdown", "system shutdown"},
	{"reboot", "system reboot"},
	{"init 0", "system halt"},
	{"init 6", "system reboot"},
	{"halt", "system halt"},
	{"poweroff", "system poweroff"},
	{":(){ :|:&};:", "fork bomb"},
	{"chmod 777 /", "removing all file permissions on root"},
	{"chown -R", "recursive ownership change"},
	// SQL destructive statements
	{"drop table", "SQL DROP TABLE"},
	{"drop database", "SQL DROP DATABASE"},
	{"delete from", "SQL DELETE FROM"},
	{"truncate table", "SQL TRUNCATE TABLE"},
	// Python destructive
	{"shutil.rmtree", "recursive directory removal"},
	{"os.remove", "file deletion"},
	// Noisy / false-positive-heavy tools
	{"nikto", "nikto is blocked — too many false positives. Use nuclei or manual testing instead"},
}

// isBlockedCommand checks if a command matches any blocked pattern.
// It also detects encoding attempts (base64, hex, etc.) and checks decoded content.
func isBlockedCommand(cmd string) string {
	// First check the raw command
	if reason := checkBlocked(cmd); reason != "" {
		return reason
	}

	// Try to decode and check base64 encoded commands
	if decoded := tryBase64Decode(cmd); decoded != "" {
		if reason := checkBlocked(decoded); reason != "" {
			return reason + " (detected via base64 decoding)"
		}
	}

	// Try hex decoding
	if decoded := tryHexDecode(cmd); decoded != "" {
		if reason := checkBlocked(decoded); reason != "" {
			return reason + " (detected via hex decoding)"
		}
	}

	// Try URL decoding
	if decoded := tryURLDecode(cmd); decoded != "" && decoded != cmd {
		if reason := checkBlocked(decoded); reason != "" {
			return reason + " (detected via URL decoding)"
		}
	}

	// Check for common obfuscation patterns
	if reason := checkObfuscation(cmd); reason != "" {
		return reason
	}

	return ""
}

// checkBlocked is the core blocking logic
func checkBlocked(cmd string) string {
	lower := strings.ToLower(cmd)
	for _, bp := range blockedPatterns {
		if strings.Contains(lower, bp.pattern) {
			return bp.reason
		}
	}
	return ""
}

// tryBase64Decode attempts to decode a base64 string
func tryBase64Decode(cmd string) string {
	// Remove common prefixes
	cmd = strings.TrimSpace(cmd)
	cmd = strings.TrimPrefix(cmd, "echo ")
	cmd = strings.TrimPrefix(cmd, "echo ")
	cmd = strings.TrimSuffix(cmd, " | base64 -d")
	cmd = strings.TrimSuffix(cmd, " | base64 --decode")
	cmd = strings.TrimSuffix(cmd, "| base64 -d")
	cmd = strings.TrimSuffix(cmd, "| base64 --decode")
	cmd = strings.Trim(cmd, " \t\n")

	// Try standard base64
	if decoded, err := decodeBase64(cmd); err == nil && len(decoded) > 0 {
		return decoded
	}

	return ""
}

// decodeBase64 decodes a base64 string
func decodeBase64(cmd string) (string, error) {
	// Add padding if needed
	missing := 4 - (len(cmd) % 4)
	if missing != 4 {
		cmd += strings.Repeat("=", missing)
	}

	data, err := decode(cmd) // using the existing base64 decode
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// tryHexDecode attempts to decode a hex string
func tryHexDecode(cmd string) string {
	cmd = strings.TrimSpace(cmd)

	// Check if it looks like hex (0x... or just hex chars)
	if !isHexString(cmd) {
		return ""
	}

	data, err := decodeHex(cmd)
	if err != nil {
		return ""
	}
	return string(data)
}

// isHexString checks if a string is valid hexadecimal
func isHexString(s string) bool {
	s = strings.ToLower(s)
	// Remove 0x prefix if present
	s = strings.TrimPrefix(s, "0x")
	if len(s) < 4 || len(s)%2 != 0 {
		return false
	}
	_, err := decodeHex(s)
	return err == nil
}

// tryURLDecode attempts to URL decode a string
func tryURLDecode(cmd string) string {
	cmd = strings.TrimSpace(cmd)

	// Must contain URL-encoded characters
	if !strings.ContainsAny(cmd, "%") {
		return ""
	}

	decoded := simpleURLDecode(cmd)
	return decoded
}

// simpleURLDecode does basic URL decoding
func simpleURLDecode(s string) string {
	result := s
	result = strings.ReplaceAll(result, "%20", " ")
	result = strings.ReplaceAll(result, "%2F", "/")
	result = strings.ReplaceAll(result, "%3A", ":")
	result = strings.ReplaceAll(result, "%3F", "?")
	result = strings.ReplaceAll(result, "%3D", "=")
	result = strings.ReplaceAll(result, "%26", "&")
	result = strings.ReplaceAll(result, "%27", "'")
	result = strings.ReplaceAll(result, "%22", "\"")
	result = strings.ReplaceAll(result, "%3C", "<")
	result = strings.ReplaceAll(result, "%3E", ">")
	result = strings.ReplaceAll(result, "%5C", "\\")
	result = strings.ReplaceAll(result, "%2D", "-")
	result = strings.ReplaceAll(result, "%5F", "_")
	result = strings.ReplaceAll(result, "%2E", ".")
	result = strings.ReplaceAll(result, "%2B", "+")
	result = strings.ReplaceAll(result, "%24", "$")
	result = strings.ReplaceAll(result, "%40", "@")
	result = strings.ReplaceAll(result, "%23", "#")
	// Handle %XX hex sequences
	for i := 0; i < len(result)-2; i++ {
		if result[i] == '%' {
			hex := result[i+1 : i+3]
			if data, err := decodeHex(hex); err == nil && len(data) == 1 {
				result = result[:i] + string(data[0]) + result[i+3:]
				i-- // recheck from the new position
			}
		}
	}
	return result
}

// extractCommands extracts all unique tool/command names from a shell command
func extractCommands(cmd string) []string {
	// Common security tools to look for
	toolsList := []string{
		"nmap", "sqlmap", "gobuster", "ffuf", "dirb", "curl", "wget",
		"nuclei", "httpx", "dnsx", "subfinder", "findomain", "assetfinder",
		"masscan", "nc", "netcat", "socat", "openssl", "whatweb", "wafw00f",
		"gospider", "katana", "hakrawler", "gau", "waybackurls", "paramspider",
		"arjun", "x8", "jq", "xmllint", "hydra", "john",
		"git", "dirsearch", "feroxbuster", "testssl", "sslyze",
		"okenv", "ds_store", "gitdumper", "githacker",
	}

	found := make(map[string]bool)
	lowerCmd := strings.ToLower(cmd)

	for _, tool := range toolsList {
		// Check if tool appears as a standalone word in the command
		patterns := []string{
			" " + tool + " ",
			" " + tool + "\n",
			"|" + tool + " ",
			"&&" + tool + " ",
			tool + " -",
			tool + " --",
		}
		for _, p := range patterns {
			if strings.Contains(lowerCmd, p) {
				found[tool] = true
			}
		}
	}

	result := make([]string, 0, len(found))
	for t := range found {
		result = append(result, t)
	}

	// Also check if the command starts with a known tool
	cmdTrimmed := strings.TrimSpace(lowerCmd)
	for _, tool := range toolsList {
		if (strings.HasPrefix(cmdTrimmed, tool+" ") || cmdTrimmed == tool) && !found[tool] {
			found[tool] = true
			result = append(result, tool)
		}
	}

	return result
}

// checkObfuscation detects common obfuscation techniques
func checkObfuscation(cmd string) string {
	lower := strings.ToLower(cmd)

	// Check for character substitution obfuscation
	// e.g., c'h'o'p, r\m -rf, etc.
	obfuscationPatterns := []struct {
		pattern string
		reason  string
	}{
		{"chr\\s*\\(", "character code obfuscation"},
		{"\\\\x[0-9a-f]{2}", "hex escape obfuscation"},
	}

	for _, op := range obfuscationPatterns {
		if matched, _ := regexp.MatchString(op.pattern, lower); matched {
			return "obfuscated command detected: " + op.reason
		}
	}

	return ""
}
