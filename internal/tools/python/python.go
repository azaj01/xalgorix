// Package python provides the python_action tool via subprocess.
package python

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/xalgord/xalgorix/v4/internal/config"
	"github.com/xalgord/xalgorix/v4/internal/resources"
	"github.com/xalgord/xalgorix/v4/internal/scanctx"
	"github.com/xalgord/xalgorix/v4/internal/tools"
	"github.com/xalgord/xalgorix/v4/internal/tools/terminal"
)

// Register adds the python_action tool to the registry.
func Register(r *tools.Registry) {
	r.Register(&tools.Tool{
		Name:        "python_action",
		Description: "Execute Python code in a subprocess. Python 3 must be installed.",
		Parameters: []tools.Parameter{
			{Name: "code", Description: "Python code to execute", Required: true},
			{Name: "timeout", Description: "Timeout in seconds (default: 1800 = 30 min)", Required: false},
		},
		Execute: func(args map[string]string) (tools.Result, error) {
			return executePythonForContext(r.GetScanContextID(), args)
		},
	})
}

func executePython(args map[string]string) (tools.Result, error) {
	return executePythonForContext(scanctx.Default().ID, args)
}

func executePythonForContext(contextID string, args map[string]string) (tools.Result, error) {
	if strings.TrimSpace(contextID) == "" {
		contextID = scanctx.Default().ID
	}

	code := args["code"]
	if code == "" {
		return tools.Result{}, fmt.Errorf("code is required")
	}

	timeoutSec := 1800 // 30 minutes — exploit scripts can run long
	if t := args["timeout"]; t != "" {
		parsed, err := strconv.Atoi(strings.TrimSpace(t))
		if err != nil {
			return tools.Result{Error: fmt.Sprintf("invalid timeout value '%s': must be a number in seconds", t)}, nil
		}
		timeoutSec = parsed
		if timeoutSec <= 0 {
			timeoutSec = 1800
		}
		if timeoutSec > 7200 { // Cap at 2 hours
			timeoutSec = 7200
		}
	}

	// Find python3
	pythonBin := "python3"
	if _, err := exec.LookPath(pythonBin); err != nil {
		pythonBin = "python"
		if _, err := exec.LookPath(pythonBin); err != nil {
			return tools.Result{}, fmt.Errorf("python not found. Install python3")
		}
	}

	waitCtx := pythonWaitContext(contextID)
	lease, err := resources.AcquireToolLeaseContext(waitCtx, false, "python_action")
	if err != nil {
		return tools.Result{Output: fmt.Sprintf("[CANCELLED] python_action launch cancelled before starting: %v", err)}, nil
	}
	defer lease.Release()

	ctx, cancel := context.WithTimeout(waitCtx, time.Duration(timeoutSec)*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, pythonBin, "-c", code)
	if wd := terminal.GetWorkDirForContext(contextID); wd != "" {
		cmd.Dir = wd
	} else {
		cmd.Dir = config.Get().Workspace
	}
	cmd.Dir = filepath.Clean(cmd.Dir)
	preparePythonWorkspace(cmd.Dir)
	cmd.Env = pythonWorkspaceEnv(cmd.Dir)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	stdout := newLimitedBuffer(1024 * 1024)
	stderr := newLimitedBuffer(512 * 1024)
	cmd.Stdout = stdout
	cmd.Stderr = stderr

	if err := cmd.Start(); err != nil {
		return tools.Result{Error: fmt.Sprintf("Failed to start python process: %v", err)}, nil
	}
	terminal.ApplyProcessLimitsWithLimit(cmd, true, lease.MemoryLimitBytes())

	// Register with terminal so watchdog knows we are active
	cleanCode := code
	if len(cleanCode) > 100 {
		cleanCode = cleanCode[:100] + "..."
	}
	terminal.TrackProcessForContext(contextID, cmd, cancel, "python: "+strings.ReplaceAll(cleanCode, "\n", " "))
	defer terminal.UntrackProcessForContext(contextID, cmd)

	waitErr := cmd.Wait()

	var b strings.Builder
	if stdout.Len() > 0 {
		out := stdout.String()
		if len(out) > 15000 {
			out = out[:15000] + "\n... [OUTPUT TRUNCATED]"
		}
		b.WriteString(out)
		if stdout.Truncated() {
			b.WriteString("\n... [OUTPUT TRUNCATED: exceeded 1MB]")
		}
	}

	if stderr.Len() > 0 {
		if b.Len() > 0 {
			b.WriteString("\n")
		}
		b.WriteString("STDERR:\n")
		errOut := stderr.String()
		if len(errOut) > 5000 {
			errOut = errOut[:5000] + "\n... [TRUNCATED]"
		}
		b.WriteString(errOut)
		if stderr.Truncated() {
			b.WriteString("\n... [STDERR TRUNCATED: exceeded 512KB]")
		}
	}

	if waitErr != nil {
		if ctx.Err() == context.DeadlineExceeded {
			b.WriteString(fmt.Sprintf("\n[TIMEOUT: exceeded %ds]", timeoutSec))
		} else if exitErr, ok := waitErr.(*exec.ExitError); ok {
			b.WriteString(fmt.Sprintf("\n[exit code: %d]", exitErr.ExitCode()))
		}
	}

	if b.Len() == 0 {
		b.WriteString("(no output)")
	}

	return tools.Result{Output: b.String()}, nil
}

func pythonWaitContext(contextID string) context.Context {
	if sc := scanctx.Get(contextID); sc != nil && sc.Ctx != nil {
		return sc.Ctx
	}
	return context.Background()
}

func preparePythonWorkspace(workDir string) {
	_ = os.MkdirAll(filepath.Join(workDir, ".tmp"), 0o755)
	_ = os.MkdirAll(filepath.Join(workDir, ".cache"), 0o755)
	_ = os.MkdirAll(filepath.Join(workDir, ".config"), 0o755)
	_ = os.MkdirAll(filepath.Join(workDir, ".local", "share"), 0o755)
}

func pythonWorkspaceEnv(workDir string) []string {
	replace := map[string]bool{
		"HOME":                    true,
		"TMPDIR":                  true,
		"XDG_CACHE_HOME":          true,
		"XDG_CONFIG_HOME":         true,
		"XDG_DATA_HOME":           true,
		"XALGORIX_WORKSPACE":      true,
		"PYTHONDONTWRITEBYTECODE": true,
	}
	env := make([]string, 0, len(os.Environ())+7)
	for _, kv := range os.Environ() {
		key, _, ok := strings.Cut(kv, "=")
		if ok && replace[key] {
			continue
		}
		env = append(env, kv)
	}
	return append(env,
		"HOME="+workDir,
		"TMPDIR="+filepath.Join(workDir, ".tmp"),
		"XDG_CACHE_HOME="+filepath.Join(workDir, ".cache"),
		"XDG_CONFIG_HOME="+filepath.Join(workDir, ".config"),
		"XDG_DATA_HOME="+filepath.Join(workDir, ".local", "share"),
		"XALGORIX_WORKSPACE="+workDir,
		"PYTHONDONTWRITEBYTECODE=1",
	)
}

type limitedBuffer struct {
	bytes.Buffer
	limit     int
	truncated bool
}

func newLimitedBuffer(limit int) *limitedBuffer {
	return &limitedBuffer{limit: limit}
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if b.limit <= 0 || b.Len() >= b.limit {
		b.truncated = true
		return len(p), nil
	}
	remaining := b.limit - b.Len()
	if len(p) > remaining {
		b.truncated = true
		_, _ = b.Buffer.Write(p[:remaining])
		return len(p), nil
	}
	_, _ = b.Buffer.Write(p)
	return len(p), nil
}

func (b *limitedBuffer) Truncated() bool {
	return b.truncated
}
