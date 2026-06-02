package scanctx

import (
	"context"
	"errors"
	"log"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"time"
)

// TerminalState provides per-session terminal process tracking,
// replacing the global processGroup and workDir in terminal.go.
type TerminalState struct {
	mu            sync.RWMutex
	processGroup  map[*exec.Cmd]context.CancelFunc
	workDir       string
	activeCommand string
	activeStart   time.Time
	streamCB      func(string)
}

// NewTerminalState creates an empty terminal state.
func NewTerminalState() *TerminalState {
	return &TerminalState{
		processGroup: make(map[*exec.Cmd]context.CancelFunc),
	}
}

// SetWorkDir sets the working directory for this session's terminal commands.
func (ts *TerminalState) SetWorkDir(dir string) {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	ts.workDir = dir
}

// GetWorkDir returns the current working directory.
func (ts *TerminalState) GetWorkDir() string {
	ts.mu.RLock()
	defer ts.mu.RUnlock()
	return ts.workDir
}

// TrackProcess registers a command for this session.
func (ts *TerminalState) TrackProcess(cmd *exec.Cmd, cancel context.CancelFunc, commandStr string) {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	ts.processGroup[cmd] = cancel
	if len(commandStr) > 200 {
		ts.activeCommand = commandStr[:200] + "..."
	} else {
		ts.activeCommand = commandStr
	}
	ts.activeStart = time.Now()
}

// UntrackProcess removes a command from tracking.
func (ts *TerminalState) UntrackProcess(cmd *exec.Cmd) {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	delete(ts.processGroup, cmd)
	if len(ts.processGroup) == 0 {
		ts.activeCommand = ""
	}
}

// ActiveProcessCount returns the number of tracked processes.
func (ts *TerminalState) ActiveProcessCount() int {
	ts.mu.RLock()
	defer ts.mu.RUnlock()
	return len(ts.processGroup)
}

// GetActiveCommand returns the currently running command and duration.
func (ts *TerminalState) GetActiveCommand() (string, time.Duration) {
	ts.mu.RLock()
	defer ts.mu.RUnlock()
	if ts.activeCommand == "" {
		return "", 0
	}
	return ts.activeCommand, time.Since(ts.activeStart)
}

// KillAll kills all processes tracked by this session.
func (ts *TerminalState) KillAll() {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	for cmd, cancel := range ts.processGroup {
		killTrackedProcess(cmd)
		if cancel != nil {
			cancel()
		}
	}
	ts.processGroup = make(map[*exec.Cmd]context.CancelFunc)
	ts.activeCommand = ""
	log.Printf("[termstate] Killed all processes for session")
}

// ReapDead removes exited processes from tracking.
func (ts *TerminalState) ReapDead() int {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	reaped := 0
	for cmd, cancel := range ts.processGroup {
		if cmd.ProcessState != nil && cmd.ProcessState.Exited() {
			delete(ts.processGroup, cmd)
			if cancel != nil {
				cancel()
			}
			reaped++
		}
	}
	if reaped > 0 && len(ts.processGroup) == 0 {
		ts.activeCommand = ""
	}
	return reaped
}

func killTrackedProcess(cmd *exec.Cmd) {
	if cmd == nil || cmd.Process == nil {
		return
	}

	pid := cmd.Process.Pid
	if pgid, err := syscall.Getpgid(pid); err == nil && pgid > 0 {
		selfPGID, selfErr := syscall.Getpgid(os.Getpid())
		if selfErr != nil || pgid != selfPGID {
			if err := syscall.Kill(-pgid, syscall.SIGKILL); err != nil && err != syscall.ESRCH {
				log.Printf("[termstate] Failed to kill process group %d for pid %d: %v", pgid, pid, err)
			}
		} else {
			log.Printf("[termstate] Refusing to kill process group %d for pid %d because it matches xalgorix", pgid, pid)
		}
	}

	if err := cmd.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
		log.Printf("[termstate] Failed to kill process pid %d: %v", pid, err)
	}
}

// SetStreamCallback sets a callback for partial output streaming.
func (ts *TerminalState) SetStreamCallback(cb func(string)) {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	ts.streamCB = cb
}

// ClearStreamCallback removes the stream callback.
func (ts *TerminalState) ClearStreamCallback() {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	ts.streamCB = nil
}

// GetStreamCallback returns the current stream callback (may be nil).
func (ts *TerminalState) GetStreamCallback() func(string) {
	ts.mu.RLock()
	defer ts.mu.RUnlock()
	return ts.streamCB
}
