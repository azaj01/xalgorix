// Smoke unit tests for the xalgorix-cloud binary entrypoint.
//
// These tests cover task 0.6 of the xalgorix-saas spec
// (Smoke unit test for the cloud binary entrypoint) and lock down the
// `--mode` dispatch contract called out in Requirement 1.9, which keeps
// the API_Server and Worker_Pool as distinct entry points behind the
// same binary.
//
// The strategy is deliberately minimal: swap the package-level
// runAPI/runWorker/runAll vars (introduced in task 0.1 specifically for
// this purpose) with stubs that record which one was invoked, then call
// run() and assert the right stub fired. We intentionally do not start
// any servers — that is what makes this a smoke test.
//
// All tests run serially (no t.Parallel) because they swap the
// package-level runner vars.
package main

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
)

// runnerCall records whether a stub runner was invoked and what args it
// received. Capturing args lets the dispatch test assert that positional
// args after `--mode` are forwarded to the chosen runner, which matters
// once the real servers grow flag-based configuration.
type runnerCall struct {
	called bool
	args   []string
}

func recordingRunner(call *runnerCall, returnErr error) func(io.Writer, []string) error {
	return func(_ io.Writer, args []string) error {
		call.called = true
		call.args = args
		return returnErr
	}
}

// withRunners swaps runAPI/runWorker/runAll for the duration of a test
// and registers cleanup to restore the originals. This isolates each
// test case from the others.
func withRunners(t *testing.T, api, worker, all func(io.Writer, []string) error) {
	t.Helper()
	origAPI, origWorker, origAll := runAPI, runWorker, runAll
	runAPI, runWorker, runAll = api, worker, all
	t.Cleanup(func() {
		runAPI, runWorker, runAll = origAPI, origWorker, origAll
	})
}

func TestRun_DispatchesByMode(t *testing.T) {
	tests := []struct {
		name       string
		args       []string
		wantAPI    bool
		wantWorker bool
		wantAll    bool
		wantArgs   []string // non-flag args expected to reach the runner
	}{
		{
			name:     "explicit api mode",
			args:     []string{"--mode", "api"},
			wantAPI:  true,
			wantArgs: []string{},
		},
		{
			name:       "explicit worker mode",
			args:       []string{"--mode", "worker"},
			wantWorker: true,
			wantArgs:   []string{},
		},
		{
			name:     "explicit all mode",
			args:     []string{"--mode", "all"},
			wantAll:  true,
			wantArgs: []string{},
		},
		{
			name:     "default mode is api",
			args:     []string{},
			wantAPI:  true,
			wantArgs: []string{},
		},
		{
			name:       "equals form --mode=worker",
			args:       []string{"--mode=worker"},
			wantWorker: true,
			wantArgs:   []string{},
		},
		{
			name:     "extra positional args are forwarded to runner",
			args:     []string{"--mode", "api", "extra", "args"},
			wantAPI:  true,
			wantArgs: []string{"extra", "args"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var apiCall, workerCall, allCall runnerCall
			withRunners(t,
				recordingRunner(&apiCall, nil),
				recordingRunner(&workerCall, nil),
				recordingRunner(&allCall, nil),
			)

			var stdout, stderr bytes.Buffer
			if err := run(tc.args, &stdout, &stderr); err != nil {
				t.Fatalf("run(%v) returned unexpected error: %v\nstderr: %s", tc.args, err, stderr.String())
			}

			if apiCall.called != tc.wantAPI {
				t.Errorf("runAPI called=%v, want %v", apiCall.called, tc.wantAPI)
			}
			if workerCall.called != tc.wantWorker {
				t.Errorf("runWorker called=%v, want %v", workerCall.called, tc.wantWorker)
			}
			if allCall.called != tc.wantAll {
				t.Errorf("runAll called=%v, want %v", allCall.called, tc.wantAll)
			}

			// Exactly one runner must fire on a successful dispatch.
			fired := boolToInt(apiCall.called) + boolToInt(workerCall.called) + boolToInt(allCall.called)
			if fired != 1 {
				t.Fatalf("expected exactly one runner to fire, got %d", fired)
			}

			gotArgs := firstNonNil(apiCall.args, workerCall.args, allCall.args)
			if !equalStringSlice(gotArgs, tc.wantArgs) {
				t.Errorf("forwarded args = %#v, want %#v", gotArgs, tc.wantArgs)
			}
		})
	}
}

func TestRun_InvalidModeReturnsError(t *testing.T) {
	var apiCall, workerCall, allCall runnerCall
	withRunners(t,
		recordingRunner(&apiCall, nil),
		recordingRunner(&workerCall, nil),
		recordingRunner(&allCall, nil),
	)

	var stdout, stderr bytes.Buffer
	err := run([]string{"--mode", "bogus"}, &stdout, &stderr)
	if err == nil {
		t.Fatalf("run(--mode bogus) returned nil error, want error")
	}
	if !strings.Contains(err.Error(), "bogus") {
		t.Errorf("error message %q should mention the offending mode", err.Error())
	}
	if !strings.Contains(err.Error(), "api") ||
		!strings.Contains(err.Error(), "worker") ||
		!strings.Contains(err.Error(), "all") {
		t.Errorf("error message %q should list the valid modes", err.Error())
	}
	if apiCall.called || workerCall.called || allCall.called {
		t.Fatalf("no runner should fire on invalid mode (api=%v worker=%v all=%v)",
			apiCall.called, workerCall.called, allCall.called)
	}
}

func TestRun_UnknownFlagReturnsError(t *testing.T) {
	var apiCall, workerCall, allCall runnerCall
	withRunners(t,
		recordingRunner(&apiCall, nil),
		recordingRunner(&workerCall, nil),
		recordingRunner(&allCall, nil),
	)

	var stdout, stderr bytes.Buffer
	if err := run([]string{"--definitely-not-a-flag"}, &stdout, &stderr); err == nil {
		t.Fatalf("run with unknown flag returned nil error, want error")
	}
	if apiCall.called || workerCall.called || allCall.called {
		t.Fatalf("no runner should fire when flag parsing fails")
	}
}

func TestRun_PropagatesRunnerError(t *testing.T) {
	wantErr := errors.New("api server failed to start")
	var apiCall, workerCall, allCall runnerCall
	withRunners(t,
		recordingRunner(&apiCall, wantErr),
		recordingRunner(&workerCall, nil),
		recordingRunner(&allCall, nil),
	)

	var stdout, stderr bytes.Buffer
	err := run([]string{"--mode", "api"}, &stdout, &stderr)
	if !errors.Is(err, wantErr) {
		t.Fatalf("run() error = %v, want %v", err, wantErr)
	}
	if !apiCall.called {
		t.Fatalf("runAPI should still be invoked even when it returns an error")
	}
}

// --- small local helpers (kept private to the test file) ---

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func equalStringSlice(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// firstNonNil returns the first non-nil slice from the inputs, or an
// empty slice if all are nil. Used so the dispatch test can fish the
// forwarded args out of whichever runner actually fired.
func firstNonNil(slices ...[]string) []string {
	for _, s := range slices {
		if s != nil {
			return s
		}
	}
	return []string{}
}
