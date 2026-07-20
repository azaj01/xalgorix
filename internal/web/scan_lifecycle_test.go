package web

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

// A deleted instance (removed from the map mid-run) must be treated as
// interrupted so the queue / subdomain loops stop scanning. Regression for
// issue #239 where deleting a scan left the pipeline running in the background.
func TestInstanceInterrupted_MissingInstanceIsInterrupted(t *testing.T) {
	s := newTestServer(t, nil)

	s.instancesMu.Lock()
	s.instances["run-1"] = &ScanInstance{ID: "run-1", Status: "running"}
	s.instances["stopped-1"] = &ScanInstance{ID: "stopped-1", Status: "stopped"}
	s.instancesMu.Unlock()

	if s.instanceInterrupted("run-1") {
		t.Error("running instance should NOT be interrupted")
	}
	if !s.instanceInterrupted("stopped-1") {
		t.Error("stopped instance should be interrupted")
	}
	if !s.instanceInterrupted("never-existed") {
		t.Error("missing/deleted instance MUST be treated as interrupted")
	}
	if s.instanceInterrupted("") {
		t.Error("empty instance id should not be interrupted")
	}
}

// Deleting a running scan must halt it: cancel the in-flight context, mark the
// instance stopped, remove it from the map, AND delete the persisted queue
// resume file so the startup auto-resume never replays it (issue #239).
func TestHandleDeleteScan_StopsInstanceAndClearsQueueState(t *testing.T) {
	s := newTestServer(t, nil)

	canceled := false
	inst := &ScanInstance{ID: "del-1", Targets: "a.com, b.com", Status: "running"}
	inst.cancel = func() { canceled = true }
	s.instancesMu.Lock()
	s.instances["del-1"] = inst
	s.instancesMu.Unlock()

	// Persist a resume file for this queue (2 targets, still at index 0).
	s.saveQueueState(0, ScanRequest{
		InstanceID: "del-1",
		Targets:    []string{"a.com", "b.com"},
		ScanMode:   "wildcard",
	})
	queuePath := s.queueStatePathForInstance("del-1")
	if _, err := os.Stat(queuePath); err != nil {
		t.Fatalf("precondition: queue state file should exist: %v", err)
	}

	rr := httptest.NewRecorder()
	s.handleGetScan(rr, httptest.NewRequest(http.MethodDelete, "/api/scans/del-1", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("delete code = %d body=%s", rr.Code, rr.Body.String())
	}

	if !canceled {
		t.Error("delete must cancel the running instance's context")
	}
	s.instancesMu.RLock()
	_, stillThere := s.instances["del-1"]
	s.instancesMu.RUnlock()
	if stillThere {
		t.Error("instance should be removed from the map after delete")
	}
	if _, err := os.Stat(queuePath); !os.IsNotExist(err) {
		t.Errorf("queue state file must be removed after delete (err=%v)", err)
	}
}

// Stopping a single instance clears its persisted resume file so the dashboard
// queue counter clears immediately and nothing is auto-resumed.
func TestHandleInstanceStop_ClearsQueueState(t *testing.T) {
	s := newTestServer(t, nil)

	inst := &ScanInstance{ID: "stop-1", Targets: "a.com", Status: "running"}
	inst.cancel = func() {}
	s.instancesMu.Lock()
	s.instances["stop-1"] = inst
	s.instancesMu.Unlock()

	s.saveQueueState(0, ScanRequest{
		InstanceID: "stop-1",
		Targets:    []string{"a.com", "b.com"},
		ScanMode:   "wildcard",
	})
	queuePath := s.queueStatePathForInstance("stop-1")
	if _, err := os.Stat(queuePath); err != nil {
		t.Fatalf("precondition: queue state file should exist: %v", err)
	}

	rr := httptest.NewRecorder()
	s.handleInstanceAction(rr, httptest.NewRequest(http.MethodPost, "/api/instances/stop-1/stop", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("stop code = %d body=%s", rr.Code, rr.Body.String())
	}

	s.instancesMu.RLock()
	got := s.instances["stop-1"]
	s.instancesMu.RUnlock()
	if got == nil || got.Status != "stopped" {
		t.Fatalf("instance should be marked stopped, got %#v", got)
	}
	if _, err := os.Stat(queuePath); !os.IsNotExist(err) {
		t.Errorf("queue state file must be removed after stop (err=%v)", err)
	}
}
