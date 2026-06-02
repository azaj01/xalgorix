package agent

// Integration tests for spec scope-guard-local-only, task 3.9.
//
// These tests exercise the agent guard end-to-end across the
// boundary that matters for the bugfix: gate verdict → tool registry
// dispatch → event-channel emission. They live alongside the unit
// tests in agent_scope_test.go so they share the same package
// privacy (a.registry, a.events, a.shouldBlockForOutOfScope are all
// unexported).
//
// Why a dispatch-level harness instead of a real LLM:
//
// The production agent loop in (*Agent).Run wires three pieces
// together for every tool call the LLM emits:
//
//   1. shouldBlockForOutOfScope(name, args)            (the gate)
//   2. a.registry.Execute(name, args) on allow         (the dispatch)
//   3. a.emit(Event{Type:"tool_call"|"tool_result"})   (the events)
//
// Driving the loop with a real LLM is not viable in a unit-test
// suite (no API key, no determinism, no offline reproducibility),
// so this file replays steps 1–3 directly against the same state
// (a.registry, a.events) the production loop touches. The ordering
// and event types mirror the corresponding lines in agent.go's
// dispatch path (see internal/agent/agent.go ~line 1465: the
// shouldBlockForOutOfScope branch). What we lose is the LLM
// round-trip itself; what we keep is every observable behavior
// the spec's requirements pin: gate verdict, args byte-identity at
// the registered tool handler, OUT-OF-SCOPE message on the event
// channel, agent loop continues (modeled as: harness returns
// without panicking and the next dispatch still works).
//
// Each test below documents which production lines it mirrors.

import (
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/config"
	"github.com/xalgord/xalgorix/v4/internal/scanctx"
	"github.com/xalgord/xalgorix/v4/internal/scopeguard"
	"github.com/xalgord/xalgorix/v4/internal/tools"
)

// dispatchOutcome captures everything the integration tests need to
// observe from one synthetic tool-call dispatch: the gate verdict,
// the args the registered tool handler saw (or nil if the handler
// was never invoked), and every event the harness emitted on the
// agent's event channel.
type dispatchOutcome struct {
	blocked bool
	reason  string
	events  []Event
}

// dispatchToolCall replays the (*Agent).Run gate-and-dispatch path
// for a single tool call without invoking the LLM. Mirrors the
// production lines in internal/agent/agent.go:
//
//   - shouldBlockForOutOfScope(name, args)    (line ~1466)
//   - emit("tool_call") + emit("tool_result") with
//     "OUT-OF-SCOPE TARGET BLOCKED — …" output  (lines ~1467–1469)
//   - registry.Execute(name, args) on allow    (line ~1502)
//   - emit("tool_call") + emit("tool_result")  (lines ~1499, 1509)
//
// Returns the outcome for the caller to assert against. Callers
// MUST drain a.events into outcome.events before asserting; this
// helper does that for them, so a.events must be a buffered channel
// sized large enough to hold every event without blocking.
func dispatchToolCall(t *testing.T, a *Agent, toolName string, toolArgs map[string]string) dispatchOutcome {
	t.Helper()
	outcome := dispatchOutcome{}

	blocked, reason := a.shouldBlockForOutOfScope(toolName, toolArgs)
	outcome.blocked = blocked
	outcome.reason = reason

	if blocked {
		blockMsg := "⛔ OUT-OF-SCOPE TARGET BLOCKED — " + reason
		a.emit(Event{Type: "tool_call", ToolName: toolName, ToolArgs: toolArgs})
		a.emit(Event{Type: "tool_result", ToolName: toolName, ToolResult: tools.Result{Output: blockMsg}})
	} else {
		a.emit(Event{Type: "tool_call", ToolName: toolName, ToolArgs: toolArgs})
		res, err := a.registry.Execute(toolName, toolArgs)
		if err != nil {
			res = tools.Result{Error: err.Error()}
		}
		a.emit(Event{Type: "tool_result", ToolName: toolName, ToolResult: res})
	}

	// Drain whatever the harness emitted. The caller-supplied
	// event channel must be buffered so emit never blocks.
	for {
		select {
		case ev := <-a.events:
			outcome.events = append(outcome.events, ev)
		default:
			return outcome
		}
	}
}

// newIntegrationAgent constructs an Agent through the standard
// harness (the same agent.NewAgent call site internal/web/server.go
// uses at server.go:3508) and returns it together with its event
// channel. The caller can then override registered tool handlers on
// a.registry to capture invocations without actually running the
// real terminal / python / browser code.
//
// listenerPort is forwarded to the localGuard so the
// self-listener rule fires for `127.0.0.1:<listenerPort>` references.
// scope is forwarded via SetActivityPolicy; pass nil for empty scope
// (Requirement 3.7 cross-check).
func newIntegrationAgent(t *testing.T, listenerPort int, scope []string) (*Agent, chan Event) {
	t.Helper()
	cfg := &config.Config{
		MaxIterations: 1,
		BindAddr:      "127.0.0.1",
		SkillsDir:     t.TempDir(),
	}
	events := make(chan Event, 64)
	sctx := scanctx.New(t.Name(), t.TempDir())
	t.Cleanup(func() { sctx.Close() })

	a := NewAgent(cfg, "integration-agent", events, scopeguard.Config{
		BindAddr: "127.0.0.1",
		Port:     listenerPort,
	}, sctx)
	t.Cleanup(func() { a.Stop() })

	a.SetActivityPolicy("active", "active", scope)
	return a, events
}

// captureTool replaces a registered tool's Execute callback with a
// capture function that records the args it received (byte-identical
// to the args the registry passes through) and returns a fixed
// success result. Returns a pointer to the captured args so the
// caller can compare against the original request.
//
// Mirrors the registered-tool-handler observation point in
// (*Registry).Execute (internal/tools/registry.go ~line 187) — the
// registry copies the caller's args into its localArgs map, then
// invokes tool.Execute(localArgs). Capturing localArgs there is
// equivalent to capturing exactly what the production tool's
// Execute callback would see.
func captureTool(t *testing.T, a *Agent, toolName string) *map[string]string {
	t.Helper()
	captured := make(map[string]string)
	tool, ok := a.registry.Get(toolName)
	if !ok {
		t.Fatalf("tool %q not registered on agent — newIntegrationAgent must call NewAgent", toolName)
	}
	wrapped := *tool
	wrapped.Execute = func(args map[string]string) (tools.Result, error) {
		// Copy on capture so a later mutation of the caller's map
		// can't retroactively change what the test observes.
		for k, v := range args {
			captured[k] = v
		}
		return tools.Result{Output: "captured-by-test"}, nil
	}
	a.registry.Register(&wrapped)
	return &captured
}

// findEvent returns the first event matching the given Type and
// (optional) ToolName, or the zero Event with ok=false if none is
// present.
func findEvent(events []Event, evtType, toolName string) (Event, bool) {
	for _, ev := range events {
		if ev.Type != evtType {
			continue
		}
		if toolName != "" && ev.ToolName != toolName {
			continue
		}
		return ev, true
	}
	return Event{}, false
}

// containsRejectionMessage returns true if any tool_result event in
// events carries the OUT-OF-SCOPE TARGET BLOCKED prefix on its
// Output field. Mirrors the production rejection text emitted at
// internal/agent/agent.go ~line 1468.
func containsRejectionMessage(events []Event) bool {
	for _, ev := range events {
		if ev.Type != "tool_result" {
			continue
		}
		out := ev.ToolResult.Output
		if len(out) >= len("⛔ OUT-OF-SCOPE TARGET BLOCKED") &&
			out[:len("⛔ OUT-OF-SCOPE TARGET BLOCKED")] == "⛔ OUT-OF-SCOPE TARGET BLOCKED" {
			return true
		}
	}
	return false
}

// ────────────────────────────────────────────────────────────────
// Test 1 — OOS pass-through
// ────────────────────────────────────────────────────────────────

// TestIntegration_OOSPassThrough drives the full
// gate→dispatch→emit chain for a Gated_Tool call referencing a
// Public_OOS_Host (`oos.example`) while Activity_Hosts is
// `{pentest-ground.com}`. Asserts:
//
//   - The gate allows the call (Property 1).
//   - The registered tool handler receives args byte-identical to
//     the LLM-provided input (Requirement 2.1, 2.2).
//   - No OUT-OF-SCOPE TARGET BLOCKED event appears on the event
//     channel.
//
// This is the inverted successor to the pre-fix behavior where
// terminal_execute against `oos.example` was rejected as `not in
// scope`.
//
// Validates: Requirements 2.1, 2.2.
func TestIntegration_OOSPassThrough(t *testing.T) {
	a, _ := newIntegrationAgent(t, 9000, []string{"https://pentest-ground.com"})
	captured := captureTool(t, a, "terminal_execute")

	args := map[string]string{
		"command": "curl https://oos.example/dump",
	}
	before := cloneArgs(args)
	outcome := dispatchToolCall(t, a, "terminal_execute", args)

	if outcome.blocked {
		t.Fatalf("OOS pass-through: gate rejected Public_OOS_Host (Req 2.1, 2.2), reason=%q", outcome.reason)
	}
	if !argsEqual(args, before) {
		t.Fatalf("args mutated by gate or dispatch:\n  before=%v\n  after =%v", before, args)
	}
	if !argsEqual(*captured, before) {
		t.Fatalf("registered tool handler saw mutated args:\n  expected=%v\n  got     =%v", before, *captured)
	}
	if containsRejectionMessage(outcome.events) {
		t.Fatalf("OUT-OF-SCOPE rejection event emitted on the websocket channel for an allowed call")
	}
	if _, ok := findEvent(outcome.events, "tool_call", "terminal_execute"); !ok {
		t.Errorf("tool_call event for terminal_execute not emitted")
	}
}

// ────────────────────────────────────────────────────────────────
// Test 2 — Local block
// ────────────────────────────────────────────────────────────────

// TestIntegration_LocalBlock drives the full
// gate→dispatch→emit chain for a Gated_Tool call against
// `127.0.0.1:<listenerPort>` while Activity_Hosts is
// `{pentest-ground.com}`. Asserts:
//
//   - The gate rejects the call (Requirement 3.1, 3.4).
//   - The registered tool handler is NOT invoked (preservation of
//     Local_Or_Listener_Host blocking).
//   - The OUT-OF-SCOPE TARGET BLOCKED event is emitted on the
//     event channel.
//   - The agent loop continues — modeled as: a subsequent allowed
//     dispatch still works after the rejection.
//
// Validates: Requirements 3.1, 3.4.
func TestIntegration_LocalBlock(t *testing.T) {
	const listenerPort = 9000
	a, _ := newIntegrationAgent(t, listenerPort, []string{"https://pentest-ground.com"})
	captured := captureTool(t, a, "terminal_execute")

	args := map[string]string{
		"command": "curl http://127.0.0.1:9000/admin",
	}
	before := cloneArgs(args)
	outcome := dispatchToolCall(t, a, "terminal_execute", args)

	if !outcome.blocked {
		t.Fatalf("Requirement 3.1/3.4: 127.0.0.1:%d MUST reject, got allow", listenerPort)
	}
	if outcome.reason == "" {
		t.Errorf("rejected but reason empty")
	}
	if len(*captured) != 0 {
		t.Fatalf("rejected tool reached the registered handler — captured=%v", *captured)
	}
	if !argsEqual(args, before) {
		t.Fatalf("args mutated under rejection:\n  before=%v\n  after =%v", before, args)
	}
	if !containsRejectionMessage(outcome.events) {
		t.Fatalf("expected OUT-OF-SCOPE TARGET BLOCKED event on the websocket channel; got events=%v", outcome.events)
	}

	// Agent-loop-continues sub-assertion: after a rejection the
	// next dispatch must still succeed end-to-end. We pick an
	// in-scope target so the gate allows it; if the harness or
	// registry got into a degraded state the second dispatch
	// would fail.
	args2 := map[string]string{"command": "curl https://pentest-ground.com/"}
	out2 := dispatchToolCall(t, a, "terminal_execute", args2)
	if out2.blocked {
		t.Fatalf("agent loop did not continue after rejection: subsequent in-scope call blocked: %s", out2.reason)
	}
	if len(*captured) == 0 {
		t.Fatalf("agent loop did not continue: subsequent allowed call never reached registered handler")
	}
}

// ────────────────────────────────────────────────────────────────
// Test 3 — Empty-scope-with-local block
// ────────────────────────────────────────────────────────────────

// TestIntegration_EmptyScopeLocalBlock pins Requirement 3.7's
// parenthetical end-to-end: when Activity_Hosts is empty, a
// Gated_Tool call against `127.0.0.1` is still rejected. This is
// the spec's most subtle preservation guarantee — the
// empty-scope short-circuit no longer covers Local_Or_Listener_Host
// inputs (design.md → "Open Question: Requirement 3.7").
//
// Validates: Requirement 3.7.
func TestIntegration_EmptyScopeLocalBlock(t *testing.T) {
	// scope=nil → activityHosts stays empty.
	a, _ := newIntegrationAgent(t, 0, nil)
	captured := captureTool(t, a, "terminal_execute")

	args := map[string]string{
		"command": "curl http://127.0.0.1/admin",
	}
	before := cloneArgs(args)
	outcome := dispatchToolCall(t, a, "terminal_execute", args)

	if !outcome.blocked {
		t.Fatalf("Requirement 3.7: loopback MUST still block when Activity_Hosts is empty, got allow")
	}
	if outcome.reason == "" {
		t.Errorf("rejected but reason empty")
	}
	if len(*captured) != 0 {
		t.Fatalf("rejected tool reached the registered handler — captured=%v", *captured)
	}
	if !argsEqual(args, before) {
		t.Fatalf("args mutated under rejection:\n  before=%v\n  after =%v", before, args)
	}
	if !containsRejectionMessage(outcome.events) {
		t.Fatalf("expected OUT-OF-SCOPE TARGET BLOCKED event on the websocket channel; got events=%v", outcome.events)
	}
}

// ────────────────────────────────────────────────────────────────
// Test 4 — add_note pass-through across iterations
// ────────────────────────────────────────────────────────────────

// TestIntegration_AddNotePassThroughAcrossIterations asserts the
// post-fix end-to-end contract for `add_note` carrying OOS-host
// text in `key` / `value`:
//
//  1. The gate is non-gated for add_note → the call passes through.
//  2. The registered add_note handler receives `key` / `value`
//     byte-identical to the LLM-provided input (no redaction).
//  3. On the next "iteration" — modeled as a follow-up
//     `read_notes` dispatch on the same agent — the persisted
//     text is byte-identical to what was stored.
//
// The first add_note → read_notes round-trip exercises the same
// notes-store the production tool uses (per-scanctx note store
// keyed off a.scanCtx.ID), so the byte-identity assertion is
// against real persistence, not a stub.
//
// Validates: Requirement 2.4.
func TestIntegration_AddNotePassThroughAcrossIterations(t *testing.T) {
	a, _ := newIntegrationAgent(t, 0, []string{"https://pentest-ground.com"})

	const key = "leak_oos.example"
	const value = "saw https://evil.example/dump"

	// Iteration 1: add_note with OOS-host text in both fields.
	addArgs := map[string]string{
		"key":   key,
		"value": value,
	}
	before := cloneArgs(addArgs)
	out1 := dispatchToolCall(t, a, "add_note", addArgs)
	if out1.blocked {
		t.Fatalf("Requirement 2.4: add_note MUST bypass the gate, got blocked: %s", out1.reason)
	}
	if !argsEqual(addArgs, before) {
		t.Fatalf("add_note args mutated by gate/dispatch:\n  before=%v\n  after =%v", before, addArgs)
	}
	tr, ok := findEvent(out1.events, "tool_result", "add_note")
	if !ok {
		t.Fatalf("add_note tool_result event missing")
	}
	if tr.ToolResult.Error != "" {
		t.Fatalf("add_note returned error: %s", tr.ToolResult.Error)
	}

	// Iteration 2 (a): read_notes with the explicit key returns the
	// byte-identical value the LLM stored. The notes tool formats a
	// keyed read as just the raw value (internal/tools/notes/notes.go
	// readNotesForContext key-branch), so the assertion is direct
	// equality, not a substring check.
	readKeyedArgs := map[string]string{"key": key}
	out2 := dispatchToolCall(t, a, "read_notes", readKeyedArgs)
	if out2.blocked {
		t.Fatalf("read_notes is non-gated and MUST bypass the gate, got blocked: %s", out2.reason)
	}
	res, ok := findEvent(out2.events, "tool_result", "read_notes")
	if !ok {
		t.Fatalf("read_notes tool_result event missing")
	}
	if res.ToolResult.Error != "" {
		t.Fatalf("read_notes returned error: %s", res.ToolResult.Error)
	}
	if res.ToolResult.Output != value {
		t.Fatalf("read_notes(key=%q) returned non-byte-identical value:\n  want=%q\n  got =%q",
			key, value, res.ToolResult.Output)
	}

	// Iteration 2 (b): read_notes with no key returns a formatted
	// dump of every stored note. Both the OOS-host key and the
	// OOS-host value must appear byte-identical inside the dump,
	// confirming the key field also round-trips without any
	// redaction wiring firing.
	readAllArgs := map[string]string{}
	out3 := dispatchToolCall(t, a, "read_notes", readAllArgs)
	if out3.blocked {
		t.Fatalf("read_notes (no key) MUST bypass the gate, got blocked: %s", out3.reason)
	}
	resAll, ok := findEvent(out3.events, "tool_result", "read_notes")
	if !ok {
		t.Fatalf("read_notes (no key) tool_result event missing")
	}
	if resAll.ToolResult.Error != "" {
		t.Fatalf("read_notes (no key) returned error: %s", resAll.ToolResult.Error)
	}
	if !containsSubstring(resAll.ToolResult.Output, key) {
		t.Fatalf("read_notes (no key) dump missing the original key byte-identical:\n  want substring=%q\n  got output=%q",
			key, resAll.ToolResult.Output)
	}
	if !containsSubstring(resAll.ToolResult.Output, value) {
		t.Fatalf("read_notes (no key) dump missing the original value byte-identical:\n  want substring=%q\n  got output=%q",
			value, resAll.ToolResult.Output)
	}
}

// containsSubstring is a tiny helper that avoids pulling strings
// into the imports just for one Contains call. The integration
// tests already use Contains via the standard library elsewhere,
// but local use here keeps the helper close to the assertion.
func containsSubstring(haystack, needle string) bool {
	if len(needle) == 0 {
		return true
	}
	if len(needle) > len(haystack) {
		return false
	}
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
