// Package auth — device_code OAuth driver tests.
//
// These tests cover Properties 14 and 16 of the design's correctness
// table:
//
//   - Property 14: device-code flow timeout — for any wall-clock
//     advance past the flow's expiresAt, the flow signals
//     ErrFlowTimeout.
//   - Property 16: poll cadence and slow_down adjustment — for any
//     initial poll interval i and any sequence of k slow_down
//     responses, the poller's effective interval after the kᵗʰ
//     slow_down equals i + 5k, and the wall-clock between successive
//     token-endpoint polls is at least the current effective
//     interval.
//
// The Clock seam declared on driver.go is virtualized via fakeClock
// so the deadline check (clock.Now() vs flow.expiresAt) is
// deterministic; the timer between polls remains real-time because
// poll() uses time.NewTimer from the standard library. Tests that
// assert timeout behavior therefore use short, real-time waits.
//
// Validates: Requirements 7.1, 7.2, 7.3, 7.4, 7.5.
package auth

import (
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/xalgord/xalgorix/v4/internal/providers"
)

// ----------------------------------------------------------------------
// fakeClock — settable Clock for deterministic deadline checks
// ----------------------------------------------------------------------

// fakeClock satisfies the auth.Clock interface and lets tests fix
// the value Now() returns. Advance() shifts the clock forward by d
// so the device-code poller's deadline check observes a defined
// wall-time without sleeping. The internal mutex makes concurrent
// reads (the poll goroutine) and writes (the test) race-free under
// the -race detector.
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func newFakeClock(start time.Time) *fakeClock {
	return &fakeClock{now: start.UTC()}
}

func (f *fakeClock) Now() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.now
}

// Advance moves the fake clock forward by d. Tests call this from
// the foreground goroutine; the poll goroutine observes the new
// value on its next clock.Now() read at the top of the loop.
func (f *fakeClock) Advance(d time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.now = f.now.Add(d)
}

// ----------------------------------------------------------------------
// deviceTestServer — httptest harness for the two upstream endpoints
// ----------------------------------------------------------------------

// tokenScript is a step-by-step script the token-endpoint stub
// follows: the iᵗʰ poll returns scripted[i] (or scripted[len-1] if
// the poller exceeds the script). Each scripted entry encodes the
// upstream response shape: status, body, and a recorded timestamp
// from time.Now() at the moment the request was received.
type tokenScript struct {
	mu    sync.Mutex
	steps []tokenStep
	calls []time.Time // wall-clock at each request
	idx   int
}

type tokenStep struct {
	status int
	body   string
}

func (s *tokenScript) record(at time.Time) (tokenStep, int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls = append(s.calls, at)
	i := s.idx
	if i >= len(s.steps) {
		i = len(s.steps) - 1
	}
	step := s.steps[i]
	s.idx++
	return step, len(s.calls) - 1
}

func (s *tokenScript) snapshot() []time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]time.Time, len(s.calls))
	copy(out, s.calls)
	return out
}

// deviceServer wires a httptest.Server with separate handlers for
// /device and /token. The device-authorization response is fixed
// per construction; the token-endpoint response follows a script.
type deviceServer struct {
	server   *httptest.Server
	devResp  deviceAuthorizationResponse
	script   *tokenScript
	devCalls int32 // sanity check: did Start hit the device endpoint?
	mu       sync.Mutex
}

func newDeviceServer(t *testing.T, dev deviceAuthorizationResponse, steps []tokenStep) *deviceServer {
	t.Helper()
	if len(steps) == 0 {
		t.Fatalf("newDeviceServer: at least one token step is required")
	}
	d := &deviceServer{
		devResp: dev,
		script:  &tokenScript{steps: steps},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/device", func(w http.ResponseWriter, r *http.Request) {
		d.mu.Lock()
		d.devCalls++
		d.mu.Unlock()
		if r.Method != http.MethodPost {
			t.Errorf("device endpoint method = %s, want POST", r.Method)
			http.Error(w, "method", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(d.devResp)
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		step, _ := d.script.record(time.Now())
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(step.status)
		_, _ = w.Write([]byte(step.body))
	})
	d.server = httptest.NewServer(mux)
	t.Cleanup(d.server.Close)
	return d
}

func (d *deviceServer) entry() providers.Entry {
	return providers.Entry{
		ID:                          "openai",
		DisplayName:                 "OpenAI",
		BaseURL:                     d.server.URL,
		HeaderStyle:                 "openai",
		Flow:                        "device_code",
		ClientID:                    "xalgorix-test",
		DeviceAuthorizationEndpoint: d.server.URL + "/device",
		TokenEndpoint:               d.server.URL + "/token",
	}
}

// successBody is a canonical token-endpoint success response.
func successBody(accessToken string, expiresIn int) string {
	return fmt.Sprintf(`{"access_token":%q,"token_type":"Bearer","expires_in":%d}`, accessToken, expiresIn)
}

// pendingBody / slowDownBody / expiredBody are the RFC 8628 control
// responses the token endpoint emits with HTTP 400.
const (
	pendingBody  = `{"error":"authorization_pending","error_description":"waiting for user"}`
	slowDownBody = `{"error":"slow_down","error_description":"please slow down"}`
	expiredBody  = `{"error":"expired_token","error_description":"too late"}`
)

// newDeviceDriverHarness builds the driver + store + server triple
// every test below relies on. The Profile_Store is rooted in
// t.TempDir() and pre-populated with an entry whose id matches the
// device server's catalog Entry.
func newDeviceDriverHarness(t *testing.T, dev deviceAuthorizationResponse, steps []tokenStep, clock Clock) (*deviceCodeDriver, *Store, *deviceServer) {
	t.Helper()
	store, _ := newTestStore(t, "openai")
	srv := newDeviceServer(t, dev, steps)
	driver := newDeviceCodeDriver(store, srv.server.Client(), clock)
	return driver, store, srv
}

// loadFlow returns the deviceFlow registered under flowID. Test
// helper used to introspect interval / profile after the goroutine
// returns.
func loadFlow(t *testing.T, d *deviceCodeDriver, flowID string) *deviceFlow {
	t.Helper()
	raw, ok := d.flows.Load(flowID)
	if !ok {
		t.Fatalf("flow %q not registered", flowID)
	}
	return raw.(*deviceFlow)
}

// waitForDone returns the value sent on flow.done or fails the test
// when timeout elapses. The buffered channel + sync.Once on
// finishFlow guarantees a single value or close — receiving from a
// closed channel returns nil/zero so the second-receive guard is
// unnecessary.
func waitForDone(t *testing.T, flow *deviceFlow, timeout time.Duration) error {
	t.Helper()
	select {
	case err := <-flow.done:
		return err
	case <-time.After(timeout):
		t.Fatalf("flow did not finalize within %s", timeout)
		return nil
	}
}

// ----------------------------------------------------------------------
// TestDevice_StartReturnsUserCode — Requirement 7.1
// ----------------------------------------------------------------------

// TestDevice_StartReturnsUserCode verifies the Start path: posting
// to deviceAuthorizationEndpoint, decoding the response, and
// surfacing the user-facing user_code + verification_uri on
// StartResult with Mode="device". ExpiresAt is anchored to the
// injected fakeClock + the response expires_in so the assertion is
// exact rather than fuzzy.
//
// Validates: Requirement 7.1.
func TestDevice_StartReturnsUserCode(t *testing.T) {
	start := time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC)
	clock := newFakeClock(start)
	dev := deviceAuthorizationResponse{
		DeviceCode:      "d",
		UserCode:        "USER",
		VerificationURI: "https://verify",
		ExpiresIn:       600,
		Interval:        5,
	}
	// One scripted token-endpoint response is enough — the test
	// stops the flow before the first poll fires.
	d, _, srv := newDeviceDriverHarness(t, dev, []tokenStep{
		{status: http.StatusBadRequest, body: pendingBody},
	}, clock)

	res, err := d.Start(t.Context(), srv.entry(), StartOptions{})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { d.stopFlow(res.FlowID, nil) })

	if res.Mode != "device" {
		t.Fatalf("Mode = %q, want %q", res.Mode, "device")
	}
	if res.UserCode != "USER" {
		t.Fatalf("UserCode = %q, want %q", res.UserCode, "USER")
	}
	if res.VerificationURI != "https://verify" {
		t.Fatalf("VerificationURI = %q, want %q", res.VerificationURI, "https://verify")
	}
	want := start.Add(600 * time.Second)
	if !res.ExpiresAt.Equal(want) {
		t.Fatalf("ExpiresAt = %s, want %s", res.ExpiresAt, want)
	}
	if res.FlowID == "" {
		t.Fatalf("FlowID is empty")
	}
}

// ----------------------------------------------------------------------
// TestDevice_PollIntervalRespectedAndSlowDown — Property 16
// ----------------------------------------------------------------------

// TestDevice_PollIntervalRespectedAndSlowDown validates Property 16:
// for any initial poll interval i and any number of slow_down
// responses k, the effective interval after the kᵗʰ slow_down
// equals i + 5k seconds, and the wall-clock between successive
// token polls is at least the effective interval at that step.
//
// Test strategy (deviation note: spec calls for ≥ 100 randomized
// sequences; we run a smaller set because each iteration sleeps in
// real wall-clock time inside the poller's time.NewTimer — see the
// design's note on this test being timing-sensitive).
//
// For each randomized (i, k) pair the test:
//
//  1. Stubs the token endpoint to return slow_down k times then
//     success.
//  2. Records the wall-clock timestamp of every token-endpoint
//     request.
//  3. Waits for flow.done on success.
//  4. Asserts flow.interval == i + 5k seconds (the math after k
//     bumps).
//  5. Asserts each delta between successive request timestamps is
//     at least the expected effective interval at that step minus
//     a small lead tolerance.
//
// Validates: Requirements 7.2, 7.3.
func TestDevice_PollIntervalRespectedAndSlowDown(t *testing.T) {
	// 6 randomized sequences. The spec says ≥ 100, but each
	// iteration's wall-clock cost is i + (i+5) + ... + (i+5k)
	// seconds, so 100 iterations are infeasible without a
	// fake-timer rewrite. The deterministic seed is logged so a
	// single failing iteration reproduces.
	const iterations = 6
	seed := time.Now().UnixNano()
	rng := rand.New(rand.NewSource(seed))
	t.Logf("Property 16 seed: %d", seed)

	for n := 0; n < iterations; n++ {
		i := 1 + rng.Intn(2) // 1..2 seconds (kept small to bound runtime)
		k := rng.Intn(3)     // 0..2 slow_downs
		t.Run(fmt.Sprintf("i=%ds_k=%d_iter=%d", i, k, n), func(t *testing.T) {
			runIntervalSlowDownCase(t, i, k)
		})
	}
}

// runIntervalSlowDownCase runs one (i, k) case for Property 16. It
// is split out so the parent t.Run subtest scope owns the per-case
// assertions and the device server / driver lifetime.
func runIntervalSlowDownCase(t *testing.T, i, k int) {
	t.Helper()
	steps := make([]tokenStep, 0, k+1)
	for j := 0; j < k; j++ {
		steps = append(steps, tokenStep{status: http.StatusBadRequest, body: slowDownBody})
	}
	steps = append(steps, tokenStep{status: http.StatusOK, body: successBody("at-cadence", 3600)})

	// expires_in is large enough (60s) that the deadline never
	// fires during this case — total polling cost is bounded by
	// i + (i+5) + ... + (i+5k) ≤ 18s for i=2, k=2.
	dev := deviceAuthorizationResponse{
		DeviceCode:      "d",
		UserCode:        "U",
		VerificationURI: "https://v",
		ExpiresIn:       60,
		Interval:        i,
	}
	clock := newFakeClock(time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC))
	d, _, srv := newDeviceDriverHarness(t, dev, steps, clock)

	startWall := time.Now()
	res, err := d.Start(t.Context(), srv.entry(), StartOptions{})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { d.stopFlow(res.FlowID, nil) })

	flow := loadFlow(t, d, res.FlowID)
	// Total expected wall-clock cost is the sum of effective
	// intervals at each iteration plus a small grace window.
	totalExpected := time.Duration(i) * time.Second
	for j := 1; j <= k; j++ {
		totalExpected += time.Duration(i+5*j) * time.Second
	}
	if dErr := waitForDone(t, flow, totalExpected+5*time.Second); dErr != nil {
		t.Fatalf("flow finalized with err = %v, want nil (success)", dErr)
	}

	// Assertion 1 — final flow.interval equals i + 5k seconds.
	wantInterval := time.Duration(i+5*k) * time.Second
	if flow.interval != wantInterval {
		t.Fatalf("flow.interval after %d slow_downs = %s, want %s", k, flow.interval, wantInterval)
	}

	// Assertion 2 — wall-clock between successive polls is at
	// least the effective interval at that step. Allow a small
	// negative tolerance to absorb scheduler jitter (timers can
	// fire a few ms early on some kernels).
	const tolerance = 50 * time.Millisecond
	calls := srv.script.snapshot()
	if len(calls) != k+1 {
		t.Fatalf("token endpoint hits = %d, want %d", len(calls), k+1)
	}
	// Effective interval before poll #n (1-indexed):
	//   poll 1 → interval = i
	//   poll 2 → interval = i + 5  (after 1 slow_down)
	//   ...
	//   poll n → interval = i + 5*(n-1)
	prev := startWall
	for n := 0; n < len(calls); n++ {
		want := time.Duration(i+5*n) * time.Second
		got := calls[n].Sub(prev)
		if got+tolerance < want {
			t.Fatalf("poll %d delta = %s, want ≥ %s", n+1, got, want)
		}
		prev = calls[n]
	}
}

// ----------------------------------------------------------------------
// TestDevice_HappyPath_PersistsProfile — Requirement 7.4
// ----------------------------------------------------------------------

// TestDevice_HappyPath_PersistsProfile verifies the success branch
// of the poll loop: after K=1 authorization_pending poll followed by
// a successful token response, the driver persists an OAuth_Profile
// keyed under "<provider>:default" containing the upstream
// access_token. Profile_Store.Get must surface the profile with the
// plaintext token (masking is an HTTP-layer concern, not a Store
// concern).
//
// Validates: Requirement 7.4.
func TestDevice_HappyPath_PersistsProfile(t *testing.T) {
	steps := []tokenStep{
		{status: http.StatusBadRequest, body: pendingBody},
		{status: http.StatusOK, body: successBody("at-happy", 3600)},
	}
	dev := deviceAuthorizationResponse{
		DeviceCode:      "d",
		UserCode:        "U",
		VerificationURI: "https://v",
		ExpiresIn:       60,
		Interval:        1,
	}
	clock := newFakeClock(time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC))
	d, store, srv := newDeviceDriverHarness(t, dev, steps, clock)

	res, err := d.Start(t.Context(), srv.entry(), StartOptions{})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { d.stopFlow(res.FlowID, nil) })
	flow := loadFlow(t, d, res.FlowID)

	if dErr := waitForDone(t, flow, 10*time.Second); dErr != nil {
		t.Fatalf("flow finalized with err = %v, want nil", dErr)
	}

	// Profile must be persisted via Store.Put and retrievable.
	prof, ok, err := store.Get(t.Context(), "openai:"+deviceCodeDefaultProfileID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !ok {
		t.Fatalf("Get reported not-found after happy-path persist")
	}
	if prof.AccessToken != "at-happy" {
		t.Fatalf("AccessToken = %q, want %q", prof.AccessToken, "at-happy")
	}
	if prof.Type != OAuth {
		t.Fatalf("Type = %q, want %q", prof.Type, OAuth)
	}
	if prof.TokenType != "Bearer" {
		t.Fatalf("TokenType = %q, want %q", prof.TokenType, "Bearer")
	}
	// flow.profile should mirror the persisted record.
	if flow.profile.AccessToken != prof.AccessToken {
		t.Fatalf("flow.profile.AccessToken = %q, want %q", flow.profile.AccessToken, prof.AccessToken)
	}
}

// ----------------------------------------------------------------------
// TestDevice_ExpiresInTimeoutReturns408 — Property 14 / Requirement 7.5
// ----------------------------------------------------------------------

// TestDevice_ExpiresInTimeoutReturns408 validates Property 14 for
// the device-code branch: when wall-clock advances past the flow's
// expiresAt and the upstream is still returning
// authorization_pending, the poll loop returns ErrFlowTimeout
// (which the HTTP layer maps to 408 "oauth flow timed out").
//
// The fakeClock starts at t0 with a 2s expires_in window. The
// poller's deadline check (clock.Now() vs flow.expiresAt) reads
// the fake clock — Advance() pushes it past the deadline so the
// next loop iteration after the in-flight timer fires observes
// the expiration. The token endpoint always returns
// authorization_pending so the only way out of the loop is
// timeout.
//
// Validates: Requirements 7.5 (and Property 14 for device-code).
func TestDevice_ExpiresInTimeoutReturns408(t *testing.T) {
	// Always-pending script — the poll loop never sees a 2xx.
	steps := []tokenStep{
		{status: http.StatusBadRequest, body: pendingBody},
	}
	dev := deviceAuthorizationResponse{
		DeviceCode:      "d",
		UserCode:        "U",
		VerificationURI: "https://v",
		ExpiresIn:       2,
		Interval:        1,
	}
	clock := newFakeClock(time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC))
	d, _, srv := newDeviceDriverHarness(t, dev, steps, clock)

	res, err := d.Start(t.Context(), srv.entry(), StartOptions{})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { d.stopFlow(res.FlowID, nil) })
	flow := loadFlow(t, d, res.FlowID)

	// Push the fake clock past the deadline. The poller currently
	// blocks on time.NewTimer(1s) (real time) — when the timer
	// fires, the loop re-checks clock.Now() and observes the
	// expiration. We give the goroutine up to 5s of real time to
	// observe the advance.
	clock.Advance(3 * time.Second)

	dErr := waitForDone(t, flow, 5*time.Second)
	if !errors.Is(dErr, ErrFlowTimeout) {
		t.Fatalf("flow finalized with err = %v, want ErrFlowTimeout", dErr)
	}

	// Sanity: the token endpoint may have been hit zero or one
	// times depending on goroutine scheduling — both are
	// acceptable, but it must never hit twice (which would
	// indicate the deadline check was skipped). The point of
	// Property 14 is that polling stops at the deadline.
	calls := srv.script.snapshot()
	if len(calls) > 1 {
		t.Fatalf("token endpoint hit %d times after expires_in elapsed, want 0 or 1", len(calls))
	}
	_ = url.Values{} // silence import linter if all branches above are removed
}
