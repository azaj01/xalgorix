// Copyright (c) Xalgorix.
// SPDX-License-Identifier: AGPL-3.0-only

package targets

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/robfig/cron/v3"
)

// fakeRecheckRepo is an in-memory TargetRepo used by every test in this file.
// It records every operation in deterministic order so tests can assert
// the exact sequence of writes the scheduler issued. The map keys are
// `targets.id` strings, which lets a test seed multiple rows and inspect
// the per-target outcome.
type fakeRecheckRepo struct {
	mu       sync.Mutex
	due      []RecheckTarget
	attempts []VerificationAttempt
	// fails records the per-target post-increment counter values that
	// IncrementConsecutiveFails returned, in order. Tests use it to
	// confirm the scheduler observed exactly the values the repo
	// persisted.
	fails        map[string]int
	resets       map[string]time.Time
	unverified   map[string]bool
	listErr      error
	recordErr    error
	incrementErr error
	resetErr     error
	markErr      error
}

func newRecheckRepo() *fakeRecheckRepo {
	return &fakeRecheckRepo{
		fails:      make(map[string]int),
		resets:     make(map[string]time.Time),
		unverified: make(map[string]bool),
	}
}

func (f *fakeRecheckRepo) ListDueRechecks(_ context.Context, _ time.Time) ([]RecheckTarget, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.listErr != nil {
		return nil, f.listErr
	}
	out := make([]RecheckTarget, len(f.due))
	copy(out, f.due)
	return out, nil
}

func (f *fakeRecheckRepo) RecordAttempt(_ context.Context, attempt VerificationAttempt) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.recordErr != nil {
		return f.recordErr
	}
	f.attempts = append(f.attempts, attempt)
	return nil
}

func (f *fakeRecheckRepo) IncrementConsecutiveFails(_ context.Context, targetID string) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.incrementErr != nil {
		return 0, f.incrementErr
	}
	f.fails[targetID]++
	return f.fails[targetID], nil
}

func (f *fakeRecheckRepo) ResetConsecutiveFails(_ context.Context, targetID string, now time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.resetErr != nil {
		return f.resetErr
	}
	f.fails[targetID] = 0
	f.resets[targetID] = now
	return nil
}

func (f *fakeRecheckRepo) MarkUnverified(_ context.Context, targetID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.markErr != nil {
		return f.markErr
	}
	f.unverified[targetID] = true
	return nil
}

// fakeVerifier returns a deterministic outcome from a per-call queue.
// The scheduler invokes Verify exactly once per target per Run pass, so
// queueing N outcomes covers N runs of N targets. A queue underflow
// fails loudly so tests don't accidentally exercise an undefined branch.
type fakeVerifier struct {
	mu       sync.Mutex
	outcomes []verifierOutcome
	calls    []verifierCall
}

type verifierOutcome struct {
	ok  bool
	err error
}

type verifierCall struct {
	host          string
	expectedToken string
}

func (f *fakeVerifier) Verify(_ context.Context, host, expectedToken string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, verifierCall{host: host, expectedToken: expectedToken})
	if len(f.outcomes) == 0 {
		return false, errors.New("fakeVerifier: no queued outcome")
	}
	o := f.outcomes[0]
	f.outcomes = f.outcomes[1:]
	return o.ok, o.err
}

// fakeAuditEmitter captures every emitted event in order so tests can
// assert that exactly one `target_downgraded` event fired per downgraded
// target and nothing else.
type fakeAuditEmitter struct {
	mu      sync.Mutex
	events  []AuditEvent
	emitErr error
}

func (f *fakeAuditEmitter) Emit(_ context.Context, event AuditEvent) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.emitErr != nil {
		return f.emitErr
	}
	f.events = append(f.events, event)
	return nil
}

// validToken is a syntactically valid 32-char base32 value section, used
// to seed RecheckTarget.Token. The full display token reconstructed by
// the scheduler is `xalgorix-site-verification=` + this constant.
const validToken = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

func seedTarget(id string) RecheckTarget {
	return RecheckTarget{
		ID:               id,
		OrgID:            "org-" + id,
		WorkspaceID:      "ws-" + id,
		Host:             id + ".example.com",
		Method:           RecheckMethodDNS,
		Token:            validToken,
		LastVerifiedAt:   time.Now().Add(-8 * 24 * time.Hour),
		ConsecutiveFails: 0,
	}
}

// TestRechecksScheduler_FailThenSuccess covers the "still verified"
// branch from the task spec: 1 failed recheck, then a successful
// recheck on the next pass. The target must not be downgraded and the
// counter must reset to zero.
func TestRechecksScheduler_FailThenSuccess(t *testing.T) {
	t.Parallel()

	repo := newRecheckRepo()
	repo.due = []RecheckTarget{seedTarget("t1")}

	dns := &fakeVerifier{outcomes: []verifierOutcome{
		{ok: false, err: nil}, // first pass: signal missing
	}}
	audit := &fakeAuditEmitter{}

	now := time.Date(2026, 1, 15, 12, 0, 0, 0, time.UTC)
	scheduler, err := NewRechecksScheduler(repo, dns, nil, nil, audit)
	if err != nil {
		t.Fatalf("NewRechecksScheduler: %v", err)
	}
	scheduler.Now = func() time.Time { return now }

	// First pass: fail.
	if err := scheduler.Run(context.Background()); err != nil {
		t.Fatalf("first Run: %v", err)
	}
	if got := repo.fails["t1"]; got != 1 {
		t.Fatalf("after first fail, ConsecutiveFails=%d, want 1", got)
	}
	if repo.unverified["t1"] {
		t.Fatalf("target was downgraded after a single failure")
	}
	if len(audit.events) != 0 {
		t.Fatalf("audit events emitted on single failure: %+v", audit.events)
	}

	// Second pass: success — counter should reset and the target stays verified.
	dns.outcomes = []verifierOutcome{{ok: true, err: nil}}
	if err := scheduler.Run(context.Background()); err != nil {
		t.Fatalf("second Run: %v", err)
	}
	if got := repo.fails["t1"]; got != 0 {
		t.Fatalf("after success, ConsecutiveFails=%d, want 0", got)
	}
	if repo.unverified["t1"] {
		t.Fatalf("target was downgraded after a single failure followed by success")
	}
	if got, want := repo.resets["t1"], now; !got.Equal(want) {
		t.Fatalf("ResetConsecutiveFails timestamp = %v, want %v", got, want)
	}
	if len(audit.events) != 0 {
		t.Fatalf("audit events emitted on success: %+v", audit.events)
	}

	// Two attempts (one failure, one success) should be recorded with
	// the right Succeeded flags.
	if got, want := len(repo.attempts), 2; got != want {
		t.Fatalf("attempts recorded = %d, want %d", got, want)
	}
	if repo.attempts[0].Succeeded {
		t.Fatalf("first attempt was recorded as succeeded")
	}
	if !repo.attempts[1].Succeeded {
		t.Fatalf("second attempt was not recorded as succeeded")
	}
	// Verify the reconstructed display token reached the verifier.
	want := tokenPrefix + validToken
	for i, call := range dns.calls {
		if call.expectedToken != want {
			t.Fatalf("verifier call %d expectedToken = %q, want %q", i, call.expectedToken, want)
		}
	}
}

// TestRechecksScheduler_TwoFailsDowngradeAndAudit covers the downgrade
// branch from Requirement 7.7: two consecutive recheck failures must
// transition the target to `unverified` and emit one
// `target_downgraded` audit event.
func TestRechecksScheduler_TwoFailsDowngradeAndAudit(t *testing.T) {
	t.Parallel()

	repo := newRecheckRepo()
	repo.due = []RecheckTarget{seedTarget("t2")}

	dns := &fakeVerifier{outcomes: []verifierOutcome{
		{ok: false, err: nil},
		{ok: false, err: errors.New("dial tcp: connection refused")},
	}}
	audit := &fakeAuditEmitter{}

	now := time.Date(2026, 1, 22, 0, 0, 0, 0, time.UTC)
	scheduler, err := NewRechecksScheduler(repo, dns, nil, nil, audit)
	if err != nil {
		t.Fatalf("NewRechecksScheduler: %v", err)
	}
	scheduler.Now = func() time.Time { return now }

	// First fail — counter becomes 1, no downgrade.
	if err := scheduler.Run(context.Background()); err != nil {
		t.Fatalf("first Run: %v", err)
	}
	if repo.unverified["t2"] {
		t.Fatalf("target downgraded after a single failure")
	}
	if len(audit.events) != 0 {
		t.Fatalf("audit events emitted before threshold: %+v", audit.events)
	}

	// Second fail — counter hits the threshold, target is downgraded
	// and a `target_downgraded` audit event is published.
	if err := scheduler.Run(context.Background()); err != nil {
		t.Fatalf("second Run: %v", err)
	}
	if !repo.unverified["t2"] {
		t.Fatalf("target was not downgraded after %d consecutive failures", RecheckDowngradeThreshold)
	}
	if got, want := len(audit.events), 1; got != want {
		t.Fatalf("audit events = %d, want %d", got, want)
	}
	ev := audit.events[0]
	if ev.EventType != AuditEventTargetDowngraded {
		t.Fatalf("audit event_type = %q, want %q", ev.EventType, AuditEventTargetDowngraded)
	}
	if ev.TargetID != "t2" {
		t.Fatalf("audit target_id = %q, want %q", ev.TargetID, "t2")
	}
	if ev.OrgID != "org-t2" || ev.WorkspaceID != "ws-t2" {
		t.Fatalf("audit tenancy = (%q,%q), want (org-t2,ws-t2)", ev.OrgID, ev.WorkspaceID)
	}
	if !ev.OccurredAt.Equal(now) {
		t.Fatalf("audit occurred_at = %v, want %v", ev.OccurredAt, now)
	}

	// Both attempts must be recorded; the second should have the
	// transport error string in Detail so operators can see *why* it
	// failed even though we treated it as a routine recheck failure.
	if got, want := len(repo.attempts), 2; got != want {
		t.Fatalf("attempts recorded = %d, want %d", got, want)
	}
	if repo.attempts[1].Detail == "" {
		t.Fatalf("attempt detail empty, want transport error message")
	}
	if got := repo.fails["t2"]; got != RecheckDowngradeThreshold {
		t.Fatalf("ConsecutiveFails = %d, want %d", got, RecheckDowngradeThreshold)
	}
}

// TestRechecksScheduler_DispatchByMethod ensures the scheduler routes
// each target to the verifier matching its `verified_method` and not the
// other way around — a regression here would mean a customer with a DNS
// verification could be silently downgraded by a misconfigured meta tag,
// which violates Requirement 7.7's "re-verify with the original method".
func TestRechecksScheduler_DispatchByMethod(t *testing.T) {
	t.Parallel()

	repo := newRecheckRepo()
	dnsTarget := seedTarget("d1")
	dnsTarget.Method = RecheckMethodDNS
	fileTarget := seedTarget("f1")
	fileTarget.Method = RecheckMethodFile
	metaTarget := seedTarget("m1")
	metaTarget.Method = RecheckMethodMeta
	repo.due = []RecheckTarget{dnsTarget, fileTarget, metaTarget}

	dns := &fakeVerifier{outcomes: []verifierOutcome{{ok: true}}}
	file := &fakeVerifier{outcomes: []verifierOutcome{{ok: true}}}
	meta := &fakeVerifier{outcomes: []verifierOutcome{{ok: true}}}

	scheduler, err := NewRechecksScheduler(repo, dns, file, meta, &fakeAuditEmitter{})
	if err != nil {
		t.Fatalf("NewRechecksScheduler: %v", err)
	}

	if err := scheduler.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}

	if len(dns.calls) != 1 || dns.calls[0].host != "d1.example.com" {
		t.Fatalf("DNS verifier got %+v, want one call for d1.example.com", dns.calls)
	}
	if len(file.calls) != 1 || file.calls[0].host != "f1.example.com" {
		t.Fatalf("File verifier got %+v, want one call for f1.example.com", file.calls)
	}
	if len(meta.calls) != 1 || meta.calls[0].host != "m1.example.com" {
		t.Fatalf("Meta verifier got %+v, want one call for m1.example.com", meta.calls)
	}
}

// TestRechecksScheduler_LocalShortCircuit ensures `verified_local`
// targets are never dispatched to an external verifier, are recorded as
// successes, and have their cadence window reset so they don't get
// re-listed every day.
func TestRechecksScheduler_LocalShortCircuit(t *testing.T) {
	t.Parallel()

	repo := newRecheckRepo()
	tgt := seedTarget("loop")
	tgt.Method = recheckMethodLocal
	tgt.Host = "localhost"
	repo.due = []RecheckTarget{tgt}

	// Wire DNS / file / meta with empty queues so any accidental
	// dispatch fails loudly.
	scheduler, err := NewRechecksScheduler(
		repo,
		&fakeVerifier{},
		&fakeVerifier{},
		&fakeVerifier{},
		&fakeAuditEmitter{},
	)
	if err != nil {
		t.Fatalf("NewRechecksScheduler: %v", err)
	}
	now := time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)
	scheduler.Now = func() time.Time { return now }

	if err := scheduler.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if got, want := len(repo.attempts), 1; got != want {
		t.Fatalf("attempts = %d, want %d", got, want)
	}
	if !repo.attempts[0].Succeeded {
		t.Fatalf("local recheck recorded as failure: %+v", repo.attempts[0])
	}
	if got, want := repo.resets["loop"], now; !got.Equal(want) {
		t.Fatalf("local reset = %v, want %v", got, want)
	}
	if repo.unverified["loop"] {
		t.Fatalf("local target was downgraded")
	}
}

// TestRechecksScheduler_NoDueTargets exercises the empty-list case: no
// repo writes, no audit events, no errors.
func TestRechecksScheduler_NoDueTargets(t *testing.T) {
	t.Parallel()

	repo := newRecheckRepo()
	audit := &fakeAuditEmitter{}
	scheduler, err := NewRechecksScheduler(repo, &fakeVerifier{}, nil, nil, audit)
	if err != nil {
		t.Fatalf("NewRechecksScheduler: %v", err)
	}
	if err := scheduler.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(repo.attempts) != 0 {
		t.Fatalf("attempts recorded with no due targets: %+v", repo.attempts)
	}
	if len(audit.events) != 0 {
		t.Fatalf("audit events emitted with no due targets: %+v", audit.events)
	}
}

// TestRechecksScheduler_ListErrorAborts confirms a repo-listing failure
// halts the whole pass — without the listing we have no work to do.
func TestRechecksScheduler_ListErrorAborts(t *testing.T) {
	t.Parallel()

	repo := newRecheckRepo()
	repo.listErr = errors.New("postgres: connection refused")
	scheduler, err := NewRechecksScheduler(repo, &fakeVerifier{}, nil, nil, &fakeAuditEmitter{})
	if err != nil {
		t.Fatalf("NewRechecksScheduler: %v", err)
	}
	err = scheduler.Run(context.Background())
	if err == nil {
		t.Fatalf("Run returned nil, want propagated repo error")
	}
	if !errors.Is(err, repo.listErr) {
		t.Fatalf("Run error = %v, want wrapping %v", err, repo.listErr)
	}
}

// TestRechecksScheduler_ContextCancelStopsIteration verifies a cancelled
// context stops the per-target loop without bumping further targets.
func TestRechecksScheduler_ContextCancelStopsIteration(t *testing.T) {
	t.Parallel()

	repo := newRecheckRepo()
	for i := 0; i < 5; i++ {
		repo.due = append(repo.due, seedTarget(fmt.Sprintf("c%d", i)))
	}
	dns := &fakeVerifier{}
	for range repo.due {
		dns.outcomes = append(dns.outcomes, verifierOutcome{ok: true})
	}

	scheduler, err := NewRechecksScheduler(repo, dns, nil, nil, &fakeAuditEmitter{})
	if err != nil {
		t.Fatalf("NewRechecksScheduler: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel before Run starts; the for-loop should bail immediately.

	if err := scheduler.Run(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Run error = %v, want context.Canceled", err)
	}
	if len(repo.attempts) != 0 {
		t.Fatalf("attempts recorded after cancellation: %d", len(repo.attempts))
	}
}

// TestRechecksScheduler_MissingVerifierForMethod confirms that an
// unconfigured verifier is reported as a failed attempt rather than
// crashing the run, and that it does NOT bump the consecutive-fail
// counter (a deployment misconfiguration must not flush every customer
// target on the second day).
func TestRechecksScheduler_MissingVerifierForMethod(t *testing.T) {
	t.Parallel()

	repo := newRecheckRepo()
	tgt := seedTarget("nomatch")
	tgt.Method = RecheckMethodMeta // but we will not wire a meta verifier
	repo.due = []RecheckTarget{tgt}

	scheduler, err := NewRechecksScheduler(repo, &fakeVerifier{}, nil, nil, &fakeAuditEmitter{})
	if err != nil {
		t.Fatalf("NewRechecksScheduler: %v", err)
	}
	err = scheduler.Run(context.Background())
	if err == nil {
		t.Fatalf("Run returned nil, want missing-verifier error")
	}
	if got, want := len(repo.attempts), 1; got != want {
		t.Fatalf("attempts = %d, want %d", got, want)
	}
	if repo.attempts[0].Succeeded {
		t.Fatalf("missing-verifier attempt recorded as success")
	}
	if got := repo.fails["nomatch"]; got != 0 {
		t.Fatalf("ConsecutiveFails bumped on missing-verifier failure: %d", got)
	}
	if repo.unverified["nomatch"] {
		t.Fatalf("target downgraded on missing-verifier failure")
	}
}

// TestRechecksScheduler_ScheduleRegistersDailyEntry confirms Schedule
// adds the job to a robfig/cron/v3 instance and returns a usable
// EntryID. We only assert registration here; the cron scheduler's own
// tests cover the actual @daily expansion.
func TestRechecksScheduler_ScheduleRegistersDailyEntry(t *testing.T) {
	t.Parallel()

	repo := newRecheckRepo()
	scheduler, err := NewRechecksScheduler(repo, &fakeVerifier{}, nil, nil, &fakeAuditEmitter{})
	if err != nil {
		t.Fatalf("NewRechecksScheduler: %v", err)
	}
	c := cron.New(cron.WithLocation(time.UTC))
	id, err := scheduler.Schedule(c)
	if err != nil {
		t.Fatalf("Schedule: %v", err)
	}
	if id == 0 {
		t.Fatalf("Schedule returned zero EntryID")
	}
	entries := c.Entries()
	if len(entries) != 1 {
		t.Fatalf("cron entries = %d, want 1", len(entries))
	}
	// Schedule with a nil cron must be a no-op rather than a crash —
	// wiring code calls this unconditionally.
	if id, err := scheduler.Schedule(nil); err != nil || id != 0 {
		t.Fatalf("Schedule(nil) = (%d, %v), want (0, nil)", id, err)
	}
}

// TestNewRechecksScheduler_RequiredDeps closes the loop on the
// constructor's documented contract: a nil repo or audit emitter is a
// configuration error, not a panic at run time.
func TestNewRechecksScheduler_RequiredDeps(t *testing.T) {
	t.Parallel()

	if _, err := NewRechecksScheduler(nil, nil, nil, nil, &fakeAuditEmitter{}); err == nil {
		t.Fatalf("expected error for nil repo")
	}
	if _, err := NewRechecksScheduler(newRecheckRepo(), nil, nil, nil, nil); err == nil {
		t.Fatalf("expected error for nil audit emitter")
	}
}
