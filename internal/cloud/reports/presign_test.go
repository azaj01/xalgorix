package reports

import (
	"context"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/xalgord/xalgorix/v4/internal/cloud/storage"
	"github.com/xalgord/xalgorix/v4/internal/cloud/tenancy"
)

// presignTestStorage is the [storage.Storage] fake used by every test
// in this file. It records every Presign invocation so assertions can
// pin the supplied key and TTL, and surfaces a configurable error so
// the failure paths can be exercised without booting a real S3 client.
//
// The fake intentionally rejects Put / Get / Delete because the
// presign flow must not touch any of those code paths.
type presignTestStorage struct {
	mu       sync.Mutex
	presigns []presignCall
	url      string
	err      error
}

type presignCall struct {
	Key string
	TTL time.Duration
}

func (s *presignTestStorage) Put(_ context.Context, _ string, _ io.Reader, _ storage.Meta) error {
	return errors.New("presignTestStorage: Put not implemented in tests")
}

func (s *presignTestStorage) Get(_ context.Context, _ string) (io.ReadCloser, error) {
	return nil, errors.New("presignTestStorage: Get not implemented in tests")
}

func (s *presignTestStorage) Delete(_ context.Context, _ string) error {
	return errors.New("presignTestStorage: Delete not implemented in tests")
}

func (s *presignTestStorage) Presign(_ context.Context, key string, ttl time.Duration) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.presigns = append(s.presigns, presignCall{Key: key, TTL: ttl})
	if s.err != nil {
		return "", s.err
	}
	return s.url, nil
}

func (s *presignTestStorage) snapshot() []presignCall {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]presignCall, len(s.presigns))
	copy(out, s.presigns)
	return out
}

// Compile-time check that the fake satisfies storage.Storage.
var _ storage.Storage = (*presignTestStorage)(nil)

// fakeReportRepo is the in-memory [ReportRepo] used by every test in
// this file. Tests seed the `rows` map keyed on report id; missing
// keys map to [ErrReportNotFound], the canonical "row not found"
// sentinel from the production presigner.
type fakeReportRepo struct {
	mu   sync.Mutex
	rows map[uuid.UUID]ReportRow
	err  error
}

func newFakeReportRepo() *fakeReportRepo {
	return &fakeReportRepo{rows: map[uuid.UUID]ReportRow{}}
}

func (r *fakeReportRepo) put(row ReportRow) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.rows[row.ID] = row
}

func (r *fakeReportRepo) GetReport(_ context.Context, id uuid.UUID) (ReportRow, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.err != nil {
		return ReportRow{}, r.err
	}
	row, ok := r.rows[id]
	if !ok {
		return ReportRow{}, ErrReportNotFound
	}
	return row, nil
}

// fakePresignAuditor records every emitted audit event in insertion
// order so tests can assert that exactly one `report_downloaded` event
// fires per successful presign.
type fakePresignAuditor struct {
	mu     sync.Mutex
	events []AuditEvent
	err    error
}

func (a *fakePresignAuditor) Emit(_ context.Context, event AuditEvent) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.err != nil {
		return a.err
	}
	a.events = append(a.events, event)
	return nil
}

func (a *fakePresignAuditor) snapshot() []AuditEvent {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]AuditEvent, len(a.events))
	copy(out, a.events)
	return out
}

// presignFixture is the canonical wiring used by every test. Tests
// override only the fields they exercise.
type presignFixture struct {
	repo    *fakeReportRepo
	store   *presignTestStorage
	audit   *fakePresignAuditor
	now     time.Time
	scanID  string
	row     ReportRow
	tenantCtx context.Context
}

func newPresignFixture(t *testing.T) *presignFixture {
	t.Helper()
	repo := newFakeReportRepo()
	store := &presignTestStorage{url: "https://example.com/signed"}
	audit := &fakePresignAuditor{}
	scanID := uuid.NewString()
	row := ReportRow{
		ID:          uuid.New(),
		OrgID:       testOrgID,
		WorkspaceID: testWorkspaceID,
		S3Key:       storage.KeyPrefix(testOrgID, testWorkspaceID) + "scan/" + scanID + "/" + ReportObjectName,
	}
	repo.put(row)
	now := time.Date(2026, 5, 15, 12, 0, 0, 0, time.UTC)
	ctx := tenancy.WithTenantInfo(context.Background(), testOrgID, testWorkspaceID)
	return &presignFixture{
		repo:      repo,
		store:     store,
		audit:     audit,
		now:       now,
		scanID:    scanID,
		row:       row,
		tenantCtx: ctx,
	}
}

func (f *presignFixture) presigner(t *testing.T, ttl time.Duration) *Presigner {
	t.Helper()
	p, err := NewPresigner(f.repo, f.store, f.audit)
	if err != nil {
		t.Fatalf("NewPresigner: %v", err)
	}
	if ttl > 0 {
		p.TTL = ttl
	}
	p.Now = func() time.Time { return f.now }
	return p
}

// TestPresign_HappyPath exercises the canonical success path: the
// repository returns a tenant-matched row, storage returns a stable
// URL, the audit emitter records exactly one `report_downloaded`
// event, and the returned `expiresAt` is `now + 15m`.
//
// Validates: Requirements 6.6, 20.7.
func TestPresign_HappyPath(t *testing.T) {
	f := newPresignFixture(t)
	p := f.presigner(t, MaxPresignTTL)

	url, expiresAt, err := p.Presign(f.tenantCtx, f.row.ID)
	if err != nil {
		t.Fatalf("Presign: unexpected error: %v", err)
	}
	if url != "https://example.com/signed" {
		t.Fatalf("url = %q, want %q", url, "https://example.com/signed")
	}
	if want := f.now.Add(MaxPresignTTL); !expiresAt.Equal(want) {
		t.Fatalf("expiresAt = %v, want %v", expiresAt, want)
	}

	calls := f.store.snapshot()
	if len(calls) != 1 {
		t.Fatalf("storage.Presign call count = %d, want 1", len(calls))
	}
	if calls[0].Key != f.row.S3Key {
		t.Fatalf("storage.Presign key = %q, want %q", calls[0].Key, f.row.S3Key)
	}
	if calls[0].TTL != MaxPresignTTL {
		t.Fatalf("storage.Presign ttl = %v, want %v", calls[0].TTL, MaxPresignTTL)
	}

	events := f.audit.snapshot()
	if len(events) != 1 {
		t.Fatalf("audit event count = %d, want 1", len(events))
	}
	ev := events[0]
	if ev.EventType != AuditEventReportDownloaded {
		t.Fatalf("audit event_type = %q, want %q", ev.EventType, AuditEventReportDownloaded)
	}
	if ev.ReportID != f.row.ID {
		t.Fatalf("audit report_id = %s, want %s", ev.ReportID, f.row.ID)
	}
	if ev.OrgID != testOrgID || ev.WorkspaceID != testWorkspaceID {
		t.Fatalf("audit tenant pair = (%q,%q), want (%q,%q)",
			ev.OrgID, ev.WorkspaceID, testOrgID, testWorkspaceID)
	}
	if ev.Key != f.row.S3Key {
		t.Fatalf("audit key = %q, want %q", ev.Key, f.row.S3Key)
	}
	if !ev.OccurredAt.Equal(f.now) {
		t.Fatalf("audit occurred_at = %v, want %v", ev.OccurredAt, f.now)
	}
}

// TestPresign_ClampsTTL asserts that a Presigner configured with a
// TTL larger than 15 minutes still issues a 15-minute URL. The clamp
// is the load-bearing invariant from Property 12 in design.md and
// must hold even if a caller misconfigures `Presigner.TTL`.
//
// Validates: Requirements 6.6, 20.7.
func TestPresign_ClampsTTL(t *testing.T) {
	cases := []struct {
		name string
		ttl  time.Duration
	}{
		{name: "one hour", ttl: time.Hour},
		{name: "exactly fifteen plus one second", ttl: MaxPresignTTL + time.Second},
		{name: "zero falls back", ttl: 0},
		{name: "negative falls back", ttl: -5 * time.Minute},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			f := newPresignFixture(t)
			p := f.presigner(t, MaxPresignTTL)
			p.TTL = tc.ttl

			_, expiresAt, err := p.Presign(f.tenantCtx, f.row.ID)
			if err != nil {
				t.Fatalf("Presign: unexpected error: %v", err)
			}
			if want := f.now.Add(MaxPresignTTL); !expiresAt.Equal(want) {
				t.Fatalf("expiresAt = %v, want %v (ttl was clamped)", expiresAt, want)
			}
			calls := f.store.snapshot()
			if len(calls) != 1 {
				t.Fatalf("storage.Presign call count = %d, want 1", len(calls))
			}
			if calls[0].TTL != MaxPresignTTL {
				t.Fatalf("storage.Presign ttl = %v, want %v (clamp failed)", calls[0].TTL, MaxPresignTTL)
			}
		})
	}
}

// TestPresign_TenantMismatchReturnsViolation asserts that a request
// whose tenant context disagrees with the row's `(org_id,
// workspace_id)` is rejected with [storage.ErrTenantIsolationViolation]
// and that NO audit event fires (the storage layer is not invoked
// either, so the audit emit cannot happen even on a partial failure).
//
// Validates: Requirements 6.6, 20.7.
func TestPresign_TenantMismatchReturnsViolation(t *testing.T) {
	otherOrg := "00000000-0000-4000-8000-0000000000bb"
	otherWs := "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"

	f := newPresignFixture(t)
	p := f.presigner(t, MaxPresignTTL)

	// Request principal is the foreign tenant; the row still belongs
	// to the canonical fixture pair.
	ctx := tenancy.WithTenantInfo(context.Background(), otherOrg, otherWs)

	_, _, err := p.Presign(ctx, f.row.ID)
	if !errors.Is(err, storage.ErrTenantIsolationViolation) {
		t.Fatalf("expected ErrTenantIsolationViolation, got %v", err)
	}
	if calls := f.store.snapshot(); len(calls) != 0 {
		t.Fatalf("storage.Presign call count = %d, want 0 on violation", len(calls))
	}
	if events := f.audit.snapshot(); len(events) != 0 {
		t.Fatalf("audit event count = %d, want 0 on violation", len(events))
	}
}

// TestPresign_EmptyTenantContextReturnsViolation asserts that a
// request that arrives with no tenant context (a coding mistake in
// the wiring of the auth middleware) is rejected with the same
// sentinel as a tenant mismatch. This is a defence-in-depth case —
// `WithTenant` is already supposed to reject mutating requests with
// no resolved tenant, but the presigner's own check ensures even a
// misrouted GET cannot leak a signed URL.
//
// Validates: Requirements 6.6, 20.7.
func TestPresign_EmptyTenantContextReturnsViolation(t *testing.T) {
	f := newPresignFixture(t)
	p := f.presigner(t, MaxPresignTTL)

	_, _, err := p.Presign(context.Background(), f.row.ID)
	if !errors.Is(err, storage.ErrTenantIsolationViolation) {
		t.Fatalf("expected ErrTenantIsolationViolation, got %v", err)
	}
}

// TestPresign_AuditFailureDoesNotBlockReturn asserts that an audit
// emission failure is logged but does not propagate to the caller.
// This is the "don't block on audit failure — log and continue"
// invariant from the task brief.
//
// Validates: Requirements 6.6, 20.7.
func TestPresign_AuditFailureDoesNotBlockReturn(t *testing.T) {
	f := newPresignFixture(t)
	f.audit.err = errors.New("audit table unavailable")

	p := f.presigner(t, MaxPresignTTL)

	url, expiresAt, err := p.Presign(f.tenantCtx, f.row.ID)
	if err != nil {
		t.Fatalf("Presign should not propagate audit failure: %v", err)
	}
	if url == "" {
		t.Fatalf("expected non-empty url despite audit failure")
	}
	if want := f.now.Add(MaxPresignTTL); !expiresAt.Equal(want) {
		t.Fatalf("expiresAt = %v, want %v", expiresAt, want)
	}
	if calls := f.store.snapshot(); len(calls) != 1 {
		t.Fatalf("storage.Presign call count = %d, want 1", len(calls))
	}
}

// TestPresign_MissingReportReturnsNotFound asserts that the
// canonical "row not found" sentinel propagates to the caller and
// that no audit event fires for a non-existent report.
//
// Validates: Requirement 6.6.
func TestPresign_MissingReportReturnsNotFound(t *testing.T) {
	f := newPresignFixture(t)
	p := f.presigner(t, MaxPresignTTL)

	_, _, err := p.Presign(f.tenantCtx, uuid.New())
	if !errors.Is(err, ErrReportNotFound) {
		t.Fatalf("expected ErrReportNotFound, got %v", err)
	}
	if events := f.audit.snapshot(); len(events) != 0 {
		t.Fatalf("audit event count = %d, want 0 for missing report", len(events))
	}
}

// TestPresign_RepoErrorPropagates asserts that an unexpected
// repository error (transport failure, query error) is wrapped and
// returned to the caller.
//
// Validates: Requirement 6.6.
func TestPresign_RepoErrorPropagates(t *testing.T) {
	f := newPresignFixture(t)
	f.repo.err = errors.New("postgres: connection refused")

	p := f.presigner(t, MaxPresignTTL)

	_, _, err := p.Presign(f.tenantCtx, f.row.ID)
	if err == nil {
		t.Fatalf("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "lookup report") {
		t.Fatalf("error message %q does not mention the lookup phase", err.Error())
	}
}

// TestPresign_StorageErrorPropagatesAndSkipsAudit asserts that a
// presign failure from the storage layer prevents the
// `report_downloaded` audit event from firing — emitting an event
// for a download that never produced a URL would be misleading.
//
// Validates: Requirement 20.7.
func TestPresign_StorageErrorPropagatesAndSkipsAudit(t *testing.T) {
	f := newPresignFixture(t)
	f.store.err = errors.New("s3: temporary failure")

	p := f.presigner(t, MaxPresignTTL)

	_, _, err := p.Presign(f.tenantCtx, f.row.ID)
	if err == nil {
		t.Fatalf("expected error, got nil")
	}
	if events := f.audit.snapshot(); len(events) != 0 {
		t.Fatalf("audit event count = %d, want 0 when presign fails", len(events))
	}
}

// TestNewPresigner_RejectsNilDependencies asserts every required
// dependency surfaces a startup error rather than a nil-pointer
// panic mid-request.
func TestNewPresigner_RejectsNilDependencies(t *testing.T) {
	repo := newFakeReportRepo()
	store := &presignTestStorage{}
	audit := &fakePresignAuditor{}

	if _, err := NewPresigner(nil, store, audit); err == nil {
		t.Fatalf("NewPresigner accepted nil repo")
	}
	if _, err := NewPresigner(repo, nil, audit); err == nil {
		t.Fatalf("NewPresigner accepted nil storage")
	}
	if _, err := NewPresigner(repo, store, nil); err == nil {
		t.Fatalf("NewPresigner accepted nil audit emitter")
	}
}
