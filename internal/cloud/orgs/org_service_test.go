package orgs

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
)

// ----------------------------------------------------------------------
// Fake repository
// ----------------------------------------------------------------------

// fakeRepo is an in-memory [Repository] used to drive [OrgService]
// without a live PostgreSQL. It implements the same atomic-transition
// semantics the production repository relies on (an "active" row can
// only transition while it is "active") so the service-level tests
// validate the actual contract instead of a relaxed double.
type fakeRepo struct {
	mu          sync.Mutex
	orgs        map[uuid.UUID]Org
	slugs       map[string]struct{}
	createErr   error
	getErr      error
	updateErr   error
	createCalls int
	updateCalls int
}

func newFakeRepo() *fakeRepo {
	return &fakeRepo{
		orgs:  make(map[uuid.UUID]Org),
		slugs: make(map[string]struct{}),
	}
}

// seed inserts an org directly without going through Create. Tests use
// it to set up preconditions (for example, a `suspended` org to
// restore).
func (f *fakeRepo) seed(t *testing.T, status Status) Org {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	id := uuid.New()
	org := Org{
		ID:        id,
		Name:      "Seeded Co",
		Slug:      "seeded-" + id.String()[:8],
		Region:    RegionUSEast1,
		Plan:      PlanFree,
		Status:    status,
		Timezone:  "UTC",
		CreatedAt: time.Now().UTC(),
	}
	f.orgs[id] = org
	f.slugs[org.Slug] = struct{}{}
	return org
}

func (f *fakeRepo) CreateOrg(_ context.Context, in CreateOrgInput) (Org, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.createCalls++
	if f.createErr != nil {
		return Org{}, f.createErr
	}
	if _, exists := f.slugs[in.Slug]; exists {
		// Mimic Postgres unique-violation surface so
		// [OrgService.Create] exercises its 23505 mapping.
		return Org{}, &pgconn.PgError{Code: "23505", Message: "duplicate key value violates unique constraint"}
	}
	id := uuid.New()
	org := Org{
		ID:        id,
		Name:      in.Name,
		Slug:      in.Slug,
		Region:    in.Region,
		Plan:      in.Plan,
		Status:    StatusActive,
		Timezone:  "UTC",
		CreatedAt: time.Now().UTC(),
	}
	f.orgs[id] = org
	f.slugs[in.Slug] = struct{}{}
	return org, nil
}

func (f *fakeRepo) GetOrg(_ context.Context, id uuid.UUID) (Org, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.getErr != nil {
		return Org{}, f.getErr
	}
	org, ok := f.orgs[id]
	if !ok {
		return Org{}, ErrOrgNotFound
	}
	return org, nil
}

func (f *fakeRepo) UpdateOrgStatus(_ context.Context, id uuid.UUID, from, to Status) (Org, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.updateCalls++
	if f.updateErr != nil {
		return Org{}, f.updateErr
	}
	org, ok := f.orgs[id]
	if !ok {
		return Org{}, ErrOrgNotFound
	}
	if org.Status != from {
		return Org{}, fmt.Errorf("%w: %s -> %s rejected, current status is %s",
			ErrInvalidStateTransition, from, to, org.Status)
	}
	org.Status = to
	f.orgs[id] = org
	return org, nil
}

// ----------------------------------------------------------------------
// Tests
// ----------------------------------------------------------------------

// TestNewOrgService_PanicsOnNilRepo asserts the constructor refuses to
// build a half-wired service.
func TestNewOrgService_PanicsOnNilRepo(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatalf("expected panic on nil repo")
		}
	}()
	_ = NewOrgService(nil)
}

// TestCreate_HappyPath asserts a valid (name, slug, region, plan) tuple
// produces an `active` Organization with the supplied attributes.
//
// Validates: Requirements 4.1.
func TestCreate_HappyPath(t *testing.T) {
	repo := newFakeRepo()
	svc := NewOrgService(repo)

	org, err := svc.Create(context.Background(), "Acme Inc", "acme", RegionUSEast1, PlanPro)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if org.Name != "Acme Inc" {
		t.Errorf("name = %q, want %q", org.Name, "Acme Inc")
	}
	if org.Slug != "acme" {
		t.Errorf("slug = %q, want %q", org.Slug, "acme")
	}
	if org.Region != RegionUSEast1 {
		t.Errorf("region = %q, want %q", org.Region, RegionUSEast1)
	}
	if org.Plan != PlanPro {
		t.Errorf("plan = %q, want %q", org.Plan, PlanPro)
	}
	if org.Status != StatusActive {
		t.Errorf("status = %q, want %q", org.Status, StatusActive)
	}
	if org.ID == uuid.Nil {
		t.Errorf("id should not be zero")
	}
}

// TestCreate_RejectsBadInput covers the validation matrix on Create.
func TestCreate_RejectsBadInput(t *testing.T) {
	cases := []struct {
		name   string
		nameIn string
		slug   string
		region Region
		plan   Plan
	}{
		{"empty name", "", "x", RegionUSEast1, PlanFree},
		{"empty slug", "Co", "", RegionUSEast1, PlanFree},
		{"bad region", "Co", "x", Region("mars-1"), PlanFree},
		{"bad plan", "Co", "x", RegionUSEast1, Plan("ultra")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svc := NewOrgService(newFakeRepo())
			_, err := svc.Create(context.Background(), tc.nameIn, tc.slug, tc.region, tc.plan)
			if !errors.Is(err, ErrInvalidArgument) {
				t.Fatalf("expected ErrInvalidArgument, got %v", err)
			}
		})
	}
}

// TestCreate_DuplicateSlug maps Postgres unique-constraint violations
// (`23505`) onto [ErrInvalidArgument] so handlers do not have to
// import pgx error types.
//
// Validates: Requirements 4.1.
func TestCreate_DuplicateSlug(t *testing.T) {
	repo := newFakeRepo()
	svc := NewOrgService(repo)
	if _, err := svc.Create(context.Background(), "Acme", "acme", RegionUSEast1, PlanFree); err != nil {
		t.Fatalf("seed create failed: %v", err)
	}
	_, err := svc.Create(context.Background(), "Acme 2", "acme", RegionUSEast1, PlanFree)
	if !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("expected ErrInvalidArgument on duplicate slug, got %v", err)
	}
}

// TestSuspend_OnActive asserts the active -> suspended transition
// succeeds.
//
// Validates: Requirements 11.8, 4.1.
func TestSuspend_OnActive(t *testing.T) {
	repo := newFakeRepo()
	seed := repo.seed(t, StatusActive)
	svc := NewOrgService(repo)

	got, err := svc.Suspend(context.Background(), seed.ID, "manual review")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Status != StatusSuspended {
		t.Fatalf("status = %q, want %q", got.Status, StatusSuspended)
	}
}

// TestSuspend_OnSuspendedReturnsInvalidTransition asserts that calling
// Suspend on a row that is already `suspended` is an error and does
// not mutate the row.
//
// Validates: Requirements 11.8, 4.1.
func TestSuspend_OnSuspendedReturnsInvalidTransition(t *testing.T) {
	repo := newFakeRepo()
	seed := repo.seed(t, StatusSuspended)
	svc := NewOrgService(repo)

	_, err := svc.Suspend(context.Background(), seed.ID, "double-tap")
	if !errors.Is(err, ErrInvalidStateTransition) {
		t.Fatalf("expected ErrInvalidStateTransition, got %v", err)
	}

	// Confirm the row was not changed.
	got, err := repo.GetOrg(context.Background(), seed.ID)
	if err != nil {
		t.Fatalf("get after failed suspend: %v", err)
	}
	if got.Status != StatusSuspended {
		t.Fatalf("status drifted to %q after rejected transition", got.Status)
	}
}

// TestSuspend_OnPendingDeleteRejected covers the second invalid-source
// status for Suspend.
//
// Validates: Requirements 11.8, 13.4.
func TestSuspend_OnPendingDeleteRejected(t *testing.T) {
	repo := newFakeRepo()
	seed := repo.seed(t, StatusPendingDelete)
	svc := NewOrgService(repo)

	_, err := svc.Suspend(context.Background(), seed.ID, "")
	if !errors.Is(err, ErrInvalidStateTransition) {
		t.Fatalf("expected ErrInvalidStateTransition, got %v", err)
	}
}

// TestRestoreFromSuspend_HappyPath asserts the suspended -> active
// transition succeeds.
//
// Validates: Requirements 11.8, 4.1.
func TestRestoreFromSuspend_HappyPath(t *testing.T) {
	repo := newFakeRepo()
	seed := repo.seed(t, StatusSuspended)
	svc := NewOrgService(repo)

	got, err := svc.RestoreFromSuspend(context.Background(), seed.ID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Status != StatusActive {
		t.Fatalf("status = %q, want %q", got.Status, StatusActive)
	}
}

// TestRestoreFromSuspend_OnActiveRejected asserts RestoreFromSuspend is
// only valid from `suspended`.
//
// Validates: Requirements 11.8, 4.1.
func TestRestoreFromSuspend_OnActiveRejected(t *testing.T) {
	repo := newFakeRepo()
	seed := repo.seed(t, StatusActive)
	svc := NewOrgService(repo)

	_, err := svc.RestoreFromSuspend(context.Background(), seed.ID)
	if !errors.Is(err, ErrInvalidStateTransition) {
		t.Fatalf("expected ErrInvalidStateTransition, got %v", err)
	}
}

// TestDelete_SetsPendingDelete asserts Delete moves the row into
// `pending_delete`, the soft-delete grace state required by
// Requirement 13.4 — the row is NOT removed.
//
// Validates: Requirements 13.4.
func TestDelete_SetsPendingDelete(t *testing.T) {
	repo := newFakeRepo()
	seed := repo.seed(t, StatusActive)
	svc := NewOrgService(repo)

	got, err := svc.Delete(context.Background(), seed.ID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Status != StatusPendingDelete {
		t.Fatalf("status = %q, want %q", got.Status, StatusPendingDelete)
	}
	// The row must still exist in the repository so the 30-day
	// grace cron can find it.
	if _, err := repo.GetOrg(context.Background(), seed.ID); err != nil {
		t.Fatalf("expected row to still exist after Delete, got %v", err)
	}
}

// TestDelete_OnSuspendedRejected asserts Delete only runs from
// `active` — preventing accidental hard-deletion of suspended
// tenants.
//
// Validates: Requirements 13.4, 11.8.
func TestDelete_OnSuspendedRejected(t *testing.T) {
	repo := newFakeRepo()
	seed := repo.seed(t, StatusSuspended)
	svc := NewOrgService(repo)

	_, err := svc.Delete(context.Background(), seed.ID)
	if !errors.Is(err, ErrInvalidStateTransition) {
		t.Fatalf("expected ErrInvalidStateTransition, got %v", err)
	}
}

// TestDelete_OnPendingDeleteRejected asserts Delete is idempotent at
// the API surface but rejected at the service so callers do not
// accidentally restart the grace timer.
//
// Validates: Requirements 13.4.
func TestDelete_OnPendingDeleteRejected(t *testing.T) {
	repo := newFakeRepo()
	seed := repo.seed(t, StatusPendingDelete)
	svc := NewOrgService(repo)

	_, err := svc.Delete(context.Background(), seed.ID)
	if !errors.Is(err, ErrInvalidStateTransition) {
		t.Fatalf("expected ErrInvalidStateTransition, got %v", err)
	}
}

// TestTransition_NilOrgIDRejected asserts every transition method
// validates the org id before reaching the repository.
func TestTransition_NilOrgIDRejected(t *testing.T) {
	repo := newFakeRepo()
	svc := NewOrgService(repo)
	ctx := context.Background()

	calls := []struct {
		name string
		run  func() error
	}{
		{"suspend", func() error { _, err := svc.Suspend(ctx, uuid.Nil, ""); return err }},
		{"restore", func() error { _, err := svc.RestoreFromSuspend(ctx, uuid.Nil); return err }},
		{"delete", func() error { _, err := svc.Delete(ctx, uuid.Nil); return err }},
	}
	for _, c := range calls {
		t.Run(c.name, func(t *testing.T) {
			if err := c.run(); !errors.Is(err, ErrInvalidArgument) {
				t.Fatalf("expected ErrInvalidArgument, got %v", err)
			}
		})
	}

	// Ensure the repository was never consulted for any of these
	// rejected calls.
	if repo.updateCalls != 0 {
		t.Fatalf("expected 0 repository updates, got %d", repo.updateCalls)
	}
}
