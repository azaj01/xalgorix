package orgs

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/google/uuid"
)

// fakeOwnershipRepo is an in-memory [OwnershipRepository] used to drive
// [TransferOwnership] without booting Postgres. It models just enough
// of the production semantics to exercise every guard:
//
//   - members are keyed by (orgID, accountID),
//   - InTx snapshots the entire member map under a mutex, hands the
//     snapshot to the callback as an [OwnershipTx], and either commits
//     the snapshot back on nil return or discards it on error,
//   - the rollback path lets us assert that no role survived a guard
//     failure, which is the property Requirement 4.8 cares about.
//
// The fake also records each transaction outcome so tests can verify
// that the repository was actually invoked (otherwise an over-zealous
// up-front guard would make a "rollback" assertion meaningless).
type fakeOwnershipRepo struct {
	mu        sync.Mutex
	members   map[ownershipMemberKey]Role
	commits   int
	rollbacks int
	// forceCountErr, when non-nil, is returned by CountOwners on every
	// call. Tests use it to force the post-state check to fail without
	// having to construct a member layout that violates the invariant.
	forceCountErr error
}

// ownershipMemberKey is the composite (org, account) key used by the
// in-memory fake. The name is namespaced to avoid colliding with
// `memberPK` declared by `member_service_test.go` (task 3.3) — both
// test files live in the same package so the symbols share a scope.
type ownershipMemberKey struct {
	OrgID     uuid.UUID
	AccountID uuid.UUID
}

func newFakeOwnershipRepo() *fakeOwnershipRepo {
	return &fakeOwnershipRepo{members: make(map[ownershipMemberKey]Role)}
}

// addMember registers a member with the given role. Tests use it to
// build the pre-state for each scenario.
func (f *fakeOwnershipRepo) addMember(orgID, accountID uuid.UUID, role Role) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.members[ownershipMemberKey{OrgID: orgID, AccountID: accountID}] = role
}

// roleOf reads the committed role for assertions after a transfer.
func (f *fakeOwnershipRepo) roleOf(orgID, accountID uuid.UUID) (Role, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	r, ok := f.members[ownershipMemberKey{OrgID: orgID, AccountID: accountID}]
	return r, ok
}

// InTx implements [OwnershipRepository.InTx]. It snapshots the member
// map, hands the snapshot to fn, and commits or discards based on the
// callback's return value. A panic inside fn rolls back as well.
func (f *fakeOwnershipRepo) InTx(ctx context.Context, fn func(tx OwnershipTx) error) error {
	f.mu.Lock()
	snapshot := make(map[ownershipMemberKey]Role, len(f.members))
	for k, v := range f.members {
		snapshot[k] = v
	}
	forceCountErr := f.forceCountErr
	f.mu.Unlock()

	tx := &fakeOwnershipTx{members: snapshot, forceCountErr: forceCountErr}

	committed := false
	defer func() {
		f.mu.Lock()
		defer f.mu.Unlock()
		if committed {
			f.members = tx.members
			f.commits++
		} else {
			f.rollbacks++
		}
	}()

	if err := fn(tx); err != nil {
		return err
	}
	committed = true
	return nil
}

// fakeOwnershipTx is the snapshot-bound transaction handed to the
// [TransferOwnership] callback by fakeOwnershipRepo.InTx.
type fakeOwnershipTx struct {
	members       map[ownershipMemberKey]Role
	forceCountErr error
}

func (t *fakeOwnershipTx) GetMemberRole(_ context.Context, orgID, accountID uuid.UUID) (Role, error) {
	role, ok := t.members[ownershipMemberKey{OrgID: orgID, AccountID: accountID}]
	if !ok {
		return "", ErrMemberNotFound
	}
	return role, nil
}

func (t *fakeOwnershipTx) SetMemberRole(_ context.Context, orgID, accountID uuid.UUID, role Role) error {
	key := ownershipMemberKey{OrgID: orgID, AccountID: accountID}
	if _, ok := t.members[key]; !ok {
		return ErrMemberNotFound
	}
	t.members[key] = role
	return nil
}

func (t *fakeOwnershipTx) CountOwners(_ context.Context, orgID uuid.UUID) (int, error) {
	if t.forceCountErr != nil {
		return 0, t.forceCountErr
	}
	n := 0
	for k, role := range t.members {
		if k.OrgID == orgID && role == RoleOwner {
			n++
		}
	}
	return n, nil
}

// ----------------------------------------------------------------------
// Tests
// ----------------------------------------------------------------------

// TestTransferOwnership_HappyPath asserts the canonical demote+promote
// applies atomically: the recipient ends up Owner, the previous Owner
// ends up Admin, and the org has exactly one Owner.
//
// Validates: Requirements 4.8, 4.9.
func TestTransferOwnership_HappyPath(t *testing.T) {
	repo := newFakeOwnershipRepo()
	orgID := uuid.New()
	currentOwner := uuid.New()
	newOwner := uuid.New()
	repo.addMember(orgID, currentOwner, RoleOwner)
	repo.addMember(orgID, newOwner, RoleMember)

	if err := TransferOwnership(context.Background(), repo, orgID, currentOwner, newOwner); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got, _ := repo.roleOf(orgID, newOwner); got != RoleOwner {
		t.Errorf("new owner role = %q, want %q", got, RoleOwner)
	}
	if got, _ := repo.roleOf(orgID, currentOwner); got != RoleAdmin {
		t.Errorf("previous owner role = %q, want %q", got, RoleAdmin)
	}
	if repo.commits != 1 || repo.rollbacks != 0 {
		t.Errorf("commits=%d rollbacks=%d, want 1/0", repo.commits, repo.rollbacks)
	}
}

// TestTransferOwnership_HappyPath_FromAdmin covers the alternate
// recipient role: an Admin getting promoted to Owner. The previous
// Owner still ends up as Admin.
//
// Validates: Requirements 4.8, 4.9.
func TestTransferOwnership_HappyPath_FromAdmin(t *testing.T) {
	repo := newFakeOwnershipRepo()
	orgID := uuid.New()
	currentOwner := uuid.New()
	newOwner := uuid.New()
	repo.addMember(orgID, currentOwner, RoleOwner)
	repo.addMember(orgID, newOwner, RoleAdmin)

	if err := TransferOwnership(context.Background(), repo, orgID, currentOwner, newOwner); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got, _ := repo.roleOf(orgID, newOwner); got != RoleOwner {
		t.Errorf("new owner role = %q, want %q", got, RoleOwner)
	}
	if got, _ := repo.roleOf(orgID, currentOwner); got != RoleAdmin {
		t.Errorf("previous owner role = %q, want %q", got, RoleAdmin)
	}
}

// TestTransferOwnership_CurrentOwnerNotFound asserts that a missing
// current-owner member rolls back the transaction with
// [ErrInvalidOwnership] and never mutates the recipient.
//
// Validates: Requirements 4.8, 4.9.
func TestTransferOwnership_CurrentOwnerNotFound(t *testing.T) {
	repo := newFakeOwnershipRepo()
	orgID := uuid.New()
	currentOwner := uuid.New() // never added to the repo
	newOwner := uuid.New()
	repo.addMember(orgID, newOwner, RoleMember)

	err := TransferOwnership(context.Background(), repo, orgID, currentOwner, newOwner)
	if !errors.Is(err, ErrInvalidOwnership) {
		t.Fatalf("expected ErrInvalidOwnership, got %v", err)
	}
	if got, _ := repo.roleOf(orgID, newOwner); got != RoleMember {
		t.Errorf("recipient role drifted to %q after failed transfer", got)
	}
	if repo.commits != 0 || repo.rollbacks != 1 {
		t.Errorf("commits=%d rollbacks=%d, want 0/1", repo.commits, repo.rollbacks)
	}
}

// TestTransferOwnership_NewOwnerNotMember asserts that promoting a
// non-member rolls back the transaction with [ErrInvalidOwnership] and
// leaves the previous Owner's role unchanged.
//
// Validates: Requirements 4.8, 4.9.
func TestTransferOwnership_NewOwnerNotMember(t *testing.T) {
	repo := newFakeOwnershipRepo()
	orgID := uuid.New()
	currentOwner := uuid.New()
	newOwner := uuid.New() // never added to the repo
	repo.addMember(orgID, currentOwner, RoleOwner)

	err := TransferOwnership(context.Background(), repo, orgID, currentOwner, newOwner)
	if !errors.Is(err, ErrInvalidOwnership) {
		t.Fatalf("expected ErrInvalidOwnership, got %v", err)
	}
	if got, _ := repo.roleOf(orgID, currentOwner); got != RoleOwner {
		t.Errorf("previous owner role drifted to %q after failed transfer", got)
	}
	if repo.commits != 0 || repo.rollbacks != 1 {
		t.Errorf("commits=%d rollbacks=%d, want 0/1", repo.commits, repo.rollbacks)
	}
}

// TestTransferOwnership_CurrentNotOwner asserts that the source account
// must currently be Owner. An Admin attempting to "transfer" their own
// admin role is rejected.
//
// Validates: Requirements 4.8.
func TestTransferOwnership_CurrentNotOwner(t *testing.T) {
	repo := newFakeOwnershipRepo()
	orgID := uuid.New()
	currentOwner := uuid.New()
	newOwner := uuid.New()
	repo.addMember(orgID, currentOwner, RoleAdmin)
	repo.addMember(orgID, newOwner, RoleMember)

	err := TransferOwnership(context.Background(), repo, orgID, currentOwner, newOwner)
	if !errors.Is(err, ErrInvalidOwnership) {
		t.Fatalf("expected ErrInvalidOwnership, got %v", err)
	}
}

// TestTransferOwnership_NewAlreadyOwner asserts that the recipient
// must not already be Owner. Otherwise the demote+promote would still
// satisfy the invariant but the call carries no useful semantics and
// likely indicates a caller bug.
//
// Validates: Requirements 4.8, 4.9.
func TestTransferOwnership_NewAlreadyOwner(t *testing.T) {
	repo := newFakeOwnershipRepo()
	orgID := uuid.New()
	currentOwner := uuid.New()
	newOwner := uuid.New()
	repo.addMember(orgID, currentOwner, RoleOwner)
	repo.addMember(orgID, newOwner, RoleOwner)

	err := TransferOwnership(context.Background(), repo, orgID, currentOwner, newOwner)
	if !errors.Is(err, ErrInvalidOwnership) {
		t.Fatalf("expected ErrInvalidOwnership, got %v", err)
	}
}

// TestTransferOwnership_RollbackOnZeroOwners simulates the post-state
// guard: the CountOwners call returns 0, which can happen under
// concurrent member removal. The transaction must roll back with
// [ErrInvalidOwnership] and the visible role state must remain
// pre-transfer.
//
// Validates: Requirements 4.9.
func TestTransferOwnership_RollbackOnZeroOwners(t *testing.T) {
	repo := newFakeOwnershipRepo()
	orgID := uuid.New()
	currentOwner := uuid.New()
	newOwner := uuid.New()
	repo.addMember(orgID, currentOwner, RoleOwner)
	repo.addMember(orgID, newOwner, RoleMember)

	// Wrap the repo so we can mutate the snapshot mid-transaction:
	// after [TransferOwnership] applies the demote+promote we delete
	// the just-promoted Owner row, leaving the snapshot with zero
	// Owners. This is the property the post-state check is supposed
	// to catch.
	wrap := &countOwnersOverride{
		inner: repo,
		mutate: func(tx *fakeOwnershipTx) {
			delete(tx.members, ownershipMemberKey{OrgID: orgID, AccountID: newOwner})
		},
	}

	err := TransferOwnership(context.Background(), wrap, orgID, currentOwner, newOwner)
	if !errors.Is(err, ErrInvalidOwnership) {
		t.Fatalf("expected ErrInvalidOwnership, got %v", err)
	}

	// The transaction rolled back, so the previous Owner must still
	// be Owner and the would-be Owner must still be Member.
	if got, _ := repo.roleOf(orgID, currentOwner); got != RoleOwner {
		t.Errorf("previous owner role = %q after rollback, want %q", got, RoleOwner)
	}
	if got, _ := repo.roleOf(orgID, newOwner); got != RoleMember {
		t.Errorf("recipient role = %q after rollback, want %q", got, RoleMember)
	}
	if repo.commits != 0 || repo.rollbacks != 1 {
		t.Errorf("commits=%d rollbacks=%d, want 0/1", repo.commits, repo.rollbacks)
	}
}

// TestTransferOwnership_NilRepoRejected asserts the wiring guard.
func TestTransferOwnership_NilRepoRejected(t *testing.T) {
	err := TransferOwnership(context.Background(), nil, uuid.New(), uuid.New(), uuid.New())
	if err == nil {
		t.Fatalf("expected error on nil repo, got nil")
	}
	if errors.Is(err, ErrInvalidOwnership) {
		// Nil-repo must NOT map onto ErrInvalidOwnership — that
		// sentinel is reserved for caller-data violations so the API
		// layer can render a stable 4xx.
		t.Fatalf("nil repo should not surface as ErrInvalidOwnership: %v", err)
	}
}

// TestTransferOwnership_NilUUIDsRejected covers the three id guards.
func TestTransferOwnership_NilUUIDsRejected(t *testing.T) {
	repo := newFakeOwnershipRepo()
	cases := []struct {
		name    string
		org     uuid.UUID
		current uuid.UUID
		newID   uuid.UUID
	}{
		{"nil org", uuid.Nil, uuid.New(), uuid.New()},
		{"nil current", uuid.New(), uuid.Nil, uuid.New()},
		{"nil new", uuid.New(), uuid.New(), uuid.Nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := TransferOwnership(context.Background(), repo, c.org, c.current, c.newID)
			if !errors.Is(err, ErrInvalidOwnership) {
				t.Fatalf("expected ErrInvalidOwnership, got %v", err)
			}
		})
	}
	if repo.commits != 0 {
		t.Errorf("expected zero commits after nil-uuid rejections, got %d", repo.commits)
	}
}

// TestTransferOwnership_SameAccountRejected asserts the same-account
// guard so callers cannot accidentally invoke a no-op that would later
// flunk the "new owner already has role owner" check at higher cost.
func TestTransferOwnership_SameAccountRejected(t *testing.T) {
	repo := newFakeOwnershipRepo()
	orgID := uuid.New()
	owner := uuid.New()
	repo.addMember(orgID, owner, RoleOwner)

	err := TransferOwnership(context.Background(), repo, orgID, owner, owner)
	if !errors.Is(err, ErrInvalidOwnership) {
		t.Fatalf("expected ErrInvalidOwnership, got %v", err)
	}
	// Up-front guard runs before InTx, so no transaction should have
	// opened.
	if repo.commits != 0 || repo.rollbacks != 0 {
		t.Errorf("commits=%d rollbacks=%d, want 0/0 (guard runs before InTx)",
			repo.commits, repo.rollbacks)
	}
}

// ----------------------------------------------------------------------
// countOwnersOverride
// ----------------------------------------------------------------------

// countOwnersOverride wraps a [fakeOwnershipRepo] so we can mutate the
// transaction snapshot AFTER [TransferOwnership] has applied its writes
// but BEFORE the post-state CountOwners call. This is the only way to
// hit the "zero owners" branch deterministically with the in-memory
// fake — production code reaches it via concurrent member deletion
// inside the same transaction.
type countOwnersOverride struct {
	inner  *fakeOwnershipRepo
	mutate func(tx *fakeOwnershipTx)
}

func (w *countOwnersOverride) InTx(ctx context.Context, fn func(tx OwnershipTx) error) error {
	return w.inner.InTx(ctx, func(tx OwnershipTx) error {
		// Wrap the inner tx so we can intercept CountOwners and
		// mutate the underlying snapshot just before it runs.
		ftx := tx.(*fakeOwnershipTx)
		shim := &countOwnersShim{inner: ftx, mutate: w.mutate}
		return fn(shim)
	})
}

// countOwnersShim is the per-call wrapper used by countOwnersOverride.
// It forwards every [OwnershipTx] method to the inner snapshot but
// runs `mutate` once, immediately before the first CountOwners call.
type countOwnersShim struct {
	inner   *fakeOwnershipTx
	mutate  func(tx *fakeOwnershipTx)
	mutated bool
}

func (s *countOwnersShim) GetMemberRole(ctx context.Context, orgID, accountID uuid.UUID) (Role, error) {
	return s.inner.GetMemberRole(ctx, orgID, accountID)
}

func (s *countOwnersShim) SetMemberRole(ctx context.Context, orgID, accountID uuid.UUID, role Role) error {
	return s.inner.SetMemberRole(ctx, orgID, accountID, role)
}

func (s *countOwnersShim) CountOwners(ctx context.Context, orgID uuid.UUID) (int, error) {
	if !s.mutated && s.mutate != nil {
		s.mutate(s.inner)
		s.mutated = true
	}
	return s.inner.CountOwners(ctx, orgID)
}
