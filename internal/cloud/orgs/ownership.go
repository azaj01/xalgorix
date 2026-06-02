// Package orgs — atomic ownership transfer.
//
// This file implements task 3.5 of the xalgorix-saas spec:
//
//   - [TransferOwnership]                 promotes the target Member to Owner
//                                         and demotes the previous Owner to
//                                         Admin within a single database
//                                         transaction.
//   - [OwnershipRepository] + [OwnershipTx] are the small persistence
//                                         contracts the function depends on.
//                                         Production code wires a pgx-backed
//                                         repository that calls
//                                         [db.Pool.BeginTx]; tests in
//                                         `ownership_test.go` substitute an
//                                         in-memory fake.
//
// Two invariants from `requirements.md` drive the design:
//
//   - Requirement 4.8 — "WHEN an Owner transfers ownership to another
//     Member, THE API_Server SHALL atomically promote the recipient to
//     Owner and demote the previous Owner to Admin." Both writes must
//     therefore land in the same transaction so a crash, panic, or
//     repository error can never leave the org with two Owners or with the
//     recipient promoted but the previous Owner unchanged.
//   - Requirement 4.9 — "THE API_Server SHALL prevent an Organization from
//     having zero Owners at any time." We enforce this two ways: as an
//     up-front guard (the recipient must currently have a role *other*
//     than `owner`, otherwise the demote+promote is a no-op that could
//     accidentally cancel out under concurrent races), and as a
//     transactional post-check that COUNTs `role='owner'` and rolls back
//     with [ErrInvalidOwnership] when the result is anything other than 1.
//
// All guard failures map onto a single sentinel — [ErrInvalidOwnership] —
// so the API layer can render one stable error code regardless of which
// rule was violated. The wrapped error preserves enough context for
// operators reading logs to tell the cases apart via `errors.Unwrap` or
// `errors.As`.
//
// This file deliberately does NOT touch `member_service.go` (task 3.3,
// running in parallel) — the ownership transfer is its own self-contained
// surface, repo, and error vocabulary. When MemberService lands it can
// adopt this function as a method by composing the two without changes
// here.
//
// Validates: Requirements 4.8, 4.9.

package orgs

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
)

// ErrInvalidOwnership is the single sentinel returned by
// [TransferOwnership] when any guard rejects the operation:
//
//   - currentOwnerID does not exist as a member of orgID,
//   - newOwnerID does not exist as a member of orgID,
//   - currentOwnerID's role is not `owner`,
//   - newOwnerID's role is already `owner`,
//   - currentOwnerID and newOwnerID are the same account, or
//   - the post-transfer Owner count is not exactly 1.
//
// Callers can use `errors.Is(err, ErrInvalidOwnership)` to detect any
// of those cases without sniffing for individual sub-causes; the
// wrapped error preserves the specific sub-cause for log messages.
//
// Validates: Requirements 4.8, 4.9.
var ErrInvalidOwnership = errors.New("orgs: invalid ownership transfer")

// OwnershipTx is the transactional surface [TransferOwnership] uses to
// read, write, and audit member roles inside a single database
// transaction. It is intentionally minimal — three calls — so the
// production pgx-backed repository can implement it without leaking
// pgx types into the rest of the package, and so the in-memory fake in
// `ownership_test.go` can model it deterministically.
//
// Implementations MUST execute every method against the same underlying
// transaction handed to the surrounding [OwnershipRepository.InTx]
// callback. They MUST also enforce row-level locking on the rows they
// read (`SELECT ... FOR UPDATE` on the production side) so concurrent
// transfers cannot race past each other into a state where two
// completed transfers both observed a single Owner.
type OwnershipTx interface {
	// GetMemberRole returns the role of accountID within orgID.
	// Returns [ErrMemberNotFound] when no such member exists.
	GetMemberRole(ctx context.Context, orgID, accountID uuid.UUID) (Role, error)

	// SetMemberRole updates the role of accountID within orgID.
	// Returns [ErrMemberNotFound] when no such member exists. The
	// caller is responsible for ordering Set calls so that the org
	// transiently retains at least one Owner — the post-state check
	// in [TransferOwnership] will otherwise roll back the whole
	// transaction.
	SetMemberRole(ctx context.Context, orgID, accountID uuid.UUID, role Role) error

	// CountOwners returns the number of rows in `members` for orgID
	// whose role equals [RoleOwner]. The count MUST reflect every
	// write performed inside the same transaction so the post-state
	// check sees the demote+promote applied above.
	CountOwners(ctx context.Context, orgID uuid.UUID) (int, error)
}

// OwnershipRepository is the persistence contract that lets
// [TransferOwnership] open a transaction without depending on pgx
// directly. The production implementation is a thin shim around
// [db.Pool.BeginTx] from task 1.11; tests use the in-memory fake in
// `ownership_test.go`.
type OwnershipRepository interface {
	// InTx opens a database transaction, calls fn with an
	// [OwnershipTx] bound to that transaction, then commits if fn
	// returns nil or rolls back otherwise. Any error returned by fn
	// (including [ErrInvalidOwnership]) MUST be surfaced verbatim to
	// the caller so `errors.Is` keeps working across the boundary.
	//
	// Implementations MUST guarantee that a panic inside fn results
	// in a rollback rather than a half-applied transaction. The
	// production pgx implementation gets this for free by deferring
	// `tx.Rollback(ctx)` (pgx ignores rollback after commit).
	InTx(ctx context.Context, fn func(tx OwnershipTx) error) error
}

// TransferOwnership promotes newOwnerID to [RoleOwner] and demotes
// currentOwnerID to [RoleAdmin] within orgID, atomically inside a
// single transaction provided by repo.
//
// Guard rails (each maps onto [ErrInvalidOwnership]):
//
//  1. orgID, currentOwnerID, and newOwnerID must all be non-nil UUIDs.
//  2. currentOwnerID and newOwnerID must be distinct accounts.
//  3. currentOwnerID must currently have role [RoleOwner].
//  4. newOwnerID must currently have any role *other* than
//     [RoleOwner] (a member, admin, or viewer is fine).
//  5. After the demote+promote the org must have exactly one Owner.
//
// On any guard failure the transaction is rolled back and the function
// returns an error that satisfies `errors.Is(err, ErrInvalidOwnership)`.
// On success the function returns nil; the caller can rely on both
// role updates having been committed by then.
//
// Validates: Requirements 4.8, 4.9.
func TransferOwnership(ctx context.Context, repo OwnershipRepository, orgID, currentOwnerID, newOwnerID uuid.UUID) error {
	if repo == nil {
		// A nil repo is a wiring bug, not a guard failure — return a
		// distinct error so a panic-in-prod becomes an obvious
		// startup-time signal instead of bleeding into a 4xx.
		return errors.New("orgs: TransferOwnership requires a non-nil repository")
	}
	if orgID == uuid.Nil {
		return fmt.Errorf("%w: org id is required", ErrInvalidOwnership)
	}
	if currentOwnerID == uuid.Nil {
		return fmt.Errorf("%w: current owner id is required", ErrInvalidOwnership)
	}
	if newOwnerID == uuid.Nil {
		return fmt.Errorf("%w: new owner id is required", ErrInvalidOwnership)
	}
	if currentOwnerID == newOwnerID {
		// Transferring ownership to oneself is a no-op that would
		// also flunk guard 4 once executed; reject up-front so
		// callers get a clearer error before any transaction opens.
		return fmt.Errorf("%w: cannot transfer ownership to the same account", ErrInvalidOwnership)
	}

	return repo.InTx(ctx, func(tx OwnershipTx) error {
		// --- Pre-state guards -----------------------------------------
		// We resolve both members BEFORE writing anything so an early
		// failure rolls back without ever touching the rows.
		curRole, err := tx.GetMemberRole(ctx, orgID, currentOwnerID)
		if err != nil {
			if errors.Is(err, ErrMemberNotFound) {
				return fmt.Errorf("%w: current owner is not a member of the organization", ErrInvalidOwnership)
			}
			return err
		}
		if curRole != RoleOwner {
			return fmt.Errorf("%w: current account has role %q, expected %q",
				ErrInvalidOwnership, curRole, RoleOwner)
		}

		newRole, err := tx.GetMemberRole(ctx, orgID, newOwnerID)
		if err != nil {
			if errors.Is(err, ErrMemberNotFound) {
				return fmt.Errorf("%w: new owner is not a member of the organization", ErrInvalidOwnership)
			}
			return err
		}
		if newRole == RoleOwner {
			// If the recipient is already an Owner, the demote+promote
			// would still leave the org with at least one Owner, but
			// the operation makes no semantic sense and risks masking
			// a logic bug in the calling handler. Reject explicitly.
			return fmt.Errorf("%w: new owner already has role %q", ErrInvalidOwnership, RoleOwner)
		}

		// --- Apply the transfer ---------------------------------------
		// Order matters only weakly here: both writes happen in the
		// same transaction so external observers cannot see the
		// intermediate state, but doing the *promote first* keeps the
		// org with two Owners momentarily rather than zero — which
		// matches the spirit of Requirement 4.9 even at the
		// statement-by-statement level.
		if err := tx.SetMemberRole(ctx, orgID, newOwnerID, RoleOwner); err != nil {
			return err
		}
		if err := tx.SetMemberRole(ctx, orgID, currentOwnerID, RoleAdmin); err != nil {
			return err
		}

		// --- Post-state guard -----------------------------------------
		// Catches any race condition (concurrent member removal, an
		// inconsistent fake, or a future bug in SetMemberRole) that
		// would otherwise let the org slip into a zero-Owner or
		// multi-Owner state. Returning an error here triggers the
		// rollback in [OwnershipRepository.InTx], so neither write
		// is persisted.
		count, err := tx.CountOwners(ctx, orgID)
		if err != nil {
			return err
		}
		if count != 1 {
			return fmt.Errorf("%w: post-transfer owner count is %d, expected exactly 1",
				ErrInvalidOwnership, count)
		}
		return nil
	})
}
