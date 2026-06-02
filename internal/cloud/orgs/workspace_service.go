// Package orgs — WorkspaceService.
//
// This file implements task 3.2 of the xalgorix-saas spec:
//
//   - WorkspaceService.Create(ctx, orgID, name) — rejects duplicate names
//     within the organization (matching the `UNIQUE (org_id, name)`
//     constraint on the `workspaces` table).
//   - WorkspaceService.List(ctx, orgID) — returns every Workspace in an
//     Organization in deterministic order.
//   - WorkspaceService.AddAccess(ctx, orgID, accountID, workspaceID) — adds
//     workspaceID to the Member's `workspace_access` array.
//   - WorkspaceService.RemoveAccess(ctx, orgID, accountID, workspaceID) —
//     removes workspaceID from that array.
//   - WorkspaceService.Delete(ctx, orgID, workspaceID).
//
// The service is repository-agnostic: it depends on a small
// [WorkspaceRepository] interface that the production implementation
// (Postgres via pgx) and the in-test fake both satisfy. This keeps the
// service unit-testable without spinning up a database, while preserving
// the design.md contract that all writes happen through the per-request
// transaction bound by the tenancy middleware.
//
// Validates: Requirements 4.10.

package orgs

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

// Workspace is the minimal in-memory representation of a row in the
// `workspaces` table from migration `20250101000200_organizations_*.sql`.
// Fields mirror the DDL exactly so repositories can fill it from a
// single SELECT without an extra mapping layer.
type Workspace struct {
	ID    string
	OrgID string
	Name  string
}

// Sentinel errors returned by [WorkspaceService]. Callers (HTTP handlers,
// CLI tools, tests) compare with errors.Is so the API layer can translate
// each policy violation into a stable HTTP status / error code.
var (
	// ErrWorkspaceNameRequired is returned by Create when name is empty
	// or only whitespace.
	ErrWorkspaceNameRequired = errors.New("orgs: workspace name is required")
	// ErrOrgIDRequired is returned by every method when orgID is empty.
	ErrOrgIDRequired = errors.New("orgs: org id is required")
	// ErrWorkspaceIDRequired is returned by AddAccess, RemoveAccess, and
	// Delete when workspaceID is empty.
	ErrWorkspaceIDRequired = errors.New("orgs: workspace id is required")
	// ErrAccountIDRequired is returned by AddAccess and RemoveAccess
	// when accountID is empty.
	ErrAccountIDRequired = errors.New("orgs: account id is required")
	// ErrDuplicateWorkspaceName is returned by Create when an existing
	// Workspace in the same Organization already has the same name. The
	// name comparison is case-insensitive on the trimmed value, matching
	// the spirit of the `UNIQUE (org_id, name)` constraint plus the
	// citext-style equality the platform uses elsewhere for human names.
	ErrDuplicateWorkspaceName = errors.New("orgs: workspace name already exists in organization")
	// ErrWorkspaceNotFound is returned when a Delete or AddAccess /
	// RemoveAccess targets a workspace that does not exist or does not
	// belong to the specified organization.
	ErrWorkspaceNotFound = errors.New("orgs: workspace not found")
	// ErrMemberNotFound is returned by AddAccess / RemoveAccess when the
	// (orgID, accountID) pair is not a member row.
	ErrMemberNotFound = errors.New("orgs: member not found")
)

// WorkspaceRepository is the persistence surface required by
// [WorkspaceService]. The production implementation issues SQL through
// the pgx pool wrapper; tests substitute the in-memory fake defined in
// `workspace_service_test.go`.
//
// All methods MUST execute inside the per-request transaction bound by
// `internal/cloud/tenancy` so RLS policies on the `workspaces` and
// `members` tables apply. Implementations are therefore expected to
// resolve the active transaction from ctx via `db.WithTx`.
type WorkspaceRepository interface {
	// CreateWorkspace inserts a new row in `workspaces`. The repository
	// MUST translate a unique-violation on `(org_id, name)` into
	// [ErrDuplicateWorkspaceName].
	CreateWorkspace(ctx context.Context, orgID, name string) (Workspace, error)
	// ListWorkspaces returns every workspace for orgID, sorted by name
	// ascending so callers receive deterministic output.
	ListWorkspaces(ctx context.Context, orgID string) ([]Workspace, error)
	// DeleteWorkspace removes the workspace identified by workspaceID
	// from orgID. Returns [ErrWorkspaceNotFound] when no row matches.
	DeleteWorkspace(ctx context.Context, orgID, workspaceID string) error
	// UpdateMemberWorkspaceAccess mutates the `members.workspace_access`
	// array for (orgID, accountID). When grant is true the workspaceID
	// is appended (idempotently); when false it is removed. The
	// implementation MUST return [ErrMemberNotFound] when no member row
	// matches and [ErrWorkspaceNotFound] when workspaceID is not a
	// workspace of orgID.
	UpdateMemberWorkspaceAccess(ctx context.Context, orgID, accountID, workspaceID string, grant bool) error
}

// WorkspaceService implements the workspace-management surface of
// design.md "Components and Interfaces → internal/cloud/orgs". It is a
// thin policy layer over [WorkspaceRepository]: input validation, name
// canonicalization, and translation of repository errors into the
// package's sentinel set.
type WorkspaceService struct {
	repo WorkspaceRepository
}

// NewWorkspaceService returns a [WorkspaceService] backed by repo. A nil
// repo is rejected eagerly because the service is unusable without one
// and a delayed nil dereference would surface as a confusing runtime
// panic from a request handler.
func NewWorkspaceService(repo WorkspaceRepository) (*WorkspaceService, error) {
	if repo == nil {
		return nil, errors.New("orgs: workspace repository is required")
	}
	return &WorkspaceService{repo: repo}, nil
}

// Create inserts a new Workspace named name under orgID. The name is
// trimmed of surrounding whitespace before insertion, but is otherwise
// preserved verbatim so customers can pick any human-readable label.
//
// Returns [ErrOrgIDRequired] or [ErrWorkspaceNameRequired] for invalid
// inputs and [ErrDuplicateWorkspaceName] when an existing Workspace in
// the same Organization already has the same trimmed name.
func (s *WorkspaceService) Create(ctx context.Context, orgID, name string) (Workspace, error) {
	if orgID == "" {
		return Workspace{}, ErrOrgIDRequired
	}
	trimmed := strings.TrimSpace(name)
	if trimmed == "" {
		return Workspace{}, ErrWorkspaceNameRequired
	}
	ws, err := s.repo.CreateWorkspace(ctx, orgID, trimmed)
	if err != nil {
		return Workspace{}, err
	}
	return ws, nil
}

// List returns every Workspace owned by orgID. The slice is sorted by
// name ascending so that consumers (Dashboard list views, audit log
// snapshots, JSON responses) receive deterministic ordering even when
// the underlying SQL planner reshuffles rows.
func (s *WorkspaceService) List(ctx context.Context, orgID string) ([]Workspace, error) {
	if orgID == "" {
		return nil, ErrOrgIDRequired
	}
	return s.repo.ListWorkspaces(ctx, orgID)
}

// AddAccess appends workspaceID to the `workspace_access` array on the
// Member identified by (orgID, accountID). The operation is idempotent:
// granting access to a workspace the member already has access to is a
// no-op and returns nil.
//
// Returns [ErrMemberNotFound] when no member row matches and
// [ErrWorkspaceNotFound] when workspaceID does not belong to orgID.
func (s *WorkspaceService) AddAccess(ctx context.Context, orgID, accountID, workspaceID string) error {
	if err := requireAccessIDs(orgID, accountID, workspaceID); err != nil {
		return err
	}
	return s.repo.UpdateMemberWorkspaceAccess(ctx, orgID, accountID, workspaceID, true)
}

// RemoveAccess removes workspaceID from the `workspace_access` array on
// the Member identified by (orgID, accountID). The operation is
// idempotent: removing access the member did not have is a no-op and
// returns nil.
//
// Returns [ErrMemberNotFound] when no member row matches and
// [ErrWorkspaceNotFound] when workspaceID does not belong to orgID.
func (s *WorkspaceService) RemoveAccess(ctx context.Context, orgID, accountID, workspaceID string) error {
	if err := requireAccessIDs(orgID, accountID, workspaceID); err != nil {
		return err
	}
	return s.repo.UpdateMemberWorkspaceAccess(ctx, orgID, accountID, workspaceID, false)
}

// Delete removes the Workspace identified by workspaceID from orgID.
// The cascading `ON DELETE CASCADE` on every workspace-scoped table
// (targets, scans, findings, reports, ...) is handled at the schema
// level — the service does not need to issue secondary deletes.
//
// Returns [ErrWorkspaceNotFound] when no matching row exists.
func (s *WorkspaceService) Delete(ctx context.Context, orgID, workspaceID string) error {
	if orgID == "" {
		return ErrOrgIDRequired
	}
	if workspaceID == "" {
		return ErrWorkspaceIDRequired
	}
	return s.repo.DeleteWorkspace(ctx, orgID, workspaceID)
}

// requireAccessIDs validates that all three identifiers required by the
// access-management methods are present.
func requireAccessIDs(orgID, accountID, workspaceID string) error {
	if orgID == "" {
		return ErrOrgIDRequired
	}
	if accountID == "" {
		return ErrAccountIDRequired
	}
	if workspaceID == "" {
		return ErrWorkspaceIDRequired
	}
	return nil
}

// String implements fmt.Stringer for log-friendly output. Tests rely on
// this to assert error messages without coupling to the internal field
// layout.
func (w Workspace) String() string {
	return fmt.Sprintf("Workspace{id=%s,org=%s,name=%q}", w.ID, w.OrgID, w.Name)
}
