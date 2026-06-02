// Org / workspace / member HTTP handlers.
//
// This file implements task 3.6 of the xalgorix-saas spec —
// "Org/workspace/member endpoints". It mounts three route groups
// onto a chi router:
//
//   - `/api/v1/members*`         — Dashboard + API_Key clients
//   - `/api/internal/orgs/*`     — Dashboard-only (admin profile + lifecycle)
//   - `/api/internal/workspaces/*` — Dashboard-only workspace management
//
// The handlers are deliberately thin: input validation, JSON
// (de)serialisation, and translation of service-layer errors onto
// stable HTTP status codes plus the canonical { "error": code }
// envelope from `errors.go`. Business logic remains in
// `internal/cloud/orgs/{org_service,workspace_service,member_service}.go`.
//
// Authorisation:
//
//   - Every route lives behind the chi middleware stack the future
//     [Server.Routes] (task 8.1) will assemble (Auth → Tenancy → CSRF
//     for `/api/internal/*`). The handlers therefore assume the
//     request context already carries an Account id (via
//     [WithAccountID]) and a Role (via [orgs.WithRole]). The route
//     wiring stamps a per-route [orgs.RequireRole] gate on every
//     write endpoint so the handlers can rely on the role check
//     having happened upstream.
//
// Errors:
//
//   - 400 — malformed JSON or path parameters.
//   - 403 — RBAC rejection (handled by [orgs.RequireRole]; never
//     reached by these handlers directly).
//   - 404 — the targeted Org / Workspace / Member does not exist.
//   - 409 — invalid state transition (e.g. suspending a non-active
//     Org), invariant violation (last Owner), or duplicate
//     name (Workspace).
//   - 410 — invite expired.
//   - 422 — failed validation against the service layer
//     (ErrInvalidArgument and friends).
//   - 500 — unexpected internal error.
//
// Created by task 3.6 — `Org/workspace/member endpoints`.
// Requirements: 4.1, 4.6, 4.10, 8.1.
package api

import (
	"context"
	"github.com/google/uuid"

	"github.com/xalgord/xalgorix/v4/internal/cloud/orgs"
)

// -----------------------------------------------------------------
// Service contracts consumed by the handlers
// -----------------------------------------------------------------
//
// We declare narrow, handler-facing interfaces here so the handlers
// can be tested with in-memory fakes that have no transitive
// database dependency. The production binary adapts the concrete
// `orgs.OrgService`, `orgs.WorkspaceService`, and `orgs.MemberService`
// onto these interfaces (with thin extension wrappers for List
// methods that are not yet on the public service surface).
//
// Keeping the interfaces inside the api package — rather than in
// `internal/cloud/orgs` — avoids polluting the service layer with
// list / pagination concerns that only matter to HTTP clients.

// OrgServiceAPI is the subset of the org service the
// `/api/internal/orgs/*` handlers depend on.
type OrgServiceAPI interface {
	Create(ctx context.Context, name, slug string, region orgs.Region, plan orgs.Plan) (orgs.Org, error)
	Get(ctx context.Context, orgID uuid.UUID) (orgs.Org, error)
	Suspend(ctx context.Context, orgID uuid.UUID, reason string) (orgs.Org, error)
	RestoreFromSuspend(ctx context.Context, orgID uuid.UUID) (orgs.Org, error)
	Delete(ctx context.Context, orgID uuid.UUID) (orgs.Org, error)
}

// WorkspaceServiceAPI is the subset of the workspace service the
// `/api/internal/workspaces/*` handlers depend on. The orgID values
// passed through the interface are the canonical string form of the
// active tenant's Organization id (set by the tenancy middleware
// via `app.organization_id`).
type WorkspaceServiceAPI interface {
	Create(ctx context.Context, orgID, name string) (orgs.Workspace, error)
	List(ctx context.Context, orgID string) ([]orgs.Workspace, error)
	AddAccess(ctx context.Context, orgID, accountID, workspaceID string) error
	RemoveAccess(ctx context.Context, orgID, accountID, workspaceID string) error
	Delete(ctx context.Context, orgID, workspaceID string) error
}

// MemberServiceAPI is the subset of the member service the
// `/api/v1/members*` handlers depend on. Listing — both of members
// and of pending invites — is exposed here because the API surface
// in `design.md → /api/v1/*` requires `GET /api/v1/members`. The
// production binary's adapter implements [ListMembers] and
// [ListInvites] by querying the repository directly; the in-memory
// fake in the test suite mirrors the same semantics.
type MemberServiceAPI interface {
	ListMembers(ctx context.Context, orgID uuid.UUID) ([]orgs.Member, error)
	ChangeRole(ctx context.Context, orgID, accountID uuid.UUID, newRole orgs.Role) (orgs.Member, error)
	Remove(ctx context.Context, orgID, accountID uuid.UUID) error

	ListInvites(ctx context.Context, orgID uuid.UUID) ([]orgs.Invite, error)
	Invite(ctx context.Context, orgID, invitedBy uuid.UUID, email string, role orgs.Role) (orgs.InviteIssued, error)
	RevokeInvite(ctx context.Context, orgID, inviteID uuid.UUID) error
}

// -----------------------------------------------------------------
// JSON wire-format types
// -----------------------------------------------------------------

// orgJSON is the wire representation of an Organization. We surface
// just the fields the Dashboard and back office need; sensitive or
// internal-only columns (e.g. SSO domain) are omitted from the
// public projection until a later task explicitly opts them in.
type orgJSON struct {
	ID     uuid.UUID `json:"id"`
	Name   string    `json:"name"`
	Slug   string    `json:"slug"`
	Region string    `json:"region"`
	Plan   string    `json:"plan"`
	Status string    `json:"status"`
}

func toOrgJSON(o orgs.Org) orgJSON {
	return orgJSON{
		ID:     o.ID,
		Name:   o.Name,
		Slug:   o.Slug,
		Region: string(o.Region),
		Plan:   string(o.Plan),
		Status: string(o.Status),
	}
}

// workspaceJSON is the wire representation of a Workspace.
type workspaceJSON struct {
	ID    string `json:"id"`
	OrgID string `json:"org_id"`
	Name  string `json:"name"`
}

func toWorkspaceJSON(w orgs.Workspace) workspaceJSON {
	return workspaceJSON{ID: w.ID, OrgID: w.OrgID, Name: w.Name}
}

// memberJSON is the wire representation of a Member. The
// WorkspaceAccess slice is rendered as an array of UUID strings so
// JSON-Schema-validating clients see a stable shape.
type memberJSON struct {
	OrgID           uuid.UUID   `json:"org_id"`
	AccountID       uuid.UUID   `json:"account_id"`
	Role            string      `json:"role"`
	WorkspaceAccess []uuid.UUID `json:"workspace_access"`
}

func toMemberJSON(m orgs.Member) memberJSON {
	access := m.WorkspaceAccess
	if access == nil {
		access = []uuid.UUID{}
	}
	return memberJSON{
		OrgID:           m.OrgID,
		AccountID:       m.AccountID,
		Role:            string(m.Role),
		WorkspaceAccess: access,
	}
}

// inviteJSON is the wire representation of a pending Invite. The
// raw token is intentionally NOT included — it leaves the platform
// once, in the email body, and is never read back from the database.
type inviteJSON struct {
	ID        uuid.UUID `json:"id"`
	OrgID     uuid.UUID `json:"org_id"`
	Email     string    `json:"email"`
	Role      string    `json:"role"`
	Status    string    `json:"status"`
	ExpiresAt string    `json:"expires_at"`
}

func toInviteJSON(in orgs.Invite, status orgs.InviteStatus) inviteJSON {
	return inviteJSON{
		ID:        in.ID,
		OrgID:     in.OrgID,
		Email:     in.Email,
		Role:      string(in.Role),
		Status:    string(status),
		ExpiresAt: in.ExpiresAt.UTC().Format("2006-01-02T15:04:05Z07:00"),
	}
}
