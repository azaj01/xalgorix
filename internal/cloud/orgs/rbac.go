package orgs

// rbac.go encodes the Owner / Admin / Member / Viewer permission matrix
// from Requirement 4.2 as a static lookup map. It also exposes a chi-
// compatible RequireRole middleware factory plus context helpers used by
// API_Server handlers and the audit middleware to gate state-changing
// requests.
//
// Role hierarchy: Owner > Admin > Member > Viewer.
//
// The matrix is intentionally coarse-grained at the resource family level.
// Two cell-level rules from Requirement 4.2 are runtime-only and cannot be
// expressed in a (role, action, resource) tuple — they are enforced by
// MemberService instead:
//
//   * Admin may not change the Owner's Role (target-row check).
//   * The Organization may never have zero Owners (transactional invariant
//     in MemberService.ChangeRole and in the atomic ownership transfer).
//
// This file implements task 3.4. Requirements: 4.2, 8.3.

import (
	"context"
	"encoding/json"
	"net/http"
)

// Role names a member's role within an Organization. Persisted values match
// the CHECK constraint on `members.role` in the Phase 1 schema.
type Role string

// Role constants. Values are lower-case to match the database CHECK constraint
// `role IN ('owner','admin','member','viewer')`.
const (
	RoleOwner  Role = "owner"
	RoleAdmin  Role = "admin"
	RoleMember Role = "member"
	RoleViewer Role = "viewer"
)

// Action enumerates the verbs the RBAC matrix decides on. ActionTransferOwnership
// is modelled as its own verb because Requirement 4.2 calls it out separately
// from generic create / update / delete.
type Action string

// Action constants.
const (
	ActionCreate            Action = "create"
	ActionRead              Action = "read"
	ActionUpdate            Action = "update"
	ActionDelete            Action = "delete"
	ActionTransferOwnership Action = "transfer_ownership"
)

// Resource enumerates the resource families gated by RBAC. The list mirrors
// the Cloud_Platform domain model and is closed: API handlers must pick a
// constant from here when calling Allow.
type Resource string

// Resource constants.
const (
	ResourceOrganization Resource = "organization"
	ResourceWorkspace    Resource = "workspace"
	ResourceMember       Resource = "member"
	ResourceBilling      Resource = "billing"
	ResourceScan         Resource = "scan"
	ResourceTarget       Resource = "target"
	ResourceReport       Resource = "report"
	ResourceFinding      Resource = "finding"
	ResourceAPIKey       Resource = "api_key"
	ResourceWebhook      Resource = "webhook"
	ResourceIntegration  Resource = "integration"
	ResourceAuditLog     Resource = "audit_log"
)

// roleRank establishes the strict Owner > Admin > Member > Viewer hierarchy
// consumed by RequireRole. Higher numbers outrank lower ones.
var roleRank = map[Role]int{
	RoleOwner:  4,
	RoleAdmin:  3,
	RoleMember: 2,
	RoleViewer: 1,
}

// rbacCell is the composite key of the static matrix.
type rbacCell struct {
	role     Role
	action   Action
	resource Resource
}

// allResources lists every Resource constant. Used to seed the matrix.
var allResources = []Resource{
	ResourceOrganization,
	ResourceWorkspace,
	ResourceMember,
	ResourceBilling,
	ResourceScan,
	ResourceTarget,
	ResourceReport,
	ResourceFinding,
	ResourceAPIKey,
	ResourceWebhook,
	ResourceIntegration,
	ResourceAuditLog,
}

// crudActions are the ordinary verbs applied to a resource. ActionTransferOwnership
// is handled out-of-band because it only makes sense on Organization.
var crudActions = []Action{ActionCreate, ActionRead, ActionUpdate, ActionDelete}

// allowMatrix is the static authorisation table derived from Requirement 4.2.
// It is built at package initialisation from declarative rules to keep the
// authoring concise while still producing the (role, action, resource) → bool
// map that callers query through Allow.
var allowMatrix = buildAllowMatrix()

func buildAllowMatrix() map[rbacCell]bool {
	m := make(map[rbacCell]bool, len(allResources)*len(crudActions)*4+8)

	// --- Owner ----------------------------------------------------------
	// "Owner may perform any action including billing, deletion, and Member
	// role changes." We grant CRUD on every resource plus TransferOwnership
	// on Organization. Owner is the only role that may transfer ownership.
	for _, r := range allResources {
		for _, a := range crudActions {
			m[rbacCell{RoleOwner, a, r}] = true
		}
	}
	m[rbacCell{RoleOwner, ActionTransferOwnership, ResourceOrganization}] = true

	// --- Admin ----------------------------------------------------------
	// "Admin may perform any action except deleting the Organization,
	// transferring ownership, or changing the Owner's Role." Granular
	// "Owner's Role" enforcement happens in MemberService; the matrix
	// exposes the two boundaries that *can* be expressed at this level:
	// no Delete on Organization and no TransferOwnership.
	for _, r := range allResources {
		for _, a := range crudActions {
			m[rbacCell{RoleAdmin, a, r}] = true
		}
	}
	delete(m, rbacCell{RoleAdmin, ActionDelete, ResourceOrganization})

	// --- Member ---------------------------------------------------------
	// "Member may create and manage Scans, Targets, Reports, API_Keys,
	// Webhooks, and Integrations within Workspaces it has access to but
	// may not invite Members or change billing." Read access is universal
	// so Members can browse the Organization, the Workspace they belong
	// to, the Members list, audit log entries about their own work, etc.
	// Per Requirement 6.10 a Member may also update Finding status, so we
	// grant ActionUpdate on Finding even though Member cannot create or
	// delete a Finding directly (findings are produced by the Scan_Engine).
	for _, r := range allResources {
		m[rbacCell{RoleMember, ActionRead, r}] = true
	}
	memberManageable := []Resource{
		ResourceScan,
		ResourceTarget,
		ResourceReport,
		ResourceAPIKey,
		ResourceWebhook,
		ResourceIntegration,
	}
	for _, r := range memberManageable {
		for _, a := range []Action{ActionCreate, ActionUpdate, ActionDelete} {
			m[rbacCell{RoleMember, a, r}] = true
		}
	}
	m[rbacCell{RoleMember, ActionUpdate, ResourceFinding}] = true

	// --- Viewer ---------------------------------------------------------
	// "Viewer may read but may not create, modify, or delete any resource."
	for _, r := range allResources {
		m[rbacCell{RoleViewer, ActionRead, r}] = true
	}

	return m
}

// Allow reports whether the given (role, action, resource) tuple is
// permitted by the static matrix derived from Requirement 4.2. Unknown
// roles, actions, or resources always return false; callers must select a
// constant defined in this file.
func Allow(role Role, action Action, resource Resource) bool {
	return allowMatrix[rbacCell{role: role, action: action, resource: resource}]
}

// roleContextKey is the unexported context key used to stash the active
// Role on a request context. Using a private struct type rules out
// collisions with keys from other packages.
type roleContextKey struct{}

// WithRole returns a copy of ctx that carries the given Role. The active
// role is resolved during authentication and consumed by RequireRole and
// by Allow at the call site.
func WithRole(ctx context.Context, role Role) context.Context {
	return context.WithValue(ctx, roleContextKey{}, role)
}

// RoleFromContext returns the Role stored on ctx (if any) and a boolean
// indicating whether one was found.
func RoleFromContext(ctx context.Context) (Role, bool) {
	v, ok := ctx.Value(roleContextKey{}).(Role)
	return v, ok
}

// RequireRole returns a chi-compatible middleware factory that allows the
// request through only when the active role on the request context has
// rank ≥ min in the Owner > Admin > Member > Viewer hierarchy.
//
// On missing role or insufficient rank the middleware terminates the
// request with HTTP 403 and the JSON error body { "error": "forbidden_role" },
// matching design.md's error-code catalogue.
//
// RequireRole panics if min is not one of the four canonical Role
// constants — that would be a programming error caught at boot.
func RequireRole(min Role) func(http.Handler) http.Handler {
	minRank, ok := roleRank[min]
	if !ok {
		panic("orgs.RequireRole: unknown role " + string(min))
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			role, present := RoleFromContext(r.Context())
			if !present {
				writeForbiddenRole(w)
				return
			}
			rank, known := roleRank[role]
			if !known || rank < minRank {
				writeForbiddenRole(w)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// writeForbiddenRole emits the canonical 403 response body. It is a small
// internal helper so the response shape is consistent across all RBAC
// rejections.
func writeForbiddenRole(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	// json.Encode on a tiny string map cannot fail; ignore the error.
	_ = json.NewEncoder(w).Encode(map[string]string{"error": "forbidden_role"})
}
