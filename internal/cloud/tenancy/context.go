// Per-request tenant context helpers. The package doc lives in
// doc.go; this file adds the `WithTenantInfo`, `OrgID`, and
// `WorkspaceID` helpers used by the auth middleware to stamp the
// resolved Organization and Workspace identifiers onto the request
// context before `WithTenant` opens a tenancy-scoped transaction.
//
// Added by task 1.12 — `internal/cloud/tenancy` middleware.
// Requirements: 1.3, 1.5, 1.6.
package tenancy

import "context"

// ctxKey is an unexported type for context keys defined in this package.
// Using an unexported type prevents collisions with keys defined in
// other packages.
type ctxKey int

const (
	orgIDKey ctxKey = iota
	workspaceIDKey
)

// WithTenantInfo returns a new context that carries the supplied
// Organization and Workspace identifiers. Empty values are not
// attached so callers can safely pass partial tenant info (for
// example, when only an Organization has been resolved).
func WithTenantInfo(ctx context.Context, orgID, workspaceID string) context.Context {
	if orgID != "" {
		ctx = context.WithValue(ctx, orgIDKey, orgID)
	}
	if workspaceID != "" {
		ctx = context.WithValue(ctx, workspaceIDKey, workspaceID)
	}
	return ctx
}

// OrgID returns the Organization identifier stored in ctx by
// `WithTenantInfo`, or the empty string if none was set.
func OrgID(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	if v, ok := ctx.Value(orgIDKey).(string); ok {
		return v
	}
	return ""
}

// WorkspaceID returns the Workspace identifier stored in ctx by
// `WithTenantInfo`, or the empty string if none was set.
func WorkspaceID(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	if v, ok := ctx.Value(workspaceIDKey).(string); ok {
		return v
	}
	return ""
}
