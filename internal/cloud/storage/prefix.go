package storage

import (
	"errors"
	"fmt"
	"strings"
)

// ErrTenantIsolationViolation is returned by [Storage] operations and by
// [ValidateKey] whenever a caller attempts to read, write, presign, or
// delete an S3 object whose key does not begin with the tenant-scoped
// prefix `org/{org_id}/workspace/{workspace_id}/`.
//
// The sentinel is the wire-level signal that the architectural per-tenant
// S3 prefix scoping invariant from design.md ("Tenant isolation strategy
// (architectural)") has been breached. Every package that returns this
// error MUST also emit a `tenant_isolation_violation` audit event so the
// breach is permanently recorded in `audit_events`.
//
// Validates: Requirements 1.5, 1.6.
var ErrTenantIsolationViolation = errors.New("storage: tenant isolation violation")

// ValidateKey returns nil when key is a syntactically well-formed S3
// object key that lives strictly under the tenant-scoped prefix
// `org/{orgID}/workspace/{workspaceID}/`. It returns an error wrapping
// [ErrTenantIsolationViolation] in every other case, including:
//
//   - empty orgID, workspaceID, or key
//   - orgID or workspaceID that contain a `/` (would let the caller
//     escape the prefix by stuffing additional path segments)
//   - key that does not begin with the expected prefix
//   - key that consists of the prefix only (no object suffix)
//   - key that contains a `..` path segment (defence-in-depth against
//     keys that resolve to a parent prefix)
//
// Callers that surface this error to a request handler MUST also emit a
// `tenant_isolation_violation` audit event via [EmitTenantIsolationViolation].
//
// Validates: Requirements 1.5, 1.6, 20.7.
func ValidateKey(orgID, workspaceID, key string) error {
	if orgID == "" {
		return fmt.Errorf("%w: empty org id", ErrTenantIsolationViolation)
	}
	if workspaceID == "" {
		return fmt.Errorf("%w: empty workspace id", ErrTenantIsolationViolation)
	}
	if key == "" {
		return fmt.Errorf("%w: empty key", ErrTenantIsolationViolation)
	}
	// IDs are UUIDs in production, but we defensively reject anything
	// that contains the path separator so callers cannot smuggle an
	// extra prefix segment through the org or workspace identifier.
	if strings.ContainsRune(orgID, '/') {
		return fmt.Errorf("%w: org id contains separator", ErrTenantIsolationViolation)
	}
	if strings.ContainsRune(workspaceID, '/') {
		return fmt.Errorf("%w: workspace id contains separator", ErrTenantIsolationViolation)
	}

	prefix := KeyPrefix(orgID, workspaceID)
	if !strings.HasPrefix(key, prefix) {
		return fmt.Errorf("%w: key %q must start with %q", ErrTenantIsolationViolation, key, prefix)
	}
	suffix := key[len(prefix):]
	if suffix == "" {
		return fmt.Errorf("%w: key %q has no object suffix", ErrTenantIsolationViolation, key)
	}
	// Reject `..` segments anywhere in the key — the bucket policy is
	// the authoritative escape barrier, but we also defend in depth at
	// the application layer.
	for _, seg := range strings.Split(suffix, "/") {
		if seg == ".." {
			return fmt.Errorf("%w: key %q contains parent traversal", ErrTenantIsolationViolation, key)
		}
	}
	return nil
}

// KeyPrefix returns the canonical tenant-scoped S3 key prefix used by
// every artifact written by the Cloud_Platform: scan reports, evidence,
// logos, archived events, data exports.
//
// The returned prefix always ends with a trailing slash so callers can
// concatenate the object suffix without worrying about double slashes.
//
// Validates: Requirements 1.5, 1.6.
func KeyPrefix(orgID, workspaceID string) string {
	return "org/" + orgID + "/workspace/" + workspaceID + "/"
}
