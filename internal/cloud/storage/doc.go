// Package storage implements the S3 + KMS object-storage wrapper for the
// Xalgorix Cloud_Platform. The constructor enforces that every key starts
// with `org/{org_id}/workspace/{ws_id}/`; any key whose prefix does not
// match the active request principal returns
// `ErrTenantIsolationViolation` and emits a `tenant_isolation_violation`
// audit event. Presigned report URLs are issued with TTL ≤ 15 minutes.
//
// This package corresponds to the design.md section
// "Components and Interfaces → internal/cloud/storage" and is the
// component referenced by the "Tenant isolation strategy (architectural)"
// table for per-tenant S3 prefix scoping. Implementation lands in Phase 1
// task 1.13 and is exercised by Phase 19 task 19.13 (retention purge
// correctness property test).
//
// Created by task 0.1 — Bootstrap Go module layout.
// Requirements: 1.1, 1.9
package storage
