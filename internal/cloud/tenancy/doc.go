// Package tenancy implements the per-request tenant-scoping middleware
// and quota-enforcement helpers for the Xalgorix Cloud_Platform. The
// `WithTenant` middleware opens a per-request transaction, sets
// `app.organization_id` and `app.workspace_id` GUCs via `SET LOCAL`, and
// commits or rolls back depending on whether the handler errored, so
// PostgreSQL Row-Level Security policies named `<table>_tenant_isolation`
// can enforce strict per-Workspace data scoping.
//
// This package corresponds to the design.md section
// "Components and Interfaces → internal/cloud/tenancy" and to the
// "Tenant isolation strategy (architectural)" table. Implementation is
// added by Phase 1 task 1.12 and exercised by Phase 19 task 19.1's
// property test on tenant scoping.
//
// Created by task 0.1 — Bootstrap Go module layout.
// Requirements: 1.1, 1.9
package tenancy
