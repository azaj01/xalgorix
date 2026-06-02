// Package db owns the PostgreSQL access layer for the Xalgorix
// Cloud_Platform. It hosts the embedded `goose` migrations under
// `internal/cloud/db/migrations`, the pgx pool wrapper, and the
// `pgxctx`-style helpers used by the tenancy middleware to attach a
// per-request transaction (with `SET LOCAL app.organization_id` and
// `app.workspace_id`) to the request context.
//
// This package corresponds to the design.md section "Data Models" and to
// the high-level architecture diagram's PostgreSQL data plane. The
// migration loader and the pgx pool wrapper are added by Phase 1 tasks
// 1.1 and 1.11; subsequent migration tasks (1.2 through 1.10) populate
// `migrations/` with the schema described in `design.md → Data Models`.
//
// Created by task 0.1 — Bootstrap Go module layout.
// Requirements: 1.1, 1.9
package db
