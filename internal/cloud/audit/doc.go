// Package audit implements the append-only audit log for the Xalgorix
// Cloud_Platform. The underlying `audit_events` table has UPDATE and
// DELETE privileges revoked from every role; this package exposes only
// INSERT helpers and a filtered renderer with CSV / NDJSON export.
//
// This package corresponds to the design.md section
// "Components and Interfaces → internal/cloud/audit". The viewer, export
// pipeline, and the immutability-enforcing schema are filled in by tasks
// 1.9 (migration), 13.1 (viewer), and 13.2 (export).
//
// Created by task 0.1 — Bootstrap Go module layout.
// Requirements: 1.1, 1.9
package audit
