// Package findings implements finding ingestion, status transitions
// (open / verified / false_positive / wont_fix), and dedup keyed on
// (workspace_id, target_id, signature_hash) for the Xalgorix
// Cloud_Platform.
//
// This package corresponds to the design.md section
// "Components and Interfaces → internal/cloud/findings". Implementation
// details are filled in by Phase 5 task 5.9 (findings ingest with dedup)
// and Phase 8 task 8.6 (findings REST endpoints).
//
// Created by task 0.1 — Bootstrap Go module layout.
// Requirements: 1.1, 1.9
package findings
