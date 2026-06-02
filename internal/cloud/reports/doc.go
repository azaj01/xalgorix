// Package reports implements branded PDF report generation for the
// Xalgorix Cloud_Platform. It reuses the refactored `internal/reporting`
// primitives, writes artifacts under the per-tenant S3 prefix
// `org/{org}/workspace/{ws}/scan/{id}/report.pdf`, and exposes
// `Presign(ctx, report_id) (url, expiresAt)` with TTL ≤ 15 minutes signed
// against KMS.
//
// This package corresponds to the design.md section
// "Components and Interfaces → internal/cloud/reports". Concrete generators
// and presigners are added by Phase 6 tasks 6.1 through 6.6.
//
// Created by task 0.1 — Bootstrap Go module layout.
// Requirements: 1.1, 1.9
package reports
