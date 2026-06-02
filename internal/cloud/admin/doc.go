// Package admin implements the back-office services for Xalgorix
// Cloud_Platform operators: tenant search, time-boxed impersonation
// (60-minute `__Host-xalgorix_impersonation` JWT with audit emission),
// per-org feature flags backed by a 30-second Redis cache, and the global
// kill switch backed by a singleton `kill_switch` row.
//
// This package corresponds to the design.md section
// "Components and Interfaces → internal/cloud/admin". Concrete services
// land in Phase 12 tasks 12.1 through 12.9.
//
// Created by task 0.1 — Bootstrap Go module layout.
// Requirements: 1.1, 1.9
package admin
