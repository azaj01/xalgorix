// Package scans implements the Cloud_Platform scan dispatch pipeline: the
// Redis-backed quota service, target-verification gating on dispatch, the
// NATS JetStream `scans.dispatch` publisher, the scan lifecycle state
// machine, and the cron scheduler that materialises recurring scans into
// concrete jobs.
//
// This package corresponds to the design.md section
// "Components and Interfaces → internal/cloud/scans" with concrete files
// (dispatch.go, quota.go, lifecycle.go, scheduler.go, events.go) added by
// Phase 5 tasks 5.1 through 5.11.
//
// Created by task 0.1 — Bootstrap Go module layout.
// Requirements: 1.1, 1.9
package scans
