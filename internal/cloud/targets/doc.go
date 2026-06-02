// Package targets implements target ownership verification (DNS TXT, file,
// and HTML meta-tag), the recheck cron job, and the `verified_local`
// short-circuit for loopback hostnames.
//
// This package corresponds to the design.md section
// "Components and Interfaces → internal/cloud/targets". Concrete verifiers,
// the cooldown logic, and the recheck job are added by Phase 7 tasks 7.1
// through 7.9.
//
// Created by task 0.1 — Bootstrap Go module layout.
// Requirements: 1.1, 1.9
package targets
