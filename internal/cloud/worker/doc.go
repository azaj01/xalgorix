// Package worker implements the per-scan Worker_Pool runtime for the
// Xalgorix Cloud_Platform. Each pod pull-subscribes the NATS JetStream
// subject `scans.dispatch` with `MaxAckPending=1`, creates a per-scan
// scratch directory on tmpfs at `/var/scan/{scan_id}`, spawns the
// existing self-hosted `xalgorix` Scan_Engine binary as a subprocess,
// pumps live telemetry to Redis Pub/Sub and Streams, mirrors events to
// `scans.events.<scan_id>` for cold replay, streams artifacts under the
// per-tenant S3 prefix, honours the per-scan cancel topic with
// SIGTERM-then-SIGKILL semantics, and enforces a 24-hour watchdog
// deadline.
//
// This package corresponds to the design.md section
// "Components and Interfaces → internal/cloud/worker". The pull
// subscriber, sandbox, telemetry pump, cancellation handler, and watchdog
// are added by Phase 5 tasks 5.5 through 5.11.
//
// Created by task 0.1 — Bootstrap Go module layout.
// Requirements: 1.1, 1.9
package worker
