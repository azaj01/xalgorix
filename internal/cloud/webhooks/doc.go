// Package webhooks implements the outbound webhook delivery worker pool
// for the Xalgorix Cloud_Platform: 16 dispatcher goroutines pulling from
// `webhook_deliveries` ordered by `next_attempt_at`, HMAC-SHA256 signing
// using the per-Webhook secret in the `X-Xalgorix-Signature` header, and
// the 8-attempt exponential retry policy (1s, 5s, 30s, 2m, 10m, 1h, 6h,
// 24h) with auto-disable on terminal failure.
//
// This package corresponds to the design.md section
// "Components and Interfaces → internal/cloud/webhooks". Concrete files
// land in Phase 9 tasks 9.1 through 9.5.
//
// Created by task 0.1 — Bootstrap Go module layout.
// Requirements: 1.1, 1.9
package webhooks
