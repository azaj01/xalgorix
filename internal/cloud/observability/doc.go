// Package observability bootstraps logging, metrics, tracing, and error
// reporting for the Xalgorix Cloud_Platform. It wires a zerolog JSON
// logger with the required correlation fields, a Prometheus registry, an
// OpenTelemetry tracer that ships spans to Tempo via OTLP, and the
// Sentry hub used for error reporting with `request_id` and
// `organization_id` tags.
//
// This package corresponds to the design.md section
// "Components and Interfaces → internal/cloud/observability". The
// `MustInit(ctx, cfg)` entrypoint is the very first call inside
// `cmd/xalgorix-cloud/main.go` and is added by Phase 1 task 1.14.
//
// Created by task 0.1 — Bootstrap Go module layout.
// Requirements: 1.1, 1.9
package observability
