// Package api implements the HTTP routing, middleware stack, request
// validation, and response shaping for the Xalgorix Cloud_Platform
// API_Server.
//
// This package corresponds to the design.md section
// "Components and Interfaces → internal/cloud/api" and is the entrypoint
// referenced by the high-level architecture diagram for every authenticated
// REST and WebSocket call. Subsequent tasks (8.1 chi router, 8.2 OpenAPI
// 3.1 spec, 8.3 schema validation, 8.13 rate limiter) flesh out router.go,
// middleware.go, errors.go, and validate.go inside this package.
//
// Created by task 0.1 — Bootstrap Go module layout.
// Requirements: 1.1, 1.9
package api
