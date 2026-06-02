// Package redis owns the Redis 7 access layer for the Xalgorix
// Cloud_Platform. It wraps `github.com/redis/go-redis/v9` so the rest of
// the cloud binary depends on a small, intent-revealing surface
// (sessions, rate limiting, pub/sub fan-out, and per-scan replay
// streams) instead of speaking the raw client API.
//
// This package corresponds to the design.md sections
// "Architecture Overview" (Redis 7 Cluster) and the per-scan replay
// pipeline that uses Redis Pub/Sub plus
// `XADD scans:replay:{scan_id} MAXLEN ~ 10000 *` for reconnect replay.
// It exposes the helpers required by Phase 1 task 1.15 — `XADD`,
// `XRANGE`, `SETNX`, `PUBLISH`, and a managed `SUBSCRIBE` channel — so
// dependent packages (`internal/cloud/auth`, `internal/cloud/scans`,
// `internal/cloud/api` WebSocket coalescer) can stay agnostic of the
// underlying client topology (single, sentinel, or cluster).
//
// Created by task 1.15 — Redis client wrapper with pub/sub helpers.
// Requirements: 6.3, 14.1
package redis
