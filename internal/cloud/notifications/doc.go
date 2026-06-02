// Package notifications implements the in-app, email, and Web Push
// notification channels for the Xalgorix Cloud_Platform. In-app
// notifications are persisted to the `notifications` table and streamed
// over SSE; email is sent via Resend with RFC 8058 one-click unsubscribe;
// Web Push is delivered via VAPID-signed payloads. Per-event preferences
// are resolved by joining `notification_preferences (account_id,
// event_type, channel)` at dispatch.
//
// This package corresponds to the design.md section
// "Components and Interfaces → internal/cloud/notifications". Channel
// dispatchers and the preference resolver are added by Phase 11 tasks 11.1
// through 11.6.
//
// Created by task 0.1 — Bootstrap Go module layout.
// Requirements: 1.1, 1.9
package notifications
