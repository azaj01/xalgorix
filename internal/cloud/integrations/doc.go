// Package integrations implements first-party connectors (Slack, Discord,
// Microsoft Teams, Jira, GitHub Issues, Linear, AgentMail, generic
// Webhook) behind a single Adapter interface for the Xalgorix
// Cloud_Platform.
//
// This package corresponds to the design.md section
// "Components and Interfaces → internal/cloud/integrations". OAuth-based
// adapters store per-Workspace credentials KMS-encrypted in
// `integrations.encrypted_credentials`. Concrete adapters and plan gating
// are added by Phase 10 tasks 10.1 through 10.12.
//
// Created by task 0.1 — Bootstrap Go module layout.
// Requirements: 1.1, 1.9
package integrations
