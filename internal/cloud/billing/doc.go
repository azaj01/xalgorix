// Package billing implements the Dodo Payments integration for the
// Xalgorix Cloud_Platform: client construction, hosted-checkout sessions,
// signed webhooks with idempotency, the trialing → active → past_due →
// grace → downgraded subscription state machine, dunning, proration, seat
// changes, and on-demand overage metering.
//
// This package corresponds to the design.md section
// "Components and Interfaces → internal/cloud/billing". Concrete files
// (dodo.go, checkout.go, webhook.go, subscription.go, proration.go,
// seats.go, overage.go, plans.go) are added by Phase 4 tasks 4.1 through
// 4.13.
//
// Created by task 0.1 — Bootstrap Go module layout.
// Requirements: 1.1, 1.9
package billing
