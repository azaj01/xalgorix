// Principal helpers for the chi router.
//
// This file adds the small context-key helpers the org / workspace /
// member endpoints need to identify the caller. The auth middleware
// (added by Phase 2) is responsible for resolving the session cookie
// or `Authorization: Bearer` token onto an Account and stamping the
// Account id plus the active Role onto the request context. The
// handlers in `orgs_handler.go` then read those values via the
// helpers below and via [orgs.RoleFromContext] (declared in the
// `internal/cloud/orgs` package alongside [orgs.RequireRole]).
//
// Created by task 3.6 — `Org/workspace/member endpoints`.
// Requirements: 4.1, 4.6, 4.10, 8.1.
package api

import (
	"context"

	"github.com/google/uuid"
)

// principalCtxKey is the unexported context key that carries the
// authenticated Account id. Using an unexported struct type rules
// out collisions with keys defined in other packages.
type principalCtxKey struct{}

// WithAccountID returns a copy of ctx that carries accountID. An
// uuid.Nil value is not attached so callers can safely pass an
// unresolved id without polluting the context.
func WithAccountID(ctx context.Context, accountID uuid.UUID) context.Context {
	if accountID == uuid.Nil {
		return ctx
	}
	return context.WithValue(ctx, principalCtxKey{}, accountID)
}

// AccountIDFromContext returns the Account id stored in ctx by
// [WithAccountID], or uuid.Nil if none was set. The boolean return
// makes the "absent" case unambiguous for the handler error paths.
func AccountIDFromContext(ctx context.Context) (uuid.UUID, bool) {
	if ctx == nil {
		return uuid.Nil, false
	}
	v, ok := ctx.Value(principalCtxKey{}).(uuid.UUID)
	if !ok || v == uuid.Nil {
		return uuid.Nil, false
	}
	return v, true
}
