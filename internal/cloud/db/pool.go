// Package-level pgx pool wrapper for the Xalgorix Cloud_Platform.
//
// This file implements task 1.11 from the `xalgorix-saas` spec:
//
//   - [Pool] embeds *pgxpool.Pool so call sites that already understand the
//     pgx surface keep working without an extra forwarding layer.
//   - [NewPool] opens a pgx connection pool from a DSN, validates the DSN
//     format eagerly, and applies sensible Cloud_Platform defaults (sane
//     pool sizing, pool-level health checks).
//   - [ContextWithTx] / [WithTx] form the `pgxctx`-style helpers referenced
//     by design.md ("Components and Interfaces → internal/cloud/tenancy")
//     so the per-request transaction holding `SET LOCAL app.organization_id`
//     and `app.workspace_id` GUCs propagates through the request context
//     without leaking into other goroutines on the pool.
//   - [Pool.BeginTx] opens a transaction from the pool, attaches it to a
//     derived context, and returns both so the caller can run RLS-scoped
//     statements through the same tx that the GUCs were set on.
//
// Requirements: 1.3, 13.5.

package db

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Pool wraps a *pgxpool.Pool so the Cloud_Platform can extend it with
// transaction-context helpers without intercepting every pgx method.
// Callers that need raw pgx access can reach the embedded pool through
// the [Pool.Pool] selector.
type Pool struct {
	*pgxpool.Pool
}

// NewPool opens a pgx connection pool against dsn. It returns a wrapped
// [*Pool] ready for use by the API_Server, the Worker_Pool, and the
// goose-driven migration runner.
//
// The DSN may be either a libpq-style URL (`postgres://user:pass@host/db`)
// or a key=value DSN string (`host=... user=... dbname=...`). NewPool
// performs an initial `Ping` against the resolved primary so misconfig
// surfaces at startup rather than on the first request.
func NewPool(ctx context.Context, dsn string) (*Pool, error) {
	if dsn == "" {
		return nil, errors.New("cloud/db: NewPool requires a non-empty DSN")
	}

	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("cloud/db: parse DSN: %w", err)
	}

	// Apply Cloud_Platform defaults that are safe even when the DSN does
	// not specify them. Operators can still override these by encoding
	// the matching `pool_*` parameters in the DSN; ParseConfig populates
	// MinConns/MaxConns/MaxConnLifetime from those parameters and we only
	// fill the field when it was left at the zero value.
	if cfg.MaxConnLifetime == 0 {
		cfg.MaxConnLifetime = 30 * time.Minute
	}
	if cfg.MaxConnIdleTime == 0 {
		cfg.MaxConnIdleTime = 5 * time.Minute
	}
	if cfg.HealthCheckPeriod == 0 {
		cfg.HealthCheckPeriod = 30 * time.Second
	}

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("cloud/db: open pool: %w", err)
	}

	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("cloud/db: ping pool: %w", err)
	}

	return &Pool{Pool: pool}, nil
}

// txCtxKey is the unexported context key under which an in-flight
// pgx.Tx is stored. Using a private struct type prevents collisions
// with any other package's context keys.
type txCtxKey struct{}

// ContextWithTx returns a copy of ctx that carries tx so downstream
// repositories executed under the tenancy middleware can locate the
// transaction without threading it through every function signature.
//
// A nil tx is treated as "clear the value" so middleware can defensively
// reset the slot if it ever needs to detach a transaction from a
// context handed to user code.
func ContextWithTx(ctx context.Context, tx pgx.Tx) context.Context {
	return context.WithValue(ctx, txCtxKey{}, tx)
}

// WithTx returns the pgx.Tx previously attached by [ContextWithTx] (or
// by [Pool.BeginTx], which calls ContextWithTx internally) along with a
// boolean indicating whether a transaction is in scope.
//
// Repositories that must run under the tenancy GUCs check WithTx first
// and fall back to the pool only when no transaction is present. The
// fallback path MUST NOT issue mutating writes — design.md section
// "internal/cloud/tenancy" requires every write to occur inside the
// tenant-bound transaction.
func WithTx(ctx context.Context) (pgx.Tx, bool) {
	if ctx == nil {
		return nil, false
	}
	v := ctx.Value(txCtxKey{})
	if v == nil {
		return nil, false
	}
	tx, ok := v.(pgx.Tx)
	if !ok || tx == nil {
		return nil, false
	}
	return tx, true
}

// BeginTx opens a transaction with opts and returns a context that
// already carries the tx via [ContextWithTx]. Callers SHOULD pass the
// returned context to every downstream repository call so RLS-scoped
// queries reuse the same tx that the tenancy middleware applied
// `SET LOCAL app.organization_id` / `app.workspace_id` to.
//
// Lifecycle is the caller's responsibility: invoke Commit on success
// and Rollback on every other path (deferring `tx.Rollback(ctx)` is
// safe because pgx ignores rollback after commit). The returned context
// is derived from ctx, so cancellation of ctx still cancels the tx.
func (p *Pool) BeginTx(ctx context.Context, opts pgx.TxOptions) (context.Context, pgx.Tx, error) {
	if p == nil || p.Pool == nil {
		return ctx, nil, errors.New("cloud/db: BeginTx called on nil pool")
	}
	tx, err := p.Pool.BeginTx(ctx, opts)
	if err != nil {
		return ctx, nil, fmt.Errorf("cloud/db: begin tx: %w", err)
	}
	return ContextWithTx(ctx, tx), tx, nil
}
