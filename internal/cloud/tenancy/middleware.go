// Per-request transactional tenancy middleware. The package doc lives
// in doc.go; this file implements `WithTenant`, the chi-style
// middleware factory.
//
// `WithTenant` opens a per-request PostgreSQL transaction, stamps the
// resolved Organization and Workspace identifiers into the transaction
// via `set_config('app.organization_id', ..., true)` and
// `set_config('app.workspace_id', ..., true)`, runs the next handler
// with the transaction-bearing context, and commits on success or
// rolls back otherwise. Because `set_config(..., true)` is
// "SET LOCAL"-equivalent (transaction scoped), the GUCs cannot leak
// between concurrent requests sharing the pool.
//
// To keep this task (1.12) independent from the pgx pool wrapper task
// (1.11), the middleware does not import pgx directly. It accepts a
// `BeginTxFunc` factory and a tiny `Tx` interface, both of which the
// caller can satisfy with the real pgx wrapper (or a fake in tests).
//
// Added by task 1.12 — `internal/cloud/tenancy` middleware.
// Requirements: 1.3, 1.5, 1.6.
package tenancy

import (
	"context"
	"errors"
	"net/http"
)

// TxOptions captures the subset of transaction options the middleware
// needs to communicate to the underlying database driver. Concrete
// implementations may translate this into pgx.TxOptions.
type TxOptions struct {
	// IsoLevel maps onto the SQL standard isolation levels. Empty
	// string requests the driver default ("read committed" for
	// PostgreSQL).
	IsoLevel string
	// AccessMode is "read only" or "read write"; empty string
	// requests the driver default.
	AccessMode string
}

// Tx is the minimal abstraction over a PostgreSQL transaction the
// middleware needs. It is satisfied by pgx.Tx (with a thin shim) and
// by the test fake in `middleware_test.go`.
type Tx interface {
	// Exec runs a SQL statement that does not return rows. The
	// middleware uses this to invoke `set_config` for the tenancy
	// GUCs.
	Exec(ctx context.Context, sql string, args ...any) error
	// Commit ends the transaction and persists any work performed
	// inside it.
	Commit(ctx context.Context) error
	// Rollback discards any work performed inside the transaction.
	// Implementations should treat Rollback after Commit as a
	// no-op so the middleware's defensive defer is safe.
	Rollback(ctx context.Context) error
}

// BeginTxFunc opens a new transaction tied to ctx and returns a
// (possibly enriched) context plus the transaction handle. Returning a
// new context lets the underlying wrapper attach the tx for downstream
// consumers (for example, `internal/cloud/db/pgxctx.WithTx`) without
// the tenancy package having to know the wrapper's context key.
type BeginTxFunc func(ctx context.Context, opts TxOptions) (context.Context, Tx, error)

// txCtxKey is the context key under which `WithTenant` stores the
// active transaction. Handlers can retrieve it with `TxFromContext`
// when they need to participate in the request's transaction.
type txCtxKey struct{}

// erroredCtxKey marks the request context as failed so the deferred
// commit/rollback decision can roll back instead.
type erroredCtxKey struct{}

// TxFromContext returns the *Tx attached by `WithTenant`, or nil if
// the middleware did not run for the current request.
func TxFromContext(ctx context.Context) Tx {
	if ctx == nil {
		return nil
	}
	if tx, ok := ctx.Value(txCtxKey{}).(Tx); ok {
		return tx
	}
	return nil
}

// MarkErrored flags the current request as failed so `WithTenant`
// rolls back the transaction even when the response status code is
// otherwise successful. Handlers that detect a problem after writing
// a partial response should call this.
func MarkErrored(ctx context.Context) {
	if ctx == nil {
		return
	}
	if flag, ok := ctx.Value(erroredCtxKey{}).(*bool); ok && flag != nil {
		*flag = true
	}
}

// ErrNoTenant is returned (and surfaced as HTTP 401) when a mutating
// request reaches the middleware without a resolved Organization or
// Workspace. Read-only requests are allowed to flow through with no
// tenant for endpoints that intentionally bypass tenancy (for example,
// `/healthz`); typical deployments mount `WithTenant` only on routes
// that require tenant scoping.
var ErrNoTenant = errors.New("tenancy: no resolved tenant for mutating request")

// WithTenant returns a chi-compatible middleware that opens a
// transaction per request, stamps `app.organization_id` and
// `app.workspace_id` GUCs onto it, runs the next handler, and then
// commits on success or rolls back otherwise.
//
// Behaviour summary:
//
//   - Mutating requests (POST/PUT/PATCH/DELETE) without a resolved
//     tenant are rejected with HTTP 401 before any transaction is
//     opened.
//   - When `BeginTxFunc` returns an error, the middleware responds
//     with HTTP 500 and never invokes `next`.
//   - When any of the `set_config` calls fails, the transaction is
//     rolled back and the middleware responds with HTTP 500.
//   - When the handler panics, the panic is re-raised after the
//     transaction is rolled back, preserving the panic stack for an
//     outer recovery middleware.
//   - When the handler returns normally and the request was not
//     marked errored, the transaction is committed.
func WithTenant(beginTx BeginTxFunc) func(http.Handler) http.Handler {
	if beginTx == nil {
		panic("tenancy.WithTenant: BeginTxFunc must not be nil")
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			orgID := OrgID(ctx)
			workspaceID := WorkspaceID(ctx)

			if isMutating(r.Method) && (orgID == "" || workspaceID == "") {
				http.Error(w, "unauthorized: no resolved tenant", http.StatusUnauthorized)
				return
			}

			ctx, tx, err := beginTx(ctx, TxOptions{IsoLevel: "read committed"})
			if err != nil {
				http.Error(w, "failed to begin tenant transaction", http.StatusInternalServerError)
				return
			}

			// Stamp tenancy GUCs onto the transaction. Both calls
			// use `set_config(..., true)` so the values are
			// scoped to the current transaction (equivalent to
			// SET LOCAL) and cannot leak across pooled
			// connections.
			if orgID != "" {
				if err := tx.Exec(ctx, `SELECT set_config('app.organization_id', $1, true)`, orgID); err != nil {
					_ = tx.Rollback(ctx)
					http.Error(w, "failed to set tenant context", http.StatusInternalServerError)
					return
				}
			}
			if workspaceID != "" {
				if err := tx.Exec(ctx, `SELECT set_config('app.workspace_id', $1, true)`, workspaceID); err != nil {
					_ = tx.Rollback(ctx)
					http.Error(w, "failed to set tenant context", http.StatusInternalServerError)
					return
				}
			}

			errored := new(bool)
			ctx = context.WithValue(ctx, txCtxKey{}, tx)
			ctx = context.WithValue(ctx, erroredCtxKey{}, errored)

			// Wrap the response writer so we can detect 5xx
			// responses and roll back even when handlers do not
			// explicitly call MarkErrored.
			rw := &statusRecorder{ResponseWriter: w, status: http.StatusOK}

			panicked := true
			defer func() {
				// Per design: commit only on a successful
				// mutating request; otherwise roll back.
				// Read-only requests roll back so the
				// snapshot is released cheaply without
				// flushing WAL.
				shouldCommit := !panicked &&
					!*errored &&
					rw.status < http.StatusInternalServerError &&
					isMutating(r.Method)
				if shouldCommit {
					if err := tx.Commit(ctx); err != nil {
						// Best-effort rollback in case
						// the driver leaves the tx in
						// an indeterminate state.
						_ = tx.Rollback(ctx)
					}
				} else {
					_ = tx.Rollback(ctx)
				}
			}()

			next.ServeHTTP(rw, r.WithContext(ctx))
			panicked = false
		})
	}
}

// isMutating reports whether method is one of the HTTP verbs that
// changes server-side state. Read-only verbs are allowed to flow
// through without a resolved tenant; the actual data scoping is still
// enforced by RLS because no GUC is set.
func isMutating(method string) bool {
	switch method {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return true
	default:
		return false
	}
}

// statusRecorder is a minimal http.ResponseWriter wrapper that
// captures the status code so the middleware can roll back on 5xx.
type statusRecorder struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
}

func (s *statusRecorder) WriteHeader(code int) {
	if !s.wroteHeader {
		s.status = code
		s.wroteHeader = true
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusRecorder) Write(b []byte) (int, error) {
	if !s.wroteHeader {
		s.wroteHeader = true
	}
	return s.ResponseWriter.Write(b)
}
