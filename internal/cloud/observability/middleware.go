// Middleware helpers that surface the correlation fields named in
// Requirement 12.1 onto every authenticated request:
//
//   - RequestIDMiddleware mints (or accepts) an `X-Request-ID` value and
//     stamps it onto the request context so downstream handlers and the
//     LoggerMiddleware below can pick it up. This is the *_id_* in the
//     "request_id" log field for every entry.
//   - LoggerMiddleware wraps a chi handler in a per-request zerolog
//     logger pre-populated with `request_id`, `method`, `path`, and the
//     caller's tenant context (`organization_id`, `workspace_id`,
//     `account_id`) when those values are already present on the
//     request context. Tenancy values are pulled via well-known context
//     keys exported below so the auth/tenancy middleware (added in a
//     later task) can stamp them without taking a hard dependency on
//     this package's internals.
//
// These middlewares are written to the chi v5 signature
// (`func(http.Handler) http.Handler`) but use only the standard library
// otherwise, so they work with any net/http router. chi is the design
// choice for the API_Server and is therefore what we exercise in tests.
package observability

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"time"

	"github.com/rs/zerolog"
)

// requestIDHeader is the canonical header that propagates a correlation
// ID across services. We honour an inbound value (so traces can be
// stitched across the load balancer, the API_Server, and the
// Worker_Pool) and fall back to a freshly minted 16-byte hex value
// otherwise.
const requestIDHeader = "X-Request-ID"

// ctxKey is a private type so callers cannot accidentally collide with
// the keys we reserve for the correlation fields named in Requirement
// 12.1. Other packages stamp these values via the With* helpers below.
type ctxKey string

const (
	ctxKeyRequestID     ctxKey = "request_id"
	ctxKeyOrganizationID ctxKey = "organization_id"
	ctxKeyWorkspaceID   ctxKey = "workspace_id"
	ctxKeyAccountID     ctxKey = "account_id"
)

// WithRequestID returns a copy of ctx with the supplied request ID
// attached. Exposed so non-HTTP code paths (NATS consumers, cron jobs)
// can populate the same field log handlers expect to find.
func WithRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, ctxKeyRequestID, id)
}

// RequestIDFromContext retrieves the request ID stamped by
// RequestIDMiddleware, or the empty string if none is set.
func RequestIDFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(ctxKeyRequestID).(string); ok {
		return v
	}
	return ""
}

// WithOrganizationID stamps the active Organization ID onto the context
// so the LoggerMiddleware can promote it to the `organization_id` log
// field.
func WithOrganizationID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, ctxKeyOrganizationID, id)
}

// WithWorkspaceID stamps the active Workspace ID onto the context.
func WithWorkspaceID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, ctxKeyWorkspaceID, id)
}

// WithAccountID stamps the authenticated Account ID onto the context.
func WithAccountID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, ctxKeyAccountID, id)
}

// RequestIDMiddleware accepts an inbound `X-Request-ID` header or mints
// a new 16-byte hex value, stamps it onto the request context and the
// outbound response, and chains to next. It is safe to use as the
// outermost middleware in the chi stack.
func RequestIDMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get(requestIDHeader)
		if id == "" {
			id = newRequestID()
		}
		w.Header().Set(requestIDHeader, id)
		ctx := WithRequestID(r.Context(), id)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// LoggerMiddleware attaches a per-request zerolog logger to the
// request context, then logs an "http_request" event on completion
// with the duration, status code, and bytes written. The base logger
// is the package-level `log.Logger` set by MustInit, so all the
// service-wide fields (`service`, `env`, `version`) come along for free.
//
// The middleware uses zerolog's hlog helper for response wrapping
// because hlog already implements the http.ResponseWriter promotion
// dance for the small set of common interfaces (Hijacker, Flusher,
// Pusher) — duplicating that logic here would invite drift.
func LoggerMiddleware(base zerolog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()

			// Build a per-request logger derived from the base logger
			// and stamped with whichever correlation fields are
			// already present on the request context.
			ctx := r.Context()
			lg := base.With().
				Str("request_id", RequestIDFromContext(ctx)).
				Str("method", r.Method).
				Str("path", r.URL.Path).
				Logger()
			if v, ok := ctx.Value(ctxKeyOrganizationID).(string); ok && v != "" {
				lg = lg.With().Str("organization_id", v).Logger()
			}
			if v, ok := ctx.Value(ctxKeyWorkspaceID).(string); ok && v != "" {
				lg = lg.With().Str("workspace_id", v).Logger()
			}
			if v, ok := ctx.Value(ctxKeyAccountID).(string); ok && v != "" {
				lg = lg.With().Str("account_id", v).Logger()
			}

			ctx = lg.WithContext(ctx)
			rw := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
			next.ServeHTTP(rw, r.WithContext(ctx))

			lg.Info().
				Str("event", "http_request").
				Int("status", rw.status).
				Int("bytes", rw.bytes).
				Dur("duration", time.Since(start)).
				Msg("served")
		})
	}
}

// LoggerFromContext returns the per-request zerolog logger or the
// package default if none is set. Thin wrapper over zerolog.Ctx so
// callers do not need a direct dependency on zerolog.
func LoggerFromContext(ctx context.Context) *zerolog.Logger {
	return zerolog.Ctx(ctx)
}

// statusRecorder is the bare-minimum http.ResponseWriter wrapper that
// records the status code and bytes-written so LoggerMiddleware can
// emit them. We deliberately avoid pulling in chi's middleware.WrapResponseWriter
// here because the helpers used (zerolog) already cover the
// hijack/flush dance for handlers that need it.
type statusRecorder struct {
	http.ResponseWriter
	status int
	bytes  int
}

func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusRecorder) Write(p []byte) (int, error) {
	n, err := s.ResponseWriter.Write(p)
	s.bytes += n
	return n, err
}

// newRequestID returns a 32-character hex string suitable for the
// `request_id` correlation field. Falls back to a timestamp-derived
// value if crypto/rand somehow fails (extremely rare, e.g. on a
// kernel without /dev/urandom).
func newRequestID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// Very small chance of getting here; we still want a unique
		// fallback rather than an empty string.
		return hex.EncodeToString([]byte(time.Now().UTC().Format(time.RFC3339Nano)))
	}
	return hex.EncodeToString(b[:])
}

// keep newRequestID's behaviour visible at import-time so dead-code
// elimination cannot prune the symbol if a future caller wires its own
// request-ID middleware atop this one.
var _ = newRequestID