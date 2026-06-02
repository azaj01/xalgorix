// Sanity tests for the observability bootstrap. They exercise the
// public surface of MustInit, Registry, and the request-scoped
// middlewares end-to-end without touching any live OTLP receiver,
// Sentry project, or external network — those sinks are deliberately
// unset in the fake config so the fail-soft path documented in
// `init.go` is the one under test.
package observability

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/rs/zerolog"
)

func TestMustInit_FakeConfig_DoesNotPanic(t *testing.T) {
	var buf bytes.Buffer
	cfg := Config{
		ServiceName: "xalgorix-cloud",
		Env:         "test",
		Version:     "v0.0.0-test",
		LogLevel:    "info",
		LogOutput:   &buf,
		// OTLPEndpoint and SentryDSN intentionally empty: this test
		// asserts the fail-soft path does not panic and produces a
		// usable shutdown function.
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	shutdown := MustInit(ctx, cfg)
	if shutdown == nil {
		t.Fatal("MustInit returned a nil shutdown function")
	}

	// Registry must be set after MustInit.
	if Registry() == nil {
		t.Fatal("Registry() returned nil after MustInit")
	}

	// The bootstrap log line must mention the well-known event name
	// so operators can grep for it.
	if !bytesContains(buf.Bytes(), `"event":"observability_initialized"`) {
		t.Fatalf("expected observability_initialized event, got: %s", buf.String())
	}
	if !bytesContains(buf.Bytes(), `"service":"xalgorix-cloud"`) {
		t.Fatalf("expected service field, got: %s", buf.String())
	}
	if !bytesContains(buf.Bytes(), `"env":"test"`) {
		t.Fatalf("expected env field, got: %s", buf.String())
	}
	if !bytesContains(buf.Bytes(), `"version":"v0.0.0-test"`) {
		t.Fatalf("expected version field, got: %s", buf.String())
	}

	// Shutdown should run cleanly when the context is healthy.
	if err := shutdown(ctx); err != nil {
		t.Fatalf("shutdown returned error: %v", err)
	}
}

func TestMustInit_AppliesDefaults(t *testing.T) {
	var buf bytes.Buffer
	shutdown := MustInit(context.Background(), Config{LogOutput: &buf})
	t.Cleanup(func() { _ = shutdown(context.Background()) })

	// Default service name and env should appear in the logger.
	if !bytesContains(buf.Bytes(), `"service":"xalgorix-cloud"`) {
		t.Fatalf("default service name missing: %s", buf.String())
	}
	if !bytesContains(buf.Bytes(), `"env":"dev"`) {
		t.Fatalf("default env missing: %s", buf.String())
	}
	if !bytesContains(buf.Bytes(), `"version":"unknown"`) {
		t.Fatalf("default version missing: %s", buf.String())
	}
}

func TestSplitOTLPEndpoint(t *testing.T) {
	cases := []struct {
		in         string
		wantScheme string
		wantHost   string
	}{
		{"", "", ""},
		{"tempo:4318", "", "tempo:4318"},
		{"http://tempo:4318", "http", "tempo:4318"},
		{"https://tempo:4318", "http", "tempo:4318"}, // TLS terminated upstream
		{"grpc://tempo:4317", "grpc", "tempo:4317"},
		{"GRPC://tempo:4317", "grpc", "tempo:4317"},
	}
	for _, tc := range cases {
		gotScheme, gotHost := splitOTLPEndpoint(tc.in)
		if gotScheme != tc.wantScheme || gotHost != tc.wantHost {
			t.Errorf("splitOTLPEndpoint(%q) = (%q,%q); want (%q,%q)", tc.in, gotScheme, gotHost, tc.wantScheme, tc.wantHost)
		}
	}
}

// TestLoggerMiddleware_StampsCorrelationFields wires up the public
// middleware stack end-to-end and asserts that the JSON log line for
// the served request contains every correlation field named in
// Requirement 12.1. The stack mirrors the real ordering used by
// `internal/cloud/api/router.go` (added in task 8.1): RequestID first,
// tenancy second, Logger third, so the per-request logger sees every
// correlation field by the time it is built.
func TestLoggerMiddleware_StampsCorrelationFields(t *testing.T) {
	var buf bytes.Buffer
	logger := zerolog.New(&buf).With().Timestamp().Str("service", "xalgorix-cloud").Logger()

	// Tenancy middleware stand-in — in production, internal/cloud/tenancy
	// will stamp these from the resolved Principal. Here we simulate
	// that step so the LoggerMiddleware sees the fields when it builds
	// its per-request logger.
	tenancyMW := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := WithOrganizationID(r.Context(), "org_123")
			ctx = WithWorkspaceID(ctx, "ws_456")
			ctx = WithAccountID(ctx, "acc_789")
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}

	app := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Emit a marker line through the per-request logger so we
		// can confirm tenancy fields propagate to handler logs.
		LoggerFromContext(r.Context()).Info().Str("event", "handler_marker").Msg("ok")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "ok")
	})

	handler := RequestIDMiddleware(tenancyMW(LoggerMiddleware(logger)(app)))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/health", nil)
	req.Header.Set("X-Request-ID", "req-abcdef")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if got := rec.Header().Get("X-Request-ID"); got != "req-abcdef" {
		t.Fatalf("inbound X-Request-ID not echoed; got %q", got)
	}

	// The buffer holds at least one JSON line per emitted log entry.
	// We assert the trailing http_request entry has the expected
	// shape: request_id, method, path, status, and the marker entry
	// emitted from inside the handler picks up the tenancy fields.
	lines := splitLines(buf.Bytes())
	var sawMarker, sawHTTP bool
	for _, line := range lines {
		var m map[string]any
		if err := json.Unmarshal(line, &m); err != nil {
			t.Fatalf("invalid JSON line %q: %v", string(line), err)
		}
		switch m["event"] {
		case "handler_marker":
			sawMarker = true
			if m["organization_id"] != "org_123" {
				t.Errorf("handler_marker missing organization_id: %v", m)
			}
			if m["workspace_id"] != "ws_456" {
				t.Errorf("handler_marker missing workspace_id: %v", m)
			}
			if m["account_id"] != "acc_789" {
				t.Errorf("handler_marker missing account_id: %v", m)
			}
			if m["request_id"] != "req-abcdef" {
				t.Errorf("handler_marker missing request_id: %v", m)
			}
		case "http_request":
			sawHTTP = true
			if m["request_id"] != "req-abcdef" {
				t.Errorf("http_request missing request_id: %v", m)
			}
			if m["method"] != "GET" {
				t.Errorf("http_request method = %v", m["method"])
			}
			if m["path"] != "/api/v1/health" {
				t.Errorf("http_request path = %v", m["path"])
			}
			if int(m["status"].(float64)) != http.StatusOK {
				t.Errorf("http_request status = %v", m["status"])
			}
		}
	}
	if !sawMarker {
		t.Errorf("expected handler_marker line; got: %s", buf.String())
	}
	if !sawHTTP {
		t.Errorf("expected http_request line; got: %s", buf.String())
	}
}

func TestRequestIDMiddleware_GeneratesIDWhenMissing(t *testing.T) {
	var seen string
	handler := RequestIDMiddleware(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		seen = RequestIDFromContext(r.Context())
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if len(seen) != 32 {
		t.Fatalf("expected 32-char request ID, got %q", seen)
	}
	if rec.Header().Get("X-Request-ID") != seen {
		t.Fatalf("response header %q != ctx value %q", rec.Header().Get("X-Request-ID"), seen)
	}
}

// helpers ---------------------------------------------------------------

func bytesContains(haystack []byte, needle string) bool {
	return bytes.Contains(haystack, []byte(needle))
}

func splitLines(b []byte) [][]byte {
	if len(b) == 0 {
		return nil
	}
	out := bytes.Split(b, []byte("\n"))
	// Trim any trailing empty fragment from a final newline.
	if len(out) > 0 && len(out[len(out)-1]) == 0 {
		out = out[:len(out)-1]
	}
	return out
}
