package auth

import (
	"bytes"
	"context"
	"crypto/sha1" //nolint:gosec // matches production prefix derivation; same caveat as hibp.go.
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/rs/zerolog"
)

// hibpFixture builds a fake Pwned Passwords range server that returns the
// supplied lines verbatim under the canonical "/range/<prefix>" path. The
// returned URL is suitable for HTTPPwner.BaseURL.
type hibpFixture struct {
	server *httptest.Server
	called int
}

func newHIBPFixture(t *testing.T, body string, addPaddingRequired bool) *hibpFixture {
	t.Helper()
	fx := &hibpFixture{}
	mux := http.NewServeMux()
	mux.HandleFunc("/range/", func(w http.ResponseWriter, r *http.Request) {
		fx.called++
		if r.Method != http.MethodGet {
			t.Errorf("unexpected method: %s", r.Method)
		}
		if addPaddingRequired && r.Header.Get("Add-Padding") != "true" {
			t.Errorf("missing Add-Padding header; got %q", r.Header.Get("Add-Padding"))
		}
		// HIBP serves text/plain with CRLF line endings.
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, body)
	})
	fx.server = httptest.NewServer(mux)
	t.Cleanup(fx.server.Close)
	return fx
}

// suffixOf returns the 35-character uppercase SHA-1 suffix used by the
// HIBP range API for the supplied plaintext password.
func suffixOf(t *testing.T, plain string) string {
	t.Helper()
	sum := sha1.Sum([]byte(plain)) //nolint:gosec
	hexed := strings.ToUpper(hex.EncodeToString(sum[:]))
	return hexed[5:]
}

// captureLogger returns a zerolog.Logger writing JSON lines into buf so
// tests can assert that the fail-open event name was emitted exactly as
// the spec requires ("auth_hibp_unavailable").
func captureLogger(buf *bytes.Buffer) zerolog.Logger {
	return zerolog.New(buf).Level(zerolog.WarnLevel).With().Timestamp().Logger()
}

func TestHTTPPwner_PwnedTrue(t *testing.T) {
	t.Parallel()

	const password = "Abcdefgh1234"
	suffix := suffixOf(t, password)
	// Mix in a couple of unrelated entries plus the target with a
	// non-zero count to confirm the scanner correctly walks the stream.
	body := strings.Join([]string{
		"0123456789ABCDEF0123456789ABCDEF012:7",
		suffix + ":42",
		"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF:1",
	}, "\r\n") + "\r\n"

	fx := newHIBPFixture(t, body, true)
	pw := &HTTPPwner{
		Client:  &http.Client{Timeout: 2 * time.Second},
		BaseURL: fx.server.URL,
		Logger:  zerolog.Nop(),
	}

	got, err := pw.Pwned(context.Background(), password)
	if err != nil {
		t.Fatalf("Pwned returned error: %v", err)
	}
	if !got {
		t.Fatalf("Pwned(%q) = false, want true", password)
	}
	if fx.called != 1 {
		t.Fatalf("expected 1 upstream call, got %d", fx.called)
	}
}

func TestHTTPPwner_PwnedFalse(t *testing.T) {
	t.Parallel()

	const password = "Zyxwvutsrqp0987"
	suffix := suffixOf(t, password)
	// Body containing only unrelated suffixes and a padding-style line
	// (count=0) for the real suffix; both must result in (false, nil).
	body := strings.Join([]string{
		"0123456789ABCDEF0123456789ABCDEF012:9",
		suffix + ":0",
		"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF:3",
	}, "\r\n") + "\r\n"

	fx := newHIBPFixture(t, body, true)
	pw := &HTTPPwner{
		Client:  &http.Client{Timeout: 2 * time.Second},
		BaseURL: fx.server.URL,
		Logger:  zerolog.Nop(),
	}

	got, err := pw.Pwned(context.Background(), password)
	if err != nil {
		t.Fatalf("Pwned returned error: %v", err)
	}
	if got {
		t.Fatalf("Pwned(%q) = true, want false", password)
	}
}

func TestHTTPPwner_NetworkFailureFailsOpen(t *testing.T) {
	t.Parallel()

	// Bind a TCP listener and immediately close it to obtain a port that
	// is guaranteed not to be accepting connections, without depending on
	// a hard-coded value.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	addr := l.Addr().String()
	if err := l.Close(); err != nil {
		t.Fatalf("listener close: %v", err)
	}

	var logBuf bytes.Buffer
	pw := &HTTPPwner{
		Client:  &http.Client{Timeout: 500 * time.Millisecond},
		BaseURL: "http://" + addr,
		Logger:  captureLogger(&logBuf),
	}

	got, err := pw.Pwned(context.Background(), "Abcdefgh1234")
	if err != nil {
		t.Fatalf("Pwned returned error on network failure: %v", err)
	}
	if got {
		t.Fatalf("Pwned returned pwned=true on network failure; want fail-open false")
	}

	if !containsLogEvent(t, logBuf.Bytes(), "auth_hibp_unavailable", "warn") {
		t.Fatalf("expected auth_hibp_unavailable warn log line; got:\n%s", logBuf.String())
	}
}

func TestHTTPPwner_Non200StatusFailsOpen(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = io.WriteString(w, "boom")
	}))
	t.Cleanup(srv.Close)

	var logBuf bytes.Buffer
	pw := &HTTPPwner{
		Client:  &http.Client{Timeout: 2 * time.Second},
		BaseURL: srv.URL,
		Logger:  captureLogger(&logBuf),
	}

	got, err := pw.Pwned(context.Background(), "Abcdefgh1234")
	if err != nil {
		t.Fatalf("Pwned returned error on 500 status: %v", err)
	}
	if got {
		t.Fatalf("Pwned returned pwned=true on 500 status; want fail-open false")
	}

	if !containsLogEvent(t, logBuf.Bytes(), "auth_hibp_unavailable", "warn") {
		t.Fatalf("expected auth_hibp_unavailable warn log line; got:\n%s", logBuf.String())
	}
}

func TestHTTPPwner_TimeoutFailsOpen(t *testing.T) {
	t.Parallel()

	// Server intentionally blocks longer than the client timeout to
	// trigger a context-deadline-exceeded path through net/http.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-time.After(500 * time.Millisecond):
		case <-r.Context().Done():
		}
	}))
	t.Cleanup(srv.Close)

	var logBuf bytes.Buffer
	pw := &HTTPPwner{
		Client:  &http.Client{Timeout: 50 * time.Millisecond},
		BaseURL: srv.URL,
		Logger:  captureLogger(&logBuf),
	}

	got, err := pw.Pwned(context.Background(), "Abcdefgh1234")
	if err != nil {
		t.Fatalf("Pwned returned error on timeout: %v", err)
	}
	if got {
		t.Fatalf("Pwned returned pwned=true on timeout; want fail-open false")
	}

	if !containsLogEvent(t, logBuf.Bytes(), "auth_hibp_unavailable", "warn") {
		t.Fatalf("expected auth_hibp_unavailable warn log line; got:\n%s", logBuf.String())
	}
}

func TestHTTPPwner_NilContextRejected(t *testing.T) {
	t.Parallel()
	pw := &HTTPPwner{Logger: zerolog.Nop()}
	//nolint:staticcheck // intentionally exercising the nil-ctx programmer-error guard.
	got, err := pw.Pwned(nil, "Abcdefgh1234")
	if err == nil {
		t.Fatalf("Pwned(nil ctx) returned no error; want programmer-error")
	}
	if got {
		t.Fatalf("Pwned(nil ctx) returned pwned=true")
	}
}

// containsLogEvent reports whether at least one zerolog JSON line in raw
// has the given event field and level.
func containsLogEvent(t *testing.T, raw []byte, wantEvent, wantLevel string) bool {
	t.Helper()
	for _, line := range bytes.Split(bytes.TrimSpace(raw), []byte{'\n'}) {
		if len(line) == 0 {
			continue
		}
		var rec map[string]any
		if err := json.Unmarshal(line, &rec); err != nil {
			t.Logf("skipping unparseable log line %q: %v", line, err)
			continue
		}
		if asString(rec["event"]) == wantEvent && asString(rec["level"]) == wantLevel {
			return true
		}
	}
	return false
}

func asString(v any) string {
	s, ok := v.(string)
	if !ok {
		return fmt.Sprintf("%v", v)
	}
	return s
}
