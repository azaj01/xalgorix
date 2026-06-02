package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// helper that runs a request through the middleware and returns the
// response so each test can assert on the headers it cares about.
func runMiddleware(t *testing.T, opts SecurityHeaderOptions) *http.Response {
	t.Helper()
	mw := SecurityHeaders(opts)
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	req := httptest.NewRequest(http.MethodGet, "https://app.xalgorix.com/", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	return rr.Result()
}

// boolPtr is a tiny helper to populate the *bool option fields without
// littering each test with an inline named variable.
func boolPtr(b bool) *bool { return &b }

func TestSecurityHeaders_HSTSDefault(t *testing.T) {
	t.Parallel()
	resp := runMiddleware(t, SecurityHeaderOptions{})
	got := resp.Header.Get("Strict-Transport-Security")

	wantSeconds := int64((365 * 24 * time.Hour) / time.Second)
	want := "max-age=" + itoa(wantSeconds) + "; includeSubDomains; preload"
	if got != want {
		t.Fatalf("Strict-Transport-Security = %q, want %q", got, want)
	}
}

func TestSecurityHeaders_HSTSCustomDuration(t *testing.T) {
	t.Parallel()
	resp := runMiddleware(t, SecurityHeaderOptions{
		HSTSMaxAge:            48 * time.Hour,
		HSTSIncludeSubdomains: boolPtr(false),
		HSTSPreload:           boolPtr(false),
	})
	got := resp.Header.Get("Strict-Transport-Security")
	want := "max-age=172800"
	if got != want {
		t.Fatalf("Strict-Transport-Security = %q, want %q", got, want)
	}
}

func TestSecurityHeaders_HSTSDisabled(t *testing.T) {
	t.Parallel()
	resp := runMiddleware(t, SecurityHeaderOptions{HSTSEnabled: boolPtr(false)})
	if got := resp.Header.Get("Strict-Transport-Security"); got != "" {
		t.Fatalf("Strict-Transport-Security = %q, want empty when disabled", got)
	}
	// Even when HSTS is off, the supplementary headers are still
	// expected — they protect non-TLS attack surface (MIME sniffing,
	// referrer leakage, powerful-feature access) regardless of TLS.
	if got := resp.Header.Get("X-Content-Type-Options"); got != "nosniff" {
		t.Fatalf("X-Content-Type-Options = %q, want nosniff", got)
	}
}

func TestSecurityHeaders_CSPDefault(t *testing.T) {
	t.Parallel()
	resp := runMiddleware(t, SecurityHeaderOptions{})
	got := resp.Header.Get("Content-Security-Policy")
	want := "default-src 'self'; img-src 'self' data: https:; script-src 'self' 'wasm-unsafe-eval'; style-src 'self' 'unsafe-inline'; connect-src 'self' wss:; frame-ancestors 'none'; base-uri 'self'; form-action 'self'; object-src 'none'; upgrade-insecure-requests; report-to xalgorix-csp; report-uri /api/internal/csp-report"
	if got != want {
		t.Fatalf("Content-Security-Policy mismatch\n got: %s\nwant: %s", got, want)
	}
}

func TestSecurityHeaders_CSPOverrideReplacesExisting(t *testing.T) {
	t.Parallel()
	resp := runMiddleware(t, SecurityHeaderOptions{
		CSPDirectives: map[string]string{
			"connect-src": "'self' wss: https://api.partner.example",
		},
	})
	got := resp.Header.Get("Content-Security-Policy")
	if !strings.Contains(got, "connect-src 'self' wss: https://api.partner.example;") &&
		!strings.HasSuffix(got, "connect-src 'self' wss: https://api.partner.example") {
		t.Fatalf("expected overridden connect-src, got %q", got)
	}
	// Other defaults should still be present and order should be
	// preserved (default-src first, frame-ancestors before base-uri,
	// etc.).
	if !strings.HasPrefix(got, "default-src 'self';") {
		t.Fatalf("expected default-src to remain first, got %q", got)
	}
	if !strings.Contains(got, "frame-ancestors 'none'") {
		t.Fatalf("expected frame-ancestors to be preserved, got %q", got)
	}
}

func TestSecurityHeaders_CSPOverrideAddsNewDirective(t *testing.T) {
	t.Parallel()
	resp := runMiddleware(t, SecurityHeaderOptions{
		CSPDirectives: map[string]string{
			"font-src": "'self' https://fonts.gstatic.com",
		},
	})
	got := resp.Header.Get("Content-Security-Policy")
	if !strings.Contains(got, "font-src 'self' https://fonts.gstatic.com") {
		t.Fatalf("expected font-src directive in CSP, got %q", got)
	}
	// The existing default directives must remain unchanged when an
	// overlay only adds a new directive.
	if !strings.Contains(got, "default-src 'self';") {
		t.Fatalf("expected default-src directive to remain, got %q", got)
	}
}

func TestSecurityHeaders_CSPOverrideRemovesDirective(t *testing.T) {
	t.Parallel()
	resp := runMiddleware(t, SecurityHeaderOptions{
		CSPDirectives: map[string]string{
			"report-uri": "",
		},
	})
	got := resp.Header.Get("Content-Security-Policy")
	if strings.Contains(got, "report-uri") {
		t.Fatalf("expected report-uri to be removed, got %q", got)
	}
	if !strings.Contains(got, "report-to xalgorix-csp") {
		t.Fatalf("expected report-to to remain when only report-uri is removed, got %q", got)
	}
}

func TestSecurityHeaders_SupplementaryHeaders(t *testing.T) {
	t.Parallel()
	resp := runMiddleware(t, SecurityHeaderOptions{})

	cases := []struct {
		header string
		want   string
	}{
		{"X-Content-Type-Options", "nosniff"},
		{"Referrer-Policy", "strict-origin-when-cross-origin"},
		{"Permissions-Policy", "camera=(), microphone=(), geolocation=()"},
	}
	for _, c := range cases {
		if got := resp.Header.Get(c.header); got != c.want {
			t.Errorf("%s = %q, want %q", c.header, got, c.want)
		}
	}
}

func TestSecurityHeaders_PassesThroughHandler(t *testing.T) {
	t.Parallel()
	mw := SecurityHeaders(SecurityHeaderOptions{})
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTeapot)
		_, _ = w.Write([]byte("brewing"))
	}))
	req := httptest.NewRequest(http.MethodGet, "https://app.xalgorix.com/", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusTeapot {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusTeapot)
	}
	if rr.Body.String() != "brewing" {
		t.Fatalf("body = %q, want %q", rr.Body.String(), "brewing")
	}
	// Headers should still be applied even when the inner handler
	// writes a body.
	if got := rr.Header().Get("Content-Security-Policy"); got == "" {
		t.Fatal("expected CSP header to be set even when handler writes a body")
	}
}

// itoa is a tiny strconv.FormatInt wrapper that keeps the test cases
// readable without pulling strconv into every assertion.
func itoa(n int64) string {
	if n == 0 {
		return "0"
	}
	neg := false
	if n < 0 {
		neg = true
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
