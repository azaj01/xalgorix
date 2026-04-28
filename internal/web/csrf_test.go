package web

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/config"
)

// minimalCfgForCSRF returns a Config with auth enabled so the CSRF gate
// runs alongside the auth check. Setting credentials forces the
// session-cookie path; CSRF rejection should still happen first.
func minimalCfgForCSRF() *config.Config {
	return &config.Config{
		Username: "admin",
		Password: "test",
	}
}

// TestIsCSRFSafe covers the matrix of browser hints (Sec-Fetch-Site,
// Origin, Referer) that the CSRF middleware uses to gate state-changing
// requests. The intent is to verify cross-site browser attempts are
// rejected while non-browser API clients (no hints at all) are still
// allowed through — that's how the LLM tool layer talks to the dashboard.
func TestIsCSRFSafe(t *testing.T) {
	type tc struct {
		name    string
		method  string
		host    string
		fetch   string // Sec-Fetch-Site
		origin  string
		referer string
		want    bool
	}

	cases := []tc{
		// Read-only methods are always allowed.
		{"GET safe", "GET", "x.local", "", "", "", true},
		{"HEAD safe", "HEAD", "x.local", "", "", "", true},
		{"OPTIONS safe", "OPTIONS", "x.local", "", "", "", true},

		// Sec-Fetch-Site honored when present.
		{"same-origin allowed", "POST", "x.local", "same-origin", "https://other.tld", "", true},
		{"none allowed", "POST", "x.local", "none", "", "", true},
		{"same-site rejected", "POST", "x.local", "same-site", "", "", false},
		{"cross-site rejected", "POST", "x.local", "cross-site", "", "", false},

		// No Sec-Fetch-Site: fall back to Origin.
		{"matching origin allowed", "POST", "x.local", "", "http://x.local", "", true},
		{"mismatched origin rejected", "POST", "x.local", "", "http://attacker.tld", "", false},
		{"port-mismatched origin rejected", "POST", "x.local:1337", "", "http://x.local:9999", "", false},

		// No Origin: fall back to Referer.
		{"matching referer allowed", "POST", "x.local", "", "", "http://x.local/login", true},
		{"mismatched referer rejected", "POST", "x.local", "", "", "http://attacker.tld/", false},

		// No browser hints at all → assume non-browser API client.
		{"no hints allowed (curl)", "POST", "x.local", "", "", "", true},

		// Garbage Origin: present but unparseable host → reject.
		{"unparseable origin rejected", "POST", "x.local", "", "::not-a-url::", "", false},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := httptest.NewRequest(c.method, "/api/scan", nil)
			r.Host = c.host
			if c.fetch != "" {
				r.Header.Set("Sec-Fetch-Site", c.fetch)
			}
			if c.origin != "" {
				r.Header.Set("Origin", c.origin)
			}
			if c.referer != "" {
				r.Header.Set("Referer", c.referer)
			}
			if got := isCSRFSafe(r); got != c.want {
				t.Errorf("isCSRFSafe = %v, want %v", got, c.want)
			}
		})
	}
}

// TestAuthMiddleware_CSRFRejected confirms the middleware turns a CSRF
// failure into a 403 JSON response *before* checking the session cookie —
// otherwise a stolen cookie alone would be enough.
func TestAuthMiddleware_CSRFRejected(t *testing.T) {
	cfg := minimalCfgForCSRF()

	mw := authMiddleware(cfg)
	called := false
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("POST", "/api/scan", nil)
	req.Host = "x.local"
	req.Header.Set("Origin", "http://attacker.tld")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d (body=%q)", rr.Code, rr.Body.String())
	}
	if called {
		t.Errorf("inner handler should NOT have been called on CSRF failure")
	}
}

// TestAuthMiddleware_CSRFAllowed exercises the happy path: a legitimate
// same-origin POST should pass the CSRF gate (and then proceed to the
// session check, which 401s when no cookie is set).
func TestAuthMiddleware_CSRFAllowed(t *testing.T) {
	cfg := minimalCfgForCSRF()
	mw := authMiddleware(cfg)
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("POST", "/api/scan", nil)
	req.Host = "x.local"
	req.Header.Set("Origin", "http://x.local")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	// CSRF passes, session check fails → 401, not 403.
	if rr.Code == http.StatusForbidden {
		t.Fatalf("CSRF gate fired on a legitimate same-origin request: %s", rr.Body.String())
	}
}
