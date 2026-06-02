package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// csrfTestKey is a fixed 32-byte HMAC key shared across the CSRF
// tests. Hard-coding it keeps the assertions deterministic; the
// production wiring sources the key from the secret manager.
var csrfTestKey = []byte("0123456789abcdef0123456789abcdef")

// csrfTestOptions returns options suitable for the in-process test
// server. We disable Secure so httptest's plain-HTTP recorder can
// observe the cookie (browsers drop Secure cookies on http:// in
// real life — that protection is what the production default
// enables).
func csrfTestOptions() CSRFOptions {
	secure := false
	return CSRFOptions{
		Key:    csrfTestKey,
		Secure: &secure,
	}
}

// newCSRFHandler wraps an inner handler that records whether it ran
// and returns 204. Tests assert on both the response and the inner
// flag to confirm the middleware stops the request before the inner
// handler when the CSRF check fails.
func newCSRFHandler(t *testing.T, opts CSRFOptions) (http.Handler, *bool) {
	t.Helper()
	called := false
	mw := CSRF(opts)
	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusNoContent)
	})
	return mw(inner), &called
}

// extractCSRFCookie returns the Set-Cookie value of the CSRF cookie
// from a response, or the empty string if none is present.
func extractCSRFCookie(t *testing.T, resp *http.Response) *http.Cookie {
	t.Helper()
	for _, c := range resp.Cookies() {
		if c.Name == CSRFCookieName {
			return c
		}
	}
	return nil
}

// TestCSRF_GETIssuesCookie covers the issuance half of the
// double-submit pattern: a safe method gets the cookie stamped and
// passes through to the inner handler.
//
// Validates: Requirements 20.5
func TestCSRF_GETIssuesCookie(t *testing.T) {
	t.Parallel()
	handler, called := newCSRFHandler(t, csrfTestOptions())

	req := httptest.NewRequest(http.MethodGet, "https://app.xalgorix.com/api/me", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusNoContent)
	}
	if !*called {
		t.Fatal("inner handler should have run for GET")
	}
	c := extractCSRFCookie(t, rr.Result())
	if c == nil {
		t.Fatal("expected CSRF cookie to be issued on GET")
	}
	if c.Value == "" {
		t.Fatal("CSRF cookie has empty value")
	}
	if c.Path != "/" {
		t.Errorf("cookie Path = %q, want %q", c.Path, "/")
	}
	if c.HttpOnly {
		t.Error("CSRF cookie must NOT be HttpOnly — Dashboard JS reads the value")
	}
	if c.SameSite != http.SameSiteLaxMode {
		t.Errorf("cookie SameSite = %v, want Lax", c.SameSite)
	}
	if !parseToken(c.Value, csrfTestKey) {
		t.Errorf("cookie value %q failed HMAC verification", c.Value)
	}
}

// TestCSRF_PostMatchingHeaderAccepted is the happy path for the
// validation half: cookie + matching X-CSRF-Token header → request
// passes through.
//
// Validates: Requirements 20.5
func TestCSRF_PostMatchingHeaderAccepted(t *testing.T) {
	t.Parallel()
	handler, called := newCSRFHandler(t, csrfTestOptions())

	token := mintToken(csrfTestKey)
	req := httptest.NewRequest(http.MethodPost, "https://app.xalgorix.com/api/orgs", strings.NewReader("{}"))
	req.AddCookie(&http.Cookie{Name: CSRFCookieName, Value: token})
	req.Header.Set(CSRFHeaderName, token)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Fatalf("status = %d body=%q, want 204", rr.Code, rr.Body.String())
	}
	if !*called {
		t.Fatal("inner handler should have run on matching cookie+header")
	}
}

// TestCSRF_PostMismatchedHeaderRejected covers the canonical attack
// shape: cookie present, but header carries a different value (e.g.
// the attacker forged a state-changing form submit but cannot read
// the session cookie cross-origin).
//
// Validates: Requirements 20.5
func TestCSRF_PostMismatchedHeaderRejected(t *testing.T) {
	t.Parallel()
	handler, called := newCSRFHandler(t, csrfTestOptions())

	token := mintToken(csrfTestKey)
	other := mintToken(csrfTestKey)
	req := httptest.NewRequest(http.MethodPost, "https://app.xalgorix.com/api/orgs", strings.NewReader("{}"))
	req.AddCookie(&http.Cookie{Name: CSRFCookieName, Value: token})
	req.Header.Set(CSRFHeaderName, other)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("status = %d body=%q, want 403", rr.Code, rr.Body.String())
	}
	if *called {
		t.Fatal("inner handler must NOT run on mismatched CSRF token")
	}
}

// TestCSRF_PostMissingHeaderRejected covers the simpler case: cookie
// present but no header (e.g. the Dashboard JS forgot to set it, or
// an attacker is replaying a same-origin form post that did not
// include the custom header).
//
// Validates: Requirements 20.5
func TestCSRF_PostMissingHeaderRejected(t *testing.T) {
	t.Parallel()
	handler, called := newCSRFHandler(t, csrfTestOptions())

	token := mintToken(csrfTestKey)
	req := httptest.NewRequest(http.MethodPost, "https://app.xalgorix.com/api/orgs", strings.NewReader("{}"))
	req.AddCookie(&http.Cookie{Name: CSRFCookieName, Value: token})
	// Note: no X-CSRF-Token header.

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("status = %d body=%q, want 403", rr.Code, rr.Body.String())
	}
	if *called {
		t.Fatal("inner handler must NOT run when header is missing")
	}
}

// TestCSRF_BearerAuthBypass confirms API_Key requests skip the CSRF
// check entirely. The request has neither a cookie nor a header but
// is permitted because the Authorization scheme is Bearer.
//
// Validates: Requirements 20.5 (API_Key carve-out)
func TestCSRF_BearerAuthBypass(t *testing.T) {
	t.Parallel()
	handler, called := newCSRFHandler(t, csrfTestOptions())

	req := httptest.NewRequest(http.MethodPost, "https://app.xalgorix.com/api/scans", strings.NewReader("{}"))
	req.Header.Set("Authorization", "Bearer xax_live_abcdef0123456789")
	// No cookie, no X-CSRF-Token.

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Fatalf("status = %d body=%q, want 204 (Bearer auth bypasses CSRF)", rr.Code, rr.Body.String())
	}
	if !*called {
		t.Fatal("inner handler should have run on Bearer-authorized request")
	}
}

// TestCSRF_BearerAuthBypassCaseInsensitive guards the case-insensitive
// scheme match required by RFC 7235 §2.1. The lower-case "bearer"
// must still be honoured.
func TestCSRF_BearerAuthBypassCaseInsensitive(t *testing.T) {
	t.Parallel()
	handler, called := newCSRFHandler(t, csrfTestOptions())

	req := httptest.NewRequest(http.MethodDelete, "https://app.xalgorix.com/api/scans/42", nil)
	req.Header.Set("Authorization", "bearer xax_live_token")

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204 for lower-case bearer scheme", rr.Code)
	}
	if !*called {
		t.Fatal("inner handler should have run on lower-case Bearer header")
	}
}

// TestCSRF_NonBearerAuthDoesNotBypass guards against accidentally
// exempting Basic auth or other schemes — only Bearer (the API_Key
// shape) is CSRF-exempt.
func TestCSRF_NonBearerAuthDoesNotBypass(t *testing.T) {
	t.Parallel()
	handler, called := newCSRFHandler(t, csrfTestOptions())

	req := httptest.NewRequest(http.MethodPost, "https://app.xalgorix.com/api/orgs", strings.NewReader("{}"))
	req.Header.Set("Authorization", "Basic dXNlcjpwYXNz")

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 (Basic auth must not bypass CSRF)", rr.Code)
	}
	if *called {
		t.Fatal("inner handler must NOT run for Basic-auth POST without CSRF token")
	}
}

// TestCSRF_StaleSignedTokenStillValid pins the design choice: tokens
// are identifiers, not timestamps. A token signed by the same key
// "long ago" remains valid — protection comes from cookie/header
// equality, not token freshness.
//
// Validates: Requirements 20.5 (token is an identifier; cookie/header
// match is the actual protection).
func TestCSRF_StaleSignedTokenStillValid(t *testing.T) {
	t.Parallel()
	handler, called := newCSRFHandler(t, csrfTestOptions())

	// Mint a token "earlier" — there is no time component, so any
	// previously-issued, validly signed token must keep working.
	stale := mintToken(csrfTestKey)

	req := httptest.NewRequest(http.MethodPut, "https://app.xalgorix.com/api/orgs/42", strings.NewReader("{}"))
	req.AddCookie(&http.Cookie{Name: CSRFCookieName, Value: stale})
	req.Header.Set(CSRFHeaderName, stale)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204 — stale signed token must still validate", rr.Code)
	}
	if !*called {
		t.Fatal("inner handler should have run with a stale but signed token")
	}

	// The cookie should be re-stamped (not regenerated) because the
	// presented value was valid.
	c := extractCSRFCookie(t, rr.Result())
	if c == nil {
		t.Fatal("expected CSRF cookie to be re-stamped on the response")
	}
	if c.Value != stale {
		t.Errorf("cookie value = %q, want stale token %q (no rotation when valid)", c.Value, stale)
	}
}

// TestCSRF_ForgedSignatureRejected ensures an attacker who plants a
// `__Host-xalgorix_csrf` cookie via cookie-tossing or any other write
// without knowing the HMAC key cannot also forge a matching header:
// the middleware refuses to trust the planted cookie, mints a fresh
// token, and rejects the request because the planted header does not
// match the freshly issued token.
//
// Validates: Requirements 20.5 (HMAC-signed token prevents
// client-side guessing).
func TestCSRF_ForgedSignatureRejected(t *testing.T) {
	t.Parallel()
	handler, called := newCSRFHandler(t, csrfTestOptions())

	forged := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	req := httptest.NewRequest(http.MethodPost, "https://app.xalgorix.com/api/orgs", strings.NewReader("{}"))
	req.AddCookie(&http.Cookie{Name: CSRFCookieName, Value: forged})
	req.Header.Set(CSRFHeaderName, forged)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 — forged cookie/header pair must be rejected", rr.Code)
	}
	if *called {
		t.Fatal("inner handler must NOT run for forged token pair")
	}
	c := extractCSRFCookie(t, rr.Result())
	if c == nil {
		t.Fatal("expected fresh CSRF cookie to be issued after rejecting forged token")
	}
	if c.Value == forged {
		t.Fatal("middleware echoed the forged cookie back; expected a fresh server-signed token")
	}
	if !parseToken(c.Value, csrfTestKey) {
		t.Errorf("freshly issued cookie %q failed HMAC verification", c.Value)
	}
}

// TestCSRF_SafeMethodsBypass exercises every safe HTTP verb to be
// sure the middleware never demands a header for them.
func TestCSRF_SafeMethodsBypass(t *testing.T) {
	t.Parallel()
	for _, method := range []string{http.MethodGet, http.MethodHead, http.MethodOptions} {
		method := method
		t.Run(method, func(t *testing.T) {
			t.Parallel()
			handler, called := newCSRFHandler(t, csrfTestOptions())
			req := httptest.NewRequest(method, "https://app.xalgorix.com/api/me", nil)
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)
			if rr.Code != http.StatusNoContent {
				t.Fatalf("status = %d, want 204 for safe method %s", rr.Code, method)
			}
			if !*called {
				t.Fatalf("inner handler should run for safe method %s", method)
			}
		})
	}
}

// TestCSRF_StateChangingMethods covers every unsafe verb to ensure
// each one is gated by the header check.
func TestCSRF_StateChangingMethods(t *testing.T) {
	t.Parallel()
	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete} {
		method := method
		t.Run(method, func(t *testing.T) {
			t.Parallel()
			handler, called := newCSRFHandler(t, csrfTestOptions())
			token := mintToken(csrfTestKey)
			req := httptest.NewRequest(method, "https://app.xalgorix.com/api/orgs/1", strings.NewReader("{}"))
			req.AddCookie(&http.Cookie{Name: CSRFCookieName, Value: token})
			req.Header.Set(CSRFHeaderName, token)

			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)
			if rr.Code != http.StatusNoContent {
				t.Fatalf("status = %d, want 204 for state-changing method %s with valid CSRF", rr.Code, method)
			}
			if !*called {
				t.Fatalf("inner handler should run for %s with matching CSRF", method)
			}
		})
	}
}

// TestCSRF_CustomErrorHandler verifies a caller-supplied error
// handler is invoked on the failure path. This is the hook the
// router (task 8.1) uses to return the canonical JSON error envelope.
func TestCSRF_CustomErrorHandler(t *testing.T) {
	t.Parallel()
	opts := csrfTestOptions()
	opts.ErrorHandler = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTeapot)
		_, _ = w.Write([]byte("custom-csrf-error"))
	})
	handler, called := newCSRFHandler(t, opts)

	req := httptest.NewRequest(http.MethodPost, "https://app.xalgorix.com/api/orgs", strings.NewReader("{}"))
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusTeapot {
		t.Fatalf("status = %d, want %d from custom error handler", rr.Code, http.StatusTeapot)
	}
	if rr.Body.String() != "custom-csrf-error" {
		t.Errorf("body = %q, want custom-csrf-error", rr.Body.String())
	}
	if *called {
		t.Fatal("inner handler must NOT run when custom error handler fired")
	}
}
