// CSRF implements task 2.11 of the xalgorix-saas spec —
// "CSRF double-submit middleware". It is a chi-style middleware
// factory (`func(http.Handler) http.Handler`) so the future router
// (task 8.1) can mount it on the Dashboard route group, but it
// depends only on net/http and the standard crypto packages so it
// can be used today by any standard-library mux.
//
// The middleware enforces Requirement 20.5
//
//	"THE API_Server SHALL require a CSRF double-submit cookie on every
//	 state-changing endpoint accessed from the Dashboard."
//
// using the canonical OWASP double-submit pattern with one
// hardening twist:
//
//   - On every request the middleware ensures the response carries
//     the `__Host-xalgorix_csrf` cookie. The value is a fresh,
//     HMAC-SHA256-signed random token whenever the request did not
//     already present a server-signed token; otherwise the existing
//     value is preserved so a long-lived Dashboard session does not
//     race against the just-issued cookie.
//   - The cookie attributes match Requirement 20.5 exactly:
//     `Secure` (mandated by the `__Host-` prefix), `HttpOnly=false`
//     (the Dashboard JS must read the value to echo it back into the
//     `X-CSRF-Token` header), `SameSite=Lax`, `Path=/`, no `Domain`.
//   - On `POST`, `PUT`, `PATCH`, and `DELETE` the middleware compares
//     the cookie value to `X-CSRF-Token` in constant time. A missing
//     header or any mismatch is a hard `403 Forbidden`.
//   - Requests bearing an `Authorization: Bearer …` credential are
//     exempted entirely — API_Key requests are stateless and cannot
//     be ridden by a cookie they do not depend on (Requirements
//     section "Decisions and Defaults": "API_Key-authenticated
//     requests are CSRF-exempt and require a non-cookie credential").
//
// HMAC-signing the cookie value is what makes "double submit" robust
// against a sub-resource that can write cookies without reading them
// (cookie tossing / forced-cookie attacks): an attacker who plants
// `__Host-xalgorix_csrf=ATTACKER` cannot also forge a header that
// matches a server-trusted token, so the next state-changing request
// is rejected. The `__Host-` prefix already prevents subdomains from
// writing the cookie at all; HMAC is defense-in-depth.
//
// Note that the token itself is just an identifier — it carries no
// freshness guarantee. The CSRF protection comes from the
// cookie/header equality, not from token age, and a Dashboard tab
// left open for hours can keep using the same token. Tests in
// csrf_test.go pin this behaviour explicitly.
package api

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"net/http"
	"strings"
)

// CSRFCookieName is the cookie that carries the double-submit CSRF
// token. The `__Host-` prefix forces `Secure`, `Path=/`, and an
// empty `Domain`, which together guarantee the cookie is only
// readable by the same origin that issued it. Any deviation from
// these attributes causes browsers to ignore the Set-Cookie entirely,
// which is exactly the behaviour we want — the middleware would
// rather fail closed than silently downgrade.
const CSRFCookieName = "__Host-xalgorix_csrf"

// CSRFHeaderName is the request header the Dashboard JS echoes the
// cookie value into for state-changing requests. The custom header
// name doubles as a CORS preflight trigger, blocking simple
// cross-origin form posts before they ever reach the server.
const CSRFHeaderName = "X-CSRF-Token"

// csrfRandomBytes is the unsigned-payload size of a token. 128 bits
// of entropy is overkill for a per-session identifier but keeps the
// encoded length stable and makes brute-force collisions
// astronomically unlikely.
const csrfRandomBytes = 16

// csrfHMACBytes is the signature-tag size. 128 bits of HMAC-SHA256
// truncation is well above the 80-bit floor recommended by NIST
// SP 800-107 for tag truncation and matches the tag length used by
// established CSRF libraries (gorilla/csrf, alexedwards/scs).
const csrfHMACBytes = 16

// csrfTokenLen is the encoded random + signature length in bytes.
const csrfTokenLen = csrfRandomBytes + csrfHMACBytes

// CSRFOptions configures the CSRF middleware. The zero value is
// production-safe except for Key, which MUST be set to a deployment
// secret in production; when omitted, the middleware mints a random
// per-process key so single-replica development is still functional
// but tokens stop validating across replicas in a horizontally
// scaled cluster (the test suite catches a missing key the moment it
// observes a 403 in CI).
type CSRFOptions struct {
	// Key is the HMAC-SHA256 secret used to sign cookie tokens. The
	// production wiring sources this from the secret manager named in
	// design.md "Decisions and Defaults". A length of at least 32
	// bytes is strongly recommended; shorter keys are accepted for
	// test scenarios but are not safe for production.
	Key []byte

	// CookieName overrides CSRFCookieName. Tests override it so they
	// can run against an httptest.NewRecorder without minting cookies
	// that conflict with `__Host-` browser semantics; production
	// callers MUST leave it empty so the `__Host-` prefix is in
	// effect.
	CookieName string

	// HeaderName overrides CSRFHeaderName. Reserved for tests; leave
	// empty in production.
	HeaderName string

	// Secure controls the cookie's Secure flag. When nil, defaults to
	// true (the only value compatible with the `__Host-` prefix).
	// Tests against a non-TLS test server may set *false; production
	// callers MUST leave it nil.
	Secure *bool

	// ErrorHandler is invoked when the CSRF check fails. When nil, a
	// plain `403 Forbidden` with body "CSRF token missing or invalid"
	// is returned. The router (task 8.1) overrides this to emit the
	// canonical JSON error envelope from errors.go.
	ErrorHandler http.Handler
}

// CSRF returns a chi-style middleware that implements the
// double-submit cookie pattern documented in Requirement 20.5.
//
// The factory pre-computes the resolved options once and reuses
// them for every request, so the per-request cost is dominated by
// a single HMAC-SHA256 verification on the cookie path and a
// constant-time compare on the validation path.
func CSRF(opts CSRFOptions) func(http.Handler) http.Handler {
	cookieName := opts.CookieName
	if cookieName == "" {
		cookieName = CSRFCookieName
	}
	headerName := opts.HeaderName
	if headerName == "" {
		headerName = CSRFHeaderName
	}
	secure := true
	if opts.Secure != nil {
		secure = *opts.Secure
	}

	key := opts.Key
	if len(key) == 0 {
		// Generate a random per-process key. This degrades cleanly:
		// tokens issued by one replica will not validate at another,
		// which manifests as a 403 the operator cannot ignore. We
		// prefer that to silently issuing forgeable (zero-key) tokens.
		key = make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			// crypto/rand failures are unrecoverable. Refuse to
			// continue rather than issue tokens we cannot trust.
			panic("api/csrf: rand.Read: " + err.Error())
		}
	}

	onError := opts.ErrorHandler
	if onError == nil {
		onError = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "CSRF token missing or invalid", http.StatusForbidden)
		})
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Reuse a server-signed token from the cookie when it is
			// present and validates; otherwise mint a fresh token.
			// This is what makes a long-lived Dashboard tab keep
			// working across many requests without re-fetching the
			// page to pick up a new cookie value.
			token := readValidToken(r, cookieName, key)
			if token == "" {
				token = mintToken(key)
			}

			// Always (re-)stamp the cookie. When the existing cookie
			// validated, this is a no-op refresh of the same value.
			// When it did not, this is the issuance the Dashboard JS
			// will read on the next page load. HttpOnly is false by
			// design — the browser must let document.cookie expose
			// the value so the Dashboard can echo it back into the
			// X-CSRF-Token header.
			http.SetCookie(w, &http.Cookie{
				Name:     cookieName,
				Value:    token,
				Path:     "/",
				Secure:   secure,
				HttpOnly: false,
				SameSite: http.SameSiteLaxMode,
			})

			// API_Key requests bear `Authorization: Bearer …` and
			// have no cookie dependency, so they cannot be ridden by
			// a CSRF attacker. Skip validation entirely (Requirement
			// 20.5 carve-out for stateless credentials).
			if isBearerAuthorized(r) {
				next.ServeHTTP(w, r)
				return
			}

			// Safe methods (GET, HEAD, OPTIONS, TRACE, CONNECT) do
			// not change server state and per RFC 9110 §9.2.1 must
			// not be gated by CSRF.
			if !isStateChangingMethod(r.Method) {
				next.ServeHTTP(w, r)
				return
			}

			// Double-submit comparison: header MUST equal the cookie
			// value the server trusts. constant-time compare guards
			// against a timing oracle (negligible practical risk
			// here, but cheap enough to do).
			header := r.Header.Get(headerName)
			if header == "" {
				onError.ServeHTTP(w, r)
				return
			}
			if subtle.ConstantTimeCompare([]byte(header), []byte(token)) != 1 {
				onError.ServeHTTP(w, r)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// isStateChangingMethod returns true for the HTTP methods Requirement
// 20.5 calls "state-changing". The set is the RFC 9110 unsafe-method
// set minus CONNECT (which is irrelevant to the API surface).
func isStateChangingMethod(method string) bool {
	switch method {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return true
	default:
		return false
	}
}

// isBearerAuthorized reports whether the request carries a
// non-cookie Authorization credential. Per Requirement 20.5 these
// requests are CSRF-exempt because they cannot be ridden by a stolen
// cookie (the credential is supplied by the API_Key client itself).
//
// The match is case-insensitive on the scheme name to follow RFC
// 7235 §2.1 ("the scheme name is case-insensitive"). We additionally
// tolerate a trailing space without a token so that a malformed
// header still routes through the bearer-shaped path; the upstream
// authentication middleware (task 2.5) will reject the empty token
// with a 401, which is more informative than a 403 from this layer.
func isBearerAuthorized(r *http.Request) bool {
	auth := r.Header.Get("Authorization")
	if auth == "" {
		return false
	}
	lower := strings.ToLower(auth)
	if strings.HasPrefix(lower, "bearer ") {
		return true
	}
	return strings.EqualFold(strings.TrimSpace(auth), "bearer")
}

// mintToken creates a fresh CSRF token: csrfRandomBytes random bytes
// followed by the first csrfHMACBytes of HMAC-SHA256(key, random),
// encoded as URL-safe base64 without padding.
//
// We concatenate-and-encode (rather than encoding random and signature
// separately) so a token survives intact through a single Cookie /
// header round trip without needing a structural separator that an
// attacker could try to confuse the parser with.
func mintToken(key []byte) string {
	raw := make([]byte, csrfRandomBytes)
	if _, err := rand.Read(raw); err != nil {
		// Same reasoning as above — a crypto/rand failure is
		// unrecoverable; refuse to issue a guessable token.
		panic("api/csrf: rand.Read: " + err.Error())
	}
	sig := hmacSign(key, raw)
	payload := make([]byte, 0, csrfTokenLen)
	payload = append(payload, raw...)
	payload = append(payload, sig...)
	return base64.RawURLEncoding.EncodeToString(payload)
}

// hmacSign computes the truncated HMAC-SHA256 tag used by mintToken
// and parseToken. Truncation is to csrfHMACBytes; see the constant
// docstring for the rationale.
func hmacSign(key, raw []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(raw)
	full := mac.Sum(nil)
	out := make([]byte, csrfHMACBytes)
	copy(out, full[:csrfHMACBytes])
	return out
}

// parseToken decodes and HMAC-verifies a token. The boolean is true
// iff the token is well-formed and signed by key. Any decode error,
// length mismatch, or signature mismatch is reported as an invalid
// token; the caller treats invalid the same as missing.
func parseToken(token string, key []byte) bool {
	payload, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return false
	}
	if len(payload) != csrfTokenLen {
		return false
	}
	raw := payload[:csrfRandomBytes]
	got := payload[csrfRandomBytes:]
	want := hmacSign(key, raw)
	return subtle.ConstantTimeCompare(got, want) == 1
}

// readValidToken returns the token from the cookie iff it parses
// and has a valid HMAC under key. An empty string means "the request
// did not present a token I should trust" — the caller mints a fresh
// one in that case.
func readValidToken(r *http.Request, cookieName string, key []byte) string {
	c, err := r.Cookie(cookieName)
	if err != nil || c.Value == "" {
		return ""
	}
	if !parseToken(c.Value, key) {
		return ""
	}
	return c.Value
}
