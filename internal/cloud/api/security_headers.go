// SecurityHeaders implements task 14.1 of the xalgorix-saas spec —
// "HSTS preload + CSP middleware". It is a chi-style middleware factory
// (`func(http.Handler) http.Handler`) so the future router (task 8.1)
// can mount it on the authenticated route group, but it depends only
// on net/http so it can be used today by any standard-library mux.
//
// The middleware emits the following response headers on every
// request, fulfilling Requirements 20.2 and 20.4:
//
//   - Strict-Transport-Security (HSTS) — preload-eligible value with
//     `includeSubDomains` covers `xalgorix.com` and every subdomain,
//     satisfying Requirement 20.2 ("HSTS preload enabled on
//     xalgorix.com and all subdomains").
//   - Content-Security-Policy — exactly the policy named in design.md
//     "Decisions and Defaults" (the canonical text is restated in the
//     defaultCSPDirectives slice below), satisfying Requirement 20.4
//     ("CSP header matching the policy defined in Decisions and
//     Defaults on every authenticated route").
//   - X-Content-Type-Options, Referrer-Policy, Permissions-Policy —
//     supplementary headers called out by the task description; they
//     close adjacent attack surface (MIME sniffing, referrer leakage,
//     powerful-feature access) without changing application behaviour.
//
// The factory accepts a SecurityHeaderOptions value so deployments
// that need to relax HSTS (for staging, where preload would brick the
// host) or extend the CSP (for an integration that genuinely requires
// a third-party connect-src) can do so without forking. Zero-valued
// options pick safe production defaults — see defaultedOptions for
// the exact rule set.
package api

import (
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

// defaultHSTSMaxAge is the one-year value RFC 6797 §6.1.1 recommends
// for hosts that intend to submit to the HSTS preload list. The HSTS
// preload list at https://hstspreload.org/ requires `max-age` of at
// least 31536000 seconds (one year); we match the lower bound exactly
// rather than an arbitrarily larger value so that operators can audit
// the number against the preload submission form.
const defaultHSTSMaxAge = 365 * 24 * time.Hour

// defaultCSPDirectives encodes the canonical CSP from
// design.md → Decisions and Defaults. The directives are stored as an
// ordered slice rather than a map so the emitted header text is
// deterministic across processes (which matters for tests, audit
// logs, and CSP report-uri attribution). The semicolon between
// directives is added by formatCSP.
//
// Keep this list in lock-step with the design document; if you change
// any directive here, update both the design's Decisions and Defaults
// section and the SecurityHeaders test that pins the default policy.
var defaultCSPDirectives = []cspDirective{
	{name: "default-src", value: "'self'"},
	{name: "img-src", value: "'self' data: https:"},
	{name: "script-src", value: "'self' 'wasm-unsafe-eval'"},
	{name: "style-src", value: "'self' 'unsafe-inline'"},
	{name: "connect-src", value: "'self' wss:"},
	{name: "frame-ancestors", value: "'none'"},
	{name: "base-uri", value: "'self'"},
	{name: "form-action", value: "'self'"},
	{name: "object-src", value: "'none'"},
	{name: "upgrade-insecure-requests", value: ""},
	{name: "report-to", value: "xalgorix-csp"},
	{name: "report-uri", value: "/api/internal/csp-report"},
}

// cspDirective is a single (name, value) pair in a CSP. A blank value
// represents a value-less directive such as `upgrade-insecure-requests`.
type cspDirective struct {
	name  string
	value string
}

// SecurityHeaderOptions configures the SecurityHeaders middleware. The
// zero value is the production-safe default — every field is optional.
//
// HSTSEnabled is a tri-state encoded as *bool because Requirement 20.2
// mandates HSTS in production but the in-process integration tests
// for non-TLS handlers must be able to disable it. We use a pointer so
// the zero SecurityHeaderOptions value still defaults to "enabled".
type SecurityHeaderOptions struct {
	// HSTSEnabled toggles the Strict-Transport-Security header. When
	// nil, HSTS is enabled (the production default). When *false,
	// HSTS is suppressed entirely — useful for local development or
	// reverse proxies that already set HSTS upstream.
	HSTSEnabled *bool

	// HSTSMaxAge is the `max-age` directive value. When zero,
	// defaults to one year (defaultHSTSMaxAge).
	HSTSMaxAge time.Duration

	// HSTSIncludeSubdomains toggles the `includeSubDomains` directive.
	// When nil, it defaults to true so HSTS protection extends to
	// every Xalgorix subdomain (api.xalgorix.com, app.xalgorix.com,
	// etc.) as required by Requirement 20.2.
	HSTSIncludeSubdomains *bool

	// HSTSPreload toggles the `preload` directive. When nil, defaults
	// to true so the host is eligible for inclusion on the Chromium
	// HSTS preload list at hstspreload.org.
	HSTSPreload *bool

	// CSPDirectives, when non-nil, overlays per-directive overrides
	// onto defaultCSPDirectives. A non-empty value replaces the
	// default; an empty string removes the directive entirely. Keys
	// not present in defaultCSPDirectives are appended (sorted) so
	// the emitted header remains deterministic.
	CSPDirectives map[string]string
}

// resolvedSecurityHeaderOptions is the post-defaulting view of
// SecurityHeaderOptions. We build it once per factory invocation so
// the per-request middleware avoids re-running the same defaulting
// logic on every call.
type resolvedSecurityHeaderOptions struct {
	hstsEnabled           bool
	hstsMaxAge            time.Duration
	hstsIncludeSubdomains bool
	hstsPreload           bool
	cspHeaderValue        string
}

// resolve materialises the runtime defaults documented on
// SecurityHeaderOptions. The returned struct is safe to share across
// goroutines because every field is a value type.
func (opts SecurityHeaderOptions) resolve() resolvedSecurityHeaderOptions {
	hstsEnabled := true
	if opts.HSTSEnabled != nil {
		hstsEnabled = *opts.HSTSEnabled
	}

	includeSubdomains := true
	if opts.HSTSIncludeSubdomains != nil {
		includeSubdomains = *opts.HSTSIncludeSubdomains
	}

	preload := true
	if opts.HSTSPreload != nil {
		preload = *opts.HSTSPreload
	}

	maxAge := opts.HSTSMaxAge
	if maxAge <= 0 {
		maxAge = defaultHSTSMaxAge
	}

	return resolvedSecurityHeaderOptions{
		hstsEnabled:           hstsEnabled,
		hstsMaxAge:            maxAge,
		hstsIncludeSubdomains: includeSubdomains,
		hstsPreload:           preload,
		cspHeaderValue:        formatCSP(mergeCSP(defaultCSPDirectives, opts.CSPDirectives)),
	}
}

// SecurityHeaders returns a middleware that stamps the security
// response headers documented above onto every response. The factory
// pre-computes the rendered HSTS and CSP header values once and reuses
// them for every request, so per-request cost is a small constant.
//
// The middleware applies the headers via Header().Set before delegating
// to the wrapped handler. Setting headers before ServeHTTP is required
// because Go's http.ResponseWriter freezes the header map at the first
// Write call, and the inner handler may stream the response body.
func SecurityHeaders(opts SecurityHeaderOptions) func(http.Handler) http.Handler {
	resolved := opts.resolve()

	hstsValue := ""
	if resolved.hstsEnabled {
		hstsValue = formatHSTS(resolved.hstsMaxAge, resolved.hstsIncludeSubdomains, resolved.hstsPreload)
	}
	cspValue := resolved.cspHeaderValue

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			h := w.Header()
			if hstsValue != "" {
				h.Set("Strict-Transport-Security", hstsValue)
			}
			if cspValue != "" {
				h.Set("Content-Security-Policy", cspValue)
			}
			h.Set("X-Content-Type-Options", "nosniff")
			h.Set("Referrer-Policy", "strict-origin-when-cross-origin")
			h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
			next.ServeHTTP(w, r)
		})
	}
}

// formatHSTS renders the Strict-Transport-Security header value in the
// canonical RFC 6797 form. The directive order matches the order
// recommended by hstspreload.org so a manual `curl -I` matches the
// preload submission form character-for-character.
func formatHSTS(maxAge time.Duration, includeSubdomains, preload bool) string {
	seconds := int64(maxAge / time.Second)
	if seconds < 0 {
		seconds = 0
	}
	parts := []string{"max-age=" + strconv.FormatInt(seconds, 10)}
	if includeSubdomains {
		parts = append(parts, "includeSubDomains")
	}
	if preload {
		parts = append(parts, "preload")
	}
	return strings.Join(parts, "; ")
}

// mergeCSP applies the user-supplied overlay to the canonical default
// directive list.
//
//   - overlay value with len > 0 → replace the existing directive's
//     value, preserving its position in the slice. When the directive
//     is unknown to the defaults, it is appended after the defaults
//     in deterministic (sorted) order.
//   - overlay value of "" → drop the directive entirely.
//
// The function returns a fresh slice rather than mutating the input
// so concurrent callers (e.g. multiple SecurityHeaders factory
// invocations with different overlays in the same process) cannot
// race on defaultCSPDirectives.
func mergeCSP(defaults []cspDirective, overlay map[string]string) []cspDirective {
	if len(overlay) == 0 {
		out := make([]cspDirective, len(defaults))
		copy(out, defaults)
		return out
	}

	// Lower-case keys so callers can use either canonical or shouted
	// directive names without surprise. CSP directive names are
	// ASCII case-insensitive per the W3C CSP3 grammar.
	normalized := make(map[string]string, len(overlay))
	for k, v := range overlay {
		normalized[strings.ToLower(strings.TrimSpace(k))] = v
	}

	out := make([]cspDirective, 0, len(defaults)+len(normalized))
	consumed := make(map[string]bool, len(normalized))
	for _, d := range defaults {
		if v, ok := normalized[d.name]; ok {
			consumed[d.name] = true
			if v == "" {
				continue // overlay deletes the directive.
			}
			out = append(out, cspDirective{name: d.name, value: v})
			continue
		}
		out = append(out, d)
	}

	// Append unknown overlay directives in sorted order so the
	// emitted header is deterministic across runs.
	extras := make([]string, 0, len(normalized))
	for k := range normalized {
		if consumed[k] {
			continue
		}
		if normalized[k] == "" {
			continue // explicit deletion of a directive that was already absent.
		}
		extras = append(extras, k)
	}
	sort.Strings(extras)
	for _, k := range extras {
		out = append(out, cspDirective{name: k, value: normalized[k]})
	}
	return out
}

// formatCSP renders a directive list as the value of the
// Content-Security-Policy header. Directives are joined by `; `,
// matching the example syntax in the W3C CSP3 specification.
func formatCSP(directives []cspDirective) string {
	if len(directives) == 0 {
		return ""
	}
	parts := make([]string, 0, len(directives))
	for _, d := range directives {
		if d.value == "" {
			parts = append(parts, d.name)
			continue
		}
		parts = append(parts, d.name+" "+d.value)
	}
	return strings.Join(parts, "; ")
}
