package llm

import (
	"context"
	"net/http"
)

// AuthMethod identifies how outbound credentials are applied to a
// request. The current set is the API-key path the legacy resolver
// already used, plus the new OAuth-bearer path that Wave D wires in
// once the catalog/profile stack lands.
//
// Validates: Requirements 2.2, 2.3, 11.2.
type AuthMethod string

const (
	// AuthAPIKey selects the legacy API-key header style — Bearer for
	// OpenAI-compatible endpoints, x-api-key for Anthropic, and
	// x-goog-api-key for Gemini.
	AuthAPIKey AuthMethod = "api_key" //nolint:gosec // G101 false positive: enum value naming an auth method, not a credential

	// AuthOAuthBearer selects the OAuth Bearer header style on every
	// header style: `Authorization: Bearer <accessToken>`.
	AuthOAuthBearer AuthMethod = "oauth_bearer" //nolint:gosec // G101 false positive: enum value naming an auth method, not a credential
)

// Endpoint is the resolved outbound target for a single chat /
// stream request. It carries enough information for the LLM client
// to build the correct URL, pick the request body shape (via
// HeaderStyle), and apply the right outbound auth headers.
//
// Validates: Requirements 2.2, 2.3, 11.2.
type Endpoint struct {
	// URL is the fully-qualified outbound URL the request POSTs to,
	// e.g. https://api.openai.com/v1/chat/completions or the Gemini
	// :generateContent path. Resolvers are responsible for building
	// the final form, including any /v1 / /v1beta / :streamGenerateContent
	// suffixes.
	URL string

	// Model is the bare model name to send in the request body
	// (provider prefixes already stripped).
	Model string

	// HeaderStyle is one of "openai", "anthropic", or "gemini" and
	// drives both the request body shape and the outbound auth
	// header switch in client.go.
	HeaderStyle string

	// Auth selects which credential the client applies to the
	// outbound request — see AuthAPIKey / AuthOAuthBearer.
	Auth AuthMethod

	// APIKey is populated when Auth == AuthAPIKey.
	APIKey string

	// AccessToken is populated when Auth == AuthOAuthBearer.
	AccessToken string

	// VendorOverride, when non-nil, is invoked after the standard
	// header switch so a resolver can add or replace vendor-specific
	// headers (Anthropic's anthropic-version, Gemini's x-goog-api-key
	// for the API-key path, etc.) without the client growing more
	// switch cases.
	VendorOverride func(req *http.Request)
}

// Resolver answers "for this scan, where do we POST and which auth
// method does the response need?" Catalog-aware implementations pull
// baseURL and headerStyle from providers.Service; the legacy
// implementation reads providerBases unchanged.
//
// Validates: Requirements 2.1, 2.2, 2.3, 2.4.
type Resolver interface {
	Resolve(ctx context.Context) (Endpoint, error)
}

// fixedResolver is a Resolver that returns a pre-baked Endpoint
// every time. Used by the per-scan endpoint plumbing in
// internal/web/scan_resolve.go: the web layer resolves the endpoint
// once at scan start (so a misspelled provider_profile fails fast),
// then wraps it in a fixedResolver and feeds it to the per-scan
// LLM client. That guarantees the agent's outbound traffic carries
// exactly the credentials the operator's request resolved to,
// rather than re-running the catalog/legacy gate on every chat
// call.
type fixedResolver struct {
	ep Endpoint
}

// Resolve returns the baked endpoint and a nil error. Honors a
// canceled context so callers that pass a cancellable scope still
// observe cancellation at the resolver boundary.
func (f fixedResolver) Resolve(ctx context.Context) (Endpoint, error) {
	if err := ctx.Err(); err != nil {
		return Endpoint{}, err
	}
	return f.ep, nil
}

// NewFixedResolver returns a Resolver that always yields ep. The
// returned value is safe for concurrent use — Endpoint is value-
// typed and the resolver stores it by value, so no shared mutable
// state is exposed.
//
// This is the test-friendly alternative to NewCompositeResolver
// for callers that have already done the catalog/profile lookup
// themselves and just need to plug the result into llm.WithResolver.
func NewFixedResolver(ep Endpoint) Resolver {
	return fixedResolver{ep: ep}
}

// Option configures optional Client behavior. Wave D will use
// WithResolver to swap in the composite catalog/legacy resolver
// without changing the existing NewClient(cfg) signature for
// non-resolver call sites (variadic, so the no-option call form
// keeps compiling unchanged).
//
// Validates: Requirement 11.2.
type Option func(*Client)

// WithResolver wires a Resolver onto the Client. The resolver is
// stored on the Client but not yet consulted by doChat / ChatStream
// — Wave D (task 4.2) replaces the inline endpoint dispatch with a
// call into this resolver.
//
// Validates: Requirement 11.2.
func WithResolver(r Resolver) Option {
	return func(c *Client) {
		c.resolver = r
	}
}

// WithHTTPClient overrides the *http.Client the LLM client uses for
// outbound chat / stream requests. The default is a 10-minute
// http.Client constructed inside NewClient; tests inject a stub
// transport here to assert the outbound request shape (URL,
// Authorization header, body) without standing up a fake server.
//
// Production callers do not need this — the default client honors
// the configured request timeout and shares connections through the
// global http.DefaultTransport. The option exists primarily so the
// per-scan integration test in internal/web can intercept the agent's
// LLM traffic with a roundtripper.
//
// Validates: B1 (per-scan provider_profile traffic routing test seam).
func WithHTTPClient(httpClient *http.Client) Option {
	return func(c *Client) {
		if httpClient != nil {
			c.httpClient = httpClient
		}
	}
}
