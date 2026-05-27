// Package llm — composite Resolver wiring (Wave D task 4.1).
//
// This file declares the three implementations that drive outbound
// endpoint selection now that the catalog/profile stack has landed:
//
//   - legacyResolver reproduces Client.resolveEndpoint exactly,
//     consulting the historical providerBases map that internal/llm
//     has shipped for every API-key install before this feature.
//     It is consulted ONLY when Catalog_Service is empty AND
//     XALGORIX_LLM matches Legacy_Provider_Shape — that's the
//     Legacy_Fallback contract from Requirements 2.1 and 2.3.
//
//   - catalogResolver pulls baseURL + headerStyle from the runtime
//     catalog and authMethod + credentials from Profile_Store. It
//     is consulted whenever the catalog has at least one entry
//     (Requirement 2.2). The per-scan picker plugs in via the
//     `pick` field; the default supplied by NewCompositeResolver
//     just selects the first profile of the first catalog entry.
//     Wave E task 5.3 (resolveScanCredentials) replaces the
//     default picker with the per-scan one wired through the
//     ScanRequest.ProviderProfile field.
//
//   - compositeResolver is the dispatcher both call sites talk to.
//     It implements Resolver and routes every Resolve call to
//     either catalogResolver or legacyResolver based on the
//     R2.1/R2.2 gate, returning a *ConfigError when neither path
//     is available (Requirement 2.4).
//
// Why a composite rather than two top-level resolvers: the LLM
// client only holds one Resolver, and the legacy/catalog choice
// can change at runtime (the operator deletes the last catalog
// entry mid-process, or imports an openclaw entry into a fresh
// install). Folding the decision into a single Resolver lets
// every scan re-evaluate the gate on demand without the client
// needing to know which mode it is in.
//
// Note on Option naming: the existing llm.Option is
// `func(*Client)` (used by NewClient + WithResolver), so the
// resolver constructor uses a sibling type ResolverOption to
// avoid the conflict — see the design doc's "Components and
// Interfaces" section for the rationale.
//
// Validates: Requirements 2.1, 2.2, 2.3, 2.4, 11.2.
package llm

import (
	"context"
	"strings"

	"github.com/xalgord/xalgorix/v4/internal/auth"
	"github.com/xalgord/xalgorix/v4/internal/config"
	"github.com/xalgord/xalgorix/v4/internal/providers"
)

// ConfigError is the typed error the composite resolver returns
// when neither the catalog nor the legacy environment fallback
// can supply an outbound endpoint. The HTTP layer pattern-matches
// on this type to render a "no provider configured" message
// instead of a generic 500.
//
// Validates: Requirement 2.4.
type ConfigError struct {
	Msg string
}

// Error implements the error interface. The pointer-receiver form
// matches the style of typed errors elsewhere in this codebase
// (providers.ErrUpstream, etc.) and lets callers errors.As against
// *ConfigError.
func (e *ConfigError) Error() string { return e.Msg }

// legacyProviderBases is the runtime-immutable map of legacy
// provider slugs → default API base URLs. Lifted verbatim from
// Client.resolveEndpoint so legacyResolver.Resolve produces
// byte-identical URL results to the pre-feature code path. The
// resolver and the existing local map in client.go intentionally
// hold the same values; task 4.2 (the dispatch swap) removes the
// client.go duplicate.
//
// Validates: Requirement 2.3 (preserved endpoint shape).
var legacyProviderBases = map[string]string{
	"openai":    "https://api.openai.com/v1",
	"anthropic": "https://api.anthropic.com",
	"minimax":   "https://api.minimax.io/v1",
	"deepseek":  "https://api.deepseek.com/v1",
	"groq":      "https://api.groq.com/openai/v1",
	"ollama":    "http://localhost:11434/v1",
	// Google's chat endpoint is /v1beta/models/MODEL:generateContent;
	// we store the bare host here and append the version segment in
	// the URL builder below.
	"google": "https://generativelanguage.googleapis.com",
	"gemini": "https://generativelanguage.googleapis.com",
}

// LegacyProviderBaseURL returns the canonical legacy API base URL
// for the supplied provider slug (case-insensitive) and reports
// whether the slug is recognised. The mapping is the stable read-
// only view of legacyProviderBases — callers in internal/web (the
// migrate importer) consult it instead of duplicating the table so
// any future addition flows through a single edit site.
//
// Validates: Requirement 2.3 (preserved endpoint shape); H7 (dedup
// legacyProviderBases between resolver.go and migrate.go).
func LegacyProviderBaseURL(provider string) (string, bool) {
	v, ok := legacyProviderBases[strings.ToLower(strings.TrimSpace(provider))]
	return v, ok
}

// legacyResolver reproduces Client.resolveEndpoint() exactly,
// consulting legacyProviderBases for the URL prefix and
// XALGORIX_API_KEY for the credential. It is owned by the
// composite resolver and never used directly outside this file.
//
// Validates: Requirements 2.1, 2.3, 2.4.
type legacyResolver struct {
	cfg *config.Config
}

// catalogPick bundles the catalog Entry and credential Profile
// the catalog resolver should use for one outbound request. The
// `pick` callback on catalogResolver returns this struct so the
// per-scan picker (Wave E task 5.3) can inject a different choice
// per call without changing the resolver's surface.
type catalogPick struct {
	entry   providers.Entry
	profile auth.Profile
}

// catalogResolver pulls baseURL + headerStyle from the runtime
// catalog and the access credential from Profile_Store. The
// `pick` callback decides which (entry, profile) tuple to use for
// this Resolve call; NewCompositeResolver supplies a default that
// picks the first profile of the first catalog entry, and Wave E
// task 5.3 replaces it with the per-scan picker.
//
// Validates: Requirements 2.2, 11.2.
type catalogResolver struct {
	cat  *providers.Service
	prof *auth.Store
	pick func(ctx context.Context) (catalogPick, error)
}

// compositeResolver is the dispatcher returned by
// NewCompositeResolver. It owns optional handles to the catalog
// service, the profile store, the legacy config, and a per-scan
// picker. Resolve consults the catalog/legacy gate on every call
// so the choice tracks runtime catalog mutations (e.g. an operator
// importing the openclaw catalog mid-process).
//
// Validates: Requirements 2.1, 2.2, 2.4.
type compositeResolver struct {
	cat  *providers.Service
	prof *auth.Store
	cfg  *config.Config
	pick func(ctx context.Context) (catalogPick, error)
}

// ResolverOption configures the compositeResolver returned by
// NewCompositeResolver. A separate option type (rather than the
// existing llm.Option = func(*Client)) keeps the two surfaces
// independent — Client options should not accidentally apply to
// resolvers and vice versa.
type ResolverOption func(*compositeResolver)

// WithCatalog wires Catalog_Service and Profile_Store into the
// composite. When supplied, Resolve dispatches to catalogResolver
// any time the catalog reports at least one entry (Requirement 2.2).
// Both arguments must be non-nil for the catalog branch to engage.
func WithCatalog(cat *providers.Service, prof *auth.Store) ResolverOption {
	return func(c *compositeResolver) {
		c.cat = cat
		c.prof = prof
	}
}

// WithLegacy wires the legacy *config.Config into the composite.
// When supplied, Resolve dispatches to legacyResolver any time the
// catalog is empty (or unwired) AND XALGORIX_LLM matches
// Legacy_Provider_Shape (Requirement 2.1). Without this option
// the legacy branch is unreachable.
func WithLegacy(cfg *config.Config) ResolverOption {
	return func(c *compositeResolver) {
		c.cfg = cfg
	}
}

// WithCatalogPicker injects a custom per-scan picker that selects
// the (entry, profile) tuple catalogResolver should use for a
// single Resolve call. Wave E task 5.3 (resolveScanCredentials)
// uses this to thread the per-scan ProviderProfile field through
// the resolver. When unset, NewCompositeResolver supplies a
// default that picks the first profile of the first catalog
// entry, which is enough for the dashboard's "current default
// provider" view but not for per-scan routing.
func WithCatalogPicker(pick func(ctx context.Context) (catalogPick, error)) ResolverOption {
	return func(c *compositeResolver) {
		c.pick = pick
	}
}

// NewCompositeResolver builds a Resolver that dispatches between
// catalogResolver and legacyResolver per Requirements 2.1–2.4.
// Both WithCatalog and WithLegacy are optional; if only one is
// supplied the other branch is unavailable and Resolve returns a
// *ConfigError when the gate routes to the missing side. The
// returned value satisfies the Resolver interface so callers can
// pass it directly to llm.WithResolver.
//
// Validates: Requirements 2.1, 2.2, 2.4, 11.2.
func NewCompositeResolver(opts ...ResolverOption) Resolver {
	c := &compositeResolver{}
	for _, opt := range opts {
		if opt != nil {
			opt(c)
		}
	}
	if c.pick == nil {
		c.pick = defaultCatalogPick(c)
	}
	return c
}

// defaultCatalogPick is the picker NewCompositeResolver installs
// when WithCatalogPicker is not supplied. It selects the first
// profile of the first catalog entry — adequate for the
// dashboard's "default provider" view but not per-scan routing,
// which Wave E task 5.3 wires through ScanRequest.ProviderProfile.
//
// Closing over the *compositeResolver (rather than over the
// catalog and store directly) lets a future option apply to the
// composite without rebuilding the picker.
func defaultCatalogPick(c *compositeResolver) func(ctx context.Context) (catalogPick, error) {
	return func(ctx context.Context) (catalogPick, error) {
		if c.cat == nil {
			return catalogPick{}, &ConfigError{Msg: "catalog resolver: catalog service not wired"}
		}
		if c.prof == nil {
			return catalogPick{}, &ConfigError{Msg: "catalog resolver: profile store not wired"}
		}
		entries, err := c.cat.List(ctx)
		if err != nil {
			return catalogPick{}, err
		}
		if len(entries) == 0 {
			return catalogPick{}, &ConfigError{Msg: "catalog resolver: catalog is empty"}
		}
		first := entries[0]
		profiles, err := c.prof.List(ctx)
		if err != nil {
			return catalogPick{}, err
		}
		for _, p := range profiles {
			if p.Provider == first.ID {
				return catalogPick{entry: first, profile: p}, nil
			}
		}
		return catalogPick{}, &ConfigError{
			Msg: "catalog resolver: no profile registered for first catalog entry " + first.ID,
		}
	}
}

// Resolve implements Resolver. It evaluates the catalog/legacy
// gate on every call so the choice tracks runtime mutations.
//
// Decision order (Requirements 2.1, 2.2, 2.4):
//
//  1. catalog wired AND non-empty → catalogResolver.
//  2. legacy wired AND XALGORIX_LLM matches Legacy_Provider_Shape
//     → legacyResolver.
//  3. neither branch is available → *ConfigError.
//
// A nil catalog handle is treated identically to an empty
// catalog: the legacy branch is consulted when wired, and the
// composite returns *ConfigError otherwise.
func (c *compositeResolver) Resolve(ctx context.Context) (Endpoint, error) {
	// Branch 1 — catalog non-empty (Requirement 2.2). The catalog
	// preempts legacy unconditionally, so an operator who has
	// imported even a single openclaw entry stops paying for the
	// legacy code path on the next request.
	if c.cat != nil && !c.cat.IsEmpty() {
		cr := &catalogResolver{
			cat:  c.cat,
			prof: c.prof,
			pick: c.pick,
		}
		return cr.Resolve(ctx)
	}

	// Branch 2 — Legacy_Fallback (Requirements 2.1, 2.3). Only
	// engages when the operator's XALGORIX_LLM names one of the
	// eight known legacy slugs; arbitrary custom values fall
	// through to branch 3 with a clear error.
	if c.cfg != nil && LegacyProviderShape(c.cfg.LLM) {
		lr := &legacyResolver{cfg: c.cfg}
		return lr.Resolve(ctx)
	}

	// Branch 3 — neither path is available (Requirement 2.4).
	return Endpoint{}, &ConfigError{
		Msg: "no provider configured: catalog is empty and XALGORIX_LLM does not match a known legacy provider shape",
	}
}

// Resolve on legacyResolver reproduces Client.resolveEndpoint()
// step-for-step. The duplication is deliberate: client.go's
// inline resolveEndpoint stays in place until task 4.2 swaps the
// dispatch, so today this function is the long-lived
// implementation and client.go's copy is the legacy stub. Both
// must produce byte-identical URLs for the same input cfg —
// any divergence would break the R2.3 endpoint-shape contract.
//
// Validates: Requirements 2.1, 2.3.
func (l *legacyResolver) Resolve(ctx context.Context) (Endpoint, error) {
	if err := ctx.Err(); err != nil {
		return Endpoint{}, err
	}
	if l.cfg == nil {
		return Endpoint{}, &ConfigError{Msg: "legacy resolver: nil config"}
	}

	apiBase := l.cfg.APIBase
	model := l.cfg.LLM // matches Client.apiModel = cfg.ResolveModel() = cfg.LLM

	// Provider prefix in the model name is the source of truth
	// for the API base. If the operator pinned XALGORIX_API_BASE
	// explicitly (e.g. through the Settings free-text form) that
	// override wins below.
	provider := ""
	if idx := strings.Index(model, "/"); idx >= 0 {
		provider = strings.ToLower(model[:idx])
		model = model[idx+1:]
	}

	if apiBase == "" {
		if knownBase, ok := legacyProviderBases[provider]; ok {
			apiBase = knownBase
		} else {
			// Unknown / no provider — default to the OpenAI shape.
			apiBase = "https://api.openai.com/v1"
		}
	}
	apiBase = strings.TrimRight(apiBase, "/")

	// Build the URL based on the resolved provider/api-base. Each
	// branch matches Client.resolveEndpoint exactly.
	url := apiBase
	switch {
	case provider == "anthropic" || isAnthropicAPIBase(apiBase):
		// Anthropic uses /v1/messages. Append /v1 only if the
		// configured base doesn't already include a version
		// segment, then append /messages.
		if !strings.HasSuffix(strings.ToLower(url), "/messages") {
			if !strings.HasSuffix(apiBase, "/v1") && !strings.Contains(apiBase, "/v1/") {
				url += "/v1"
			}
			url += "/messages"
		}
	case isGeminiProvider(provider) || isGeminiAPIBase(apiBase):
		// Google Gemini uses /v1beta/models/MODEL:generateContent.
		// Strip any trailing /v1 first so we don't end up with
		// /v1/v1beta concatenated when the user supplied a
		// versioned base URL.
		url = strings.TrimSuffix(url, "/v1")
		url += "/v1beta/models/" + model + ":generateContent"
	default:
		// OpenAI-compatible chat completions for openai, minimax,
		// deepseek, groq, ollama, and any unknown custom base.
		if !strings.HasSuffix(strings.ToLower(url), "/chat/completions") {
			if !strings.HasSuffix(apiBase, "/v1") && !strings.Contains(apiBase, "/v1/") {
				url += "/v1"
			}
			url += "/chat/completions"
		}
	}

	return Endpoint{
		URL:         url,
		Model:       model,
		HeaderStyle: legacyHeaderStyle(provider, apiBase),
		Auth:        AuthAPIKey,
		APIKey:      l.cfg.APIKey,
	}, nil
}

// legacyHeaderStyle maps a legacy provider slug (and the resolved
// API base, used when no provider prefix was supplied) to one of
// the three values the LLM client switch in task 4.2 will branch
// on. The mapping is fixed by the design's "HeaderStyle for
// legacy" note:
//
//   - openai, minimax, deepseek, groq, ollama → "openai"
//   - anthropic                               → "anthropic"
//   - google, gemini                          → "gemini"
//
// Anything else falls back to "openai" because the legacy
// resolver treats unknown providers as OpenAI-compatible (the
// same default Client.resolveEndpoint applies for the URL).
func legacyHeaderStyle(provider, apiBase string) string {
	switch provider {
	case "openai", "minimax", "deepseek", "groq", "ollama":
		return "openai"
	case "anthropic":
		return "anthropic"
	case "google", "gemini":
		return "gemini"
	}
	// No provider prefix — fall back on the API base shape so a
	// bare XALGORIX_API_BASE pointing at Anthropic or Gemini still
	// gets the correct outbound header style.
	if isAnthropicAPIBase(apiBase) {
		return "anthropic"
	}
	if isGeminiAPIBase(apiBase) {
		return "gemini"
	}
	return "openai"
}

// Resolve on catalogResolver pulls baseURL + headerStyle from the
// catalog Entry chosen by `pick` and the access credential from
// the matching Profile. The URL builder mirrors the legacy
// resolver's three-branch shape (anthropic / gemini / openai) so
// catalog-driven scans hit the same outbound URLs the operator
// would expect from typing the equivalent base URL into the
// Settings form.
//
// API_Key_Profile records honor APIBaseOverride (Requirement 4.5)
// — that's the per-profile escape hatch for proxying through a
// custom gateway without touching the catalog entry's BaseURL.
//
// Validates: Requirements 2.2, 11.2.
func (cr *catalogResolver) Resolve(ctx context.Context) (Endpoint, error) {
	if err := ctx.Err(); err != nil {
		return Endpoint{}, err
	}
	if cr.cat == nil {
		return Endpoint{}, &ConfigError{Msg: "catalog resolver: nil catalog"}
	}
	if cr.prof == nil {
		return Endpoint{}, &ConfigError{Msg: "catalog resolver: nil profile store"}
	}
	if cr.pick == nil {
		return Endpoint{}, &ConfigError{Msg: "catalog resolver: nil picker"}
	}

	pick, err := cr.pick(ctx)
	if err != nil {
		return Endpoint{}, err
	}
	entry := pick.entry
	prof := pick.profile

	// Pick the first model of the entry as the default. The
	// per-scan picker (Wave E task 5.3) will set this through
	// ScanRequest.Model when the operator supplies an ad-hoc
	// override; the resolver itself only needs a sensible
	// default for the "no override" path.
	model := ""
	if len(entry.Models) > 0 {
		model = entry.Models[0]
	}

	// Determine the effective API base. APIBaseOverride applies
	// only to API_Key_Profile records — OAuth profiles don't
	// expose a base override because the access token is tied to
	// the catalog entry's authorization endpoint.
	apiBase := entry.BaseURL
	if prof.Type == auth.APIKey && prof.APIBaseOverride != "" {
		apiBase = prof.APIBaseOverride
	}
	apiBase = strings.TrimRight(apiBase, "/")

	// Build the URL by header style. Each branch matches the
	// legacy resolver's logic for the same shape so catalog and
	// legacy paths agree on URL construction for the same base.
	url := apiBase
	switch entry.HeaderStyle {
	case "anthropic":
		if !strings.HasSuffix(strings.ToLower(url), "/messages") {
			if !strings.HasSuffix(apiBase, "/v1") && !strings.Contains(apiBase, "/v1/") {
				url += "/v1"
			}
			url += "/messages"
		}
	case "gemini":
		url = strings.TrimSuffix(url, "/v1")
		url += "/v1beta/models/" + model + ":generateContent"
	case "openai":
		if !strings.HasSuffix(strings.ToLower(url), "/chat/completions") {
			if !strings.HasSuffix(apiBase, "/v1") && !strings.Contains(apiBase, "/v1/") {
				url += "/v1"
			}
			url += "/chat/completions"
		}
	default:
		// Unknown header style. validateEntry rejects this on
		// write, so reaching this branch means the on-disk file
		// was edited out-of-band. Surface a *ConfigError so the
		// caller can repair the catalog rather than dispatch a
		// malformed request.
		return Endpoint{}, &ConfigError{
			Msg: "catalog resolver: unsupported headerStyle " + entry.HeaderStyle + " for entry " + entry.ID,
		}
	}

	ep := Endpoint{
		URL:         url,
		Model:       model,
		HeaderStyle: entry.HeaderStyle,
	}
	if prof.Type == auth.OAuth {
		ep.Auth = AuthOAuthBearer
		ep.AccessToken = prof.AccessToken
	} else {
		ep.Auth = AuthAPIKey
		ep.APIKey = prof.APIKey
	}
	return ep, nil
}

// Compile-time assertion that *compositeResolver satisfies the
// Resolver interface. Mirrors the iface_check_test.go pattern
// used in internal/auth — surfaces an interface-satisfaction
// regression at build time rather than at the call site.
var _ Resolver = (*compositeResolver)(nil)
