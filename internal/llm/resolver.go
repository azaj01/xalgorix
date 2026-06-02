// Package llm — composite Resolver wiring (rewritten in v4.4.22).
//
// v4.4.21 routed outbound LLM traffic through a runtime-editable
// catalog whose existence/emptiness drove the legacy/catalog
// branch decision. v4.4.22 replaces that with a compiled-in
// catalog plus an explicit "active credential" pointer
// (cfg.LLMProfile, "<provider>:<profileId>"). The composite
// resolver now dispatches purely off cfg.LLMProfile + cfg.APIKey.
//
// Decision order:
//
//  1. cfg.LLMProfile != "" AND maps to a real Profile_Store entry
//     AND that entry's Provider matches a Builtin() catalog id →
//     dispatch through catalogResolver.
//
//  2. Else cfg.LLM matches Legacy_Provider_Shape AND cfg.APIKey is
//     set → dispatch through legacyResolver. This preserves the
//     v4.4.21 path for operators upgrading without re-saving
//     credentials through the new UI.
//
//  3. Otherwise → return *ConfigError "no provider configured".
//
// The per-scan picker plumbed through WithCatalogPicker still
// overrides the active-credential lookup so a per-request
// ScanRequest.ProviderProfile can target a different stored
// profile without touching cfg.LLMProfile.
package llm

import (
	"context"
	"strings"

	"github.com/xalgord/xalgorix/v4/internal/auth"
	"github.com/xalgord/xalgorix/v4/internal/config"
	"github.com/xalgord/xalgorix/v4/internal/providers"
)

// ConfigError is the typed error the composite resolver returns
// when neither the catalog branch nor the legacy fallback can
// supply an outbound endpoint. The HTTP layer pattern-matches on
// this type to render a "no provider configured" message rather
// than a generic 500.
type ConfigError struct {
	Msg string
}

// Error implements the error interface.
func (e *ConfigError) Error() string { return e.Msg }

// legacyProviderBases is the runtime-immutable map of legacy
// provider slugs → default API base URLs. Lifted verbatim from
// the v4.4.21 client.resolveEndpoint so the legacy resolver
// produces byte-identical URL results to the pre-feature path.
var legacyProviderBases = map[string]string{
	"openai":    "https://api.openai.com/v1",
	"anthropic": "https://api.anthropic.com",
	"minimax":   "https://api.minimax.io/v1",
	"deepseek":  "https://api.deepseek.com/v1",
	"groq":      "https://api.groq.com/openai/v1",
	"ollama":    "http://localhost:11434/v1",
	"google":    "https://generativelanguage.googleapis.com",
	"gemini":    "https://generativelanguage.googleapis.com",
}

// LegacyProviderBaseURL returns the canonical legacy API base URL
// for the supplied provider slug (case-insensitive) and reports
// whether the slug is recognized.
func LegacyProviderBaseURL(provider string) (string, bool) {
	v, ok := legacyProviderBases[strings.ToLower(strings.TrimSpace(provider))]
	return v, ok
}

// legacyResolver reproduces v4.4.21 client.resolveEndpoint().
type legacyResolver struct {
	cfg *config.Config
}

// catalogPick bundles the catalog Entry and credential Profile
// the catalog branch should use for one outbound request.
type catalogPick struct {
	entry   providers.Entry
	profile auth.Profile
}

// catalogResolver pulls baseURL + headerStyle from the compiled-in
// catalog (looked up by provider slug) and the access credential
// from the chosen Profile.
type catalogResolver struct {
	cat  *providers.Service
	prof *auth.Store
	pick func(ctx context.Context) (catalogPick, error)
}

// compositeResolver dispatches between catalogResolver and
// legacyResolver per the precedence rules in the package doc.
type compositeResolver struct {
	cat  *providers.Service
	prof *auth.Store
	cfg  *config.Config
	pick func(ctx context.Context) (catalogPick, error)
}

// ResolverOption configures the compositeResolver.
type ResolverOption func(*compositeResolver)

// WithCatalog wires the read-only catalog and the profile store
// into the composite. Both arguments must be non-nil for the
// catalog branch to engage; the catalog itself is the compiled-in
// providers.Builtin() set so it never reports IsEmpty == true.
func WithCatalog(cat *providers.Service, prof *auth.Store) ResolverOption {
	return func(c *compositeResolver) {
		c.cat = cat
		c.prof = prof
	}
}

// WithLegacy wires the legacy *config.Config so the legacy
// fallback branch has access to cfg.LLM / cfg.APIKey / cfg.APIBase.
func WithLegacy(cfg *config.Config) ResolverOption {
	return func(c *compositeResolver) {
		c.cfg = cfg
	}
}

// WithCatalogPicker injects a custom per-scan picker. The default
// picker uses cfg.LLMProfile to look up a Profile_Store entry; the
// per-scan path in internal/web overrides this to honor a
// ScanRequest.ProviderProfile field.
func WithCatalogPicker(pick func(ctx context.Context) (catalogPick, error)) ResolverOption {
	return func(c *compositeResolver) {
		c.pick = pick
	}
}

// NewCompositeResolver builds a Resolver that dispatches between
// the catalog-driven path and the legacy fallback per the
// precedence rules documented at the top of this file.
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

// defaultCatalogPick reads cfg.LLMProfile, splits it into
// "<provider>:<profileId>", looks the matching profile up in the
// store, and looks the matching catalog entry up in Builtin(). An
// empty cfg.LLMProfile is signaled via *ConfigError so the
// composite falls through to the legacy branch.
func defaultCatalogPick(c *compositeResolver) func(ctx context.Context) (catalogPick, error) {
	return func(ctx context.Context) (catalogPick, error) {
		if c.cat == nil {
			return catalogPick{}, &ConfigError{Msg: "catalog resolver: catalog service not wired"}
		}
		if c.prof == nil {
			return catalogPick{}, &ConfigError{Msg: "catalog resolver: profile store not wired"}
		}
		if c.cfg == nil || strings.TrimSpace(c.cfg.LLMProfile) == "" {
			return catalogPick{}, &ConfigError{Msg: "catalog resolver: no active LLM profile (XALGORIX_LLM_PROFILE unset)"}
		}
		profile, ok, err := c.prof.Get(ctx, strings.TrimSpace(c.cfg.LLMProfile))
		if err != nil {
			return catalogPick{}, err
		}
		if !ok {
			return catalogPick{}, &ConfigError{
				Msg: "catalog resolver: profile " + c.cfg.LLMProfile + " not found",
			}
		}
		entry, ok, err := c.cat.Get(ctx, profile.Provider)
		if err != nil {
			return catalogPick{}, err
		}
		if !ok {
			return catalogPick{}, &ConfigError{
				Msg: "catalog resolver: provider " + profile.Provider + " not in builtin catalog",
			}
		}
		return catalogPick{entry: entry, profile: profile}, nil
	}
}

// Resolve implements Resolver. It evaluates the cfg.LLMProfile
// gate on every call so the choice tracks runtime mutations to
// the active credential pointer.
func (c *compositeResolver) Resolve(ctx context.Context) (Endpoint, error) {
	// Branch 1 — explicit active credential pointer wins.
	if c.cfg != nil && strings.TrimSpace(c.cfg.LLMProfile) != "" && c.cat != nil && c.prof != nil {
		cr := &catalogResolver{cat: c.cat, prof: c.prof, pick: c.pick}
		ep, err := cr.Resolve(ctx)
		if err == nil {
			return ep, nil
		}
		// On catalog-branch failure (unknown profile, missing
		// catalog entry) return the typed error so the HTTP
		// layer surfaces "no provider configured" rather than
		// silently falling through to legacy.
		return Endpoint{}, err
	}

	// Branch 2 — legacy fallback. cfg.APIKey must also be set per
	// the new precedence rules so a stale cfg.LLM without
	// credentials does not produce a broken outbound request.
	if c.cfg != nil && LegacyProviderShape(c.cfg.LLM) && strings.TrimSpace(c.cfg.APIKey) != "" {
		lr := &legacyResolver{cfg: c.cfg}
		return lr.Resolve(ctx)
	}

	// Branch 3 — neither path is available.
	return Endpoint{}, &ConfigError{
		Msg: "no provider configured: set XALGORIX_LLM_PROFILE to a saved credential or set XALGORIX_LLM + XALGORIX_API_KEY",
	}
}

// Resolve on legacyResolver reproduces v4.4.21
// Client.resolveEndpoint() step-for-step.
func (l *legacyResolver) Resolve(ctx context.Context) (Endpoint, error) {
	if err := ctx.Err(); err != nil {
		return Endpoint{}, err
	}
	if l.cfg == nil {
		return Endpoint{}, &ConfigError{Msg: "legacy resolver: nil config"}
	}

	apiBase := l.cfg.APIBase
	model := l.cfg.LLM

	provider := ""
	if idx := strings.Index(model, "/"); idx >= 0 {
		provider = strings.ToLower(model[:idx])
		model = model[idx+1:]
	}

	if apiBase == "" {
		if knownBase, ok := legacyProviderBases[provider]; ok {
			apiBase = knownBase
		} else {
			apiBase = "https://api.openai.com/v1"
		}
	}
	apiBase = strings.TrimRight(apiBase, "/")

	url := apiBase
	switch {
	case provider == "anthropic" || isAnthropicAPIBase(apiBase):
		if !strings.HasSuffix(strings.ToLower(url), "/messages") {
			if !strings.HasSuffix(apiBase, "/v1") && !strings.Contains(apiBase, "/v1/") {
				url += "/v1"
			}
			url += "/messages"
		}
	case isGeminiProvider(provider) || isGeminiAPIBase(apiBase):
		url = strings.TrimSuffix(url, "/v1")
		url += "/v1beta/models/" + model + ":generateContent"
	default:
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

// legacyHeaderStyle maps a legacy slug + base URL to one of the
// three values the LLM client switch dispatches on.
func legacyHeaderStyle(provider, apiBase string) string {
	switch provider {
	case "openai", "minimax", "deepseek", "groq", "ollama":
		return "openai"
	case "anthropic":
		return "anthropic"
	case "google", "gemini":
		return "gemini"
	}
	if isAnthropicAPIBase(apiBase) {
		return "anthropic"
	}
	if isGeminiAPIBase(apiBase) {
		return "gemini"
	}
	return "openai"
}

// Resolve on catalogResolver pulls baseURL + headerStyle from the
// catalog Entry and credentials from the matching Profile.
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

	model := ""
	if len(entry.Models) > 0 {
		model = entry.Models[0]
	}

	apiBase := entry.BaseURL
	if prof.Type == auth.APIKey && prof.APIBaseOverride != "" {
		apiBase = prof.APIBaseOverride
	}
	apiBase = strings.TrimRight(apiBase, "/")

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

// Compile-time interface assertion.
var _ Resolver = (*compositeResolver)(nil)
