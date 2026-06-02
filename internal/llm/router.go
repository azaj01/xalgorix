// Package llm — model router (LiteLLM-style).
//
// Router resolves a model name to an Endpoint with credentials by:
//  1. Determining which provider handles the model (via ResolveProvider)
//  2. Looking up the provider's API key (via KeyStore)
//  3. Building the correct endpoint URL (via catalog Entry)
//
// This replaces the single-provider paradigm with multi-provider
// auto-routing: operators configure keys for multiple providers,
// and the router picks the right one based on the model name.
package llm

import (
	"context"
	"fmt"
	"strings"

	"github.com/xalgord/xalgorix/v4/internal/providers"
)

// Router resolves model names to provider endpoints with credentials.
type Router struct {
	catalog  *providers.Service
	keys     *KeyStore
	modelCfg string // the model string from config (may have provider prefix)
}

// NewRouter creates a Router wired to the catalog and key store.
func NewRouter(catalog *providers.Service, keys *KeyStore) *Router {
	return &Router{
		catalog: catalog,
		keys:    keys,
	}
}

// WithModel returns a copy of the Router configured for a specific
// model string. This is used when the resolver needs to route a
// specific model rather than the default from config.
func (r *Router) WithModel(model string) *Router {
	return &Router{
		catalog:  r.catalog,
		keys:     r.keys,
		modelCfg: model,
	}
}

// RouteResult contains the resolution details for display/debugging.
type RouteResult struct {
	ProviderID  string `json:"provider_id"`
	DisplayName string `json:"display_name"`
	BareModel   string `json:"bare_model"`
	BaseURL     string `json:"base_url"`
	HeaderStyle string `json:"header_style"`
	HasKey      bool   `json:"has_key"`
}

// TestRoute resolves a model name and returns the routing details
// without actually making a request. Used by the "test model"
// feature in the settings UI.
func (r *Router) TestRoute(model string) (RouteResult, error) {
	providerID, bareModel, ok := ResolveProvider(model)
	if !ok {
		return RouteResult{}, fmt.Errorf("model %q does not match any known provider — use explicit prefix like openai/%s", model, model)
	}

	entry, entryOK, err := r.catalog.Get(context.Background(), providerID)
	if err != nil {
		return RouteResult{}, fmt.Errorf("catalog lookup failed for provider %q: %w", providerID, err)
	}
	if !entryOK {
		return RouteResult{}, fmt.Errorf("provider %q not found in catalog", providerID)
	}

	hasKey := r.keys.HasKey(providerID)

	return RouteResult{
		ProviderID:  providerID,
		DisplayName: entry.DisplayName,
		BareModel:   bareModel,
		BaseURL:     entry.BaseURL,
		HeaderStyle: entry.HeaderStyle,
		HasKey:      hasKey,
	}, nil
}

// Route resolves a model string to a complete Endpoint with
// credentials. Returns an error if the provider can't be determined,
// the provider isn't in the catalog, or no API key is configured.
func (r *Router) Route(ctx context.Context, model string) (Endpoint, error) {
	if ctx.Err() != nil {
		return Endpoint{}, ctx.Err()
	}

	if model == "" {
		model = r.modelCfg
	}
	if model == "" {
		return Endpoint{}, &ConfigError{Msg: "router: no model specified"}
	}

	// Step 1: Resolve model → provider
	providerID, bareModel, ok := ResolveProvider(model)
	if !ok {
		return Endpoint{}, &ConfigError{
			Msg: fmt.Sprintf("router: model %q does not match any known provider — use provider/model format (e.g., openai/%s)", model, model),
		}
	}

	// Step 2: Look up provider in catalog
	entry, entryOK, err := r.catalog.Get(ctx, providerID)
	if err != nil {
		return Endpoint{}, fmt.Errorf("router: catalog lookup: %w", err)
	}
	if !entryOK {
		return Endpoint{}, &ConfigError{
			Msg: fmt.Sprintf("router: provider %q not in catalog", providerID),
		}
	}

	// Step 3: Get API key
	pk, hasKey := r.keys.Get(providerID)
	if !hasKey || pk.APIKey == "" {
		return Endpoint{}, &ConfigError{
			Msg: fmt.Sprintf("router: no API key configured for %s — add it in Settings → LLM → Provider Keys", entry.DisplayName),
		}
	}

	// Step 4: Build endpoint URL
	apiBase := entry.BaseURL
	if pk.BaseURL != "" {
		apiBase = pk.BaseURL // per-key base URL override
	}
	apiBase = strings.TrimRight(apiBase, "/")

	headerStyle := entry.HeaderStyle
	if pk.HeaderStyle != "" {
		headerStyle = pk.HeaderStyle
	}

	url := apiBase
	switch headerStyle {
	case "anthropic":
		if !strings.HasSuffix(strings.ToLower(url), "/messages") {
			if !strings.HasSuffix(apiBase, "/v1") && !strings.Contains(apiBase, "/v1/") {
				url += "/v1"
			}
			url += "/messages"
		}
	case "gemini":
		url = strings.TrimSuffix(url, "/v1")
		url += "/v1beta/models/" + bareModel + ":generateContent"
	case "openai":
		if !strings.HasSuffix(strings.ToLower(url), "/chat/completions") {
			if !strings.HasSuffix(apiBase, "/v1") && !strings.Contains(apiBase, "/v1/") {
				url += "/v1"
			}
			url += "/chat/completions"
		}
	default:
		// Fallback to OpenAI-compatible format
		if !strings.HasSuffix(strings.ToLower(url), "/chat/completions") {
			if !strings.HasSuffix(apiBase, "/v1") && !strings.Contains(apiBase, "/v1/") {
				url += "/v1"
			}
			url += "/chat/completions"
		}
	}

	return Endpoint{
		URL:         url,
		Model:       bareModel,
		HeaderStyle: headerStyle,
		Auth:        AuthAPIKey,
		APIKey:      pk.APIKey,
	}, nil
}

// CanRoute returns true if the router has enough configuration to
// route at least one model (i.e., at least one provider key exists).
func (r *Router) CanRoute() bool {
	return len(r.keys.ConfiguredProviders()) > 0
}
