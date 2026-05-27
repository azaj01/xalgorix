// Package web — per-scan endpoint resolver (Wave E task 5.3).
//
// resolveScanCredentials translates a single ScanRequest into the
// effective llm.Endpoint the scan will POST to, applying the four
// precedence rules from Requirement 11:
//
//   1. R11.2: When ScanRequest.ProviderProfile is non-empty, look up
//      the matching Auth_Profile in Profile_Store and the matching
//      Catalog_Entry in Catalog_Service, build the URL via
//      buildEndpoint, and populate (Auth, APIKey | AccessToken)
//      from the profile.
//   2. R11.3: When ProviderProfile is empty, defer to
//      legacyOrCatalogDefaultEndpoint, which mirrors the existing
//      Settings free-text path (legacy resolver when the catalog is
//      empty AND XALGORIX_LLM matches Legacy_Provider_Shape;
//      otherwise the catalog's first-entry / first-profile default).
//   3. R11.4: Ad-hoc Model / APIKey / APIBase overrides take
//      precedence over whatever step 1 or 2 produced. APIKey
//      additionally forces Auth=AuthAPIKey so a pasted key never
//      gets sent as an OAuth bearer token by mistake.
//   4. R11.6: An unknown ProviderProfile (or profile referencing a
//      missing catalog entry, or an uninitialized store) returns
//      errUnknownProviderProfile so the /api/scan handler can map
//      it to HTTP 400 BEFORE any scan goroutine spawns.
//
// The /api/scan handler calls resolveScanCredentials early as a
// precondition check; the actual scan goroutine resolves through
// the LLM client's composite resolver as before, so this helper is
// not yet on the hot path of an in-flight request. Surfacing the
// 400 here is purely a fail-fast against a misspelled profile id.
//
// Validates: Requirements 11.1, 11.2, 11.3, 11.4, 11.5, 11.6.
package web

import (
	"context"
	"errors"
	"log"
	"strings"

	"github.com/xalgord/xalgorix/v4/internal/auth"
	"github.com/xalgord/xalgorix/v4/internal/config"
	"github.com/xalgord/xalgorix/v4/internal/llm"
	"github.com/xalgord/xalgorix/v4/internal/providers"
)

// errUnknownProviderProfile is returned by resolveScanCredentials
// whenever the supplied ProviderProfile cannot be mapped to a live
// (Catalog_Entry, Auth_Profile) tuple. The handler maps this to
// HTTP 400 with the canonical body "unknown provider profile" per
// Requirement 11.6. Declared as a sentinel (rather than ad-hoc
// fmt.Errorf) so test code and future callers can errors.Is on it.
var errUnknownProviderProfile = errors.New("unknown provider profile")

// resolveScanCredentials returns the effective LLM endpoint for one
// scan. The full precedence rule lives in the package doc above; in
// summary: profile lookup (R11.2) → catalog default fallback (R11.3)
// → ad-hoc override merge (R11.4). Unknown ProviderProfile values
// return errUnknownProviderProfile so the /api/scan handler can
// fail fast with HTTP 400 (R11.6).
//
// Validates: Requirements 11.2, 11.3, 11.4, 11.6.
func (s *Server) resolveScanCredentials(ctx context.Context, req ScanRequest, cfg *config.Config) (llm.Endpoint, error) {
	var ep llm.Endpoint

	if req.ProviderProfile != "" {
		// Profile-driven resolution requires both stores to be
		// live. A nil catalog or profile store on a request that
		// names a profile is indistinguishable from a "missing"
		// profile from the operator's point of view, so collapse
		// both to errUnknownProviderProfile rather than surfacing
		// a 503 — the dashboard shows one error envelope either
		// way and the operator's first remediation step is the
		// same: re-check the spelling of the profile key.
		if s.profiles == nil || s.catalog == nil {
			return llm.Endpoint{}, errUnknownProviderProfile
		}
		prof, ok, err := s.profiles.Get(ctx, req.ProviderProfile)
		if err != nil {
			return llm.Endpoint{}, err
		}
		if !ok {
			return llm.Endpoint{}, errUnknownProviderProfile
		}
		entry, ok, err := s.catalog.Get(ctx, prof.Provider)
		if err != nil {
			return llm.Endpoint{}, err
		}
		if !ok {
			// Profile references a catalog entry that no longer
			// exists. From the operator's point of view this is
			// the same failure mode as a missing profile — the
			// "<provider>:<profileId>" key cannot be resolved
			// to an outbound endpoint.
			return llm.Endpoint{}, errUnknownProviderProfile
		}
		url, model, headerStyle := buildEndpoint(entry, prof)
		ep = llm.Endpoint{
			URL:         url,
			Model:       model,
			HeaderStyle: headerStyle,
		}
		if prof.Type == auth.OAuth {
			ep.Auth = llm.AuthOAuthBearer
			ep.AccessToken = prof.AccessToken
		} else {
			ep.Auth = llm.AuthAPIKey
			ep.APIKey = prof.APIKey
		}
	} else {
		// No provider_profile → legacy / catalog-default path
		// (Requirement 11.3). The helper returns a zero Endpoint
		// when no provider is configured at all; we leave it
		// zero here so the ad-hoc overrides below can still
		// populate it (the operator may be supplying APIBase +
		// APIKey + Model directly).
		ep = s.legacyOrCatalogDefaultEndpoint(ctx, cfg)
	}

	// Ad-hoc override merge (Requirement 11.4). The same
	// authenticated-operator gate already enforced on /api/scan
	// admits the override path; this helper only merges values.
	//
	// Order matters: APIKey is processed before Model/APIBase so
	// the Auth flip to AuthAPIKey takes effect even on requests
	// that also override Model. APIKey also clears AccessToken so
	// a stale OAuth bearer never rides along on a request the
	// operator explicitly steered to API-key auth.
	if req.APIKey != "" {
		ep.Auth = llm.AuthAPIKey
		ep.APIKey = req.APIKey
		ep.AccessToken = ""
	}
	if req.Model != "" {
		ep.Model = req.Model
	}
	if req.APIBase != "" {
		// Best-effort override: callers historically pass the
		// full chat-completions / messages / generateContent
		// URL here, so we just trim the trailing slash and use
		// it verbatim. The legacy resolver behaved identically
		// (Client.resolveEndpoint set apiBase from cfg.APIBase
		// without re-deriving the version segment), so this
		// preserves the existing override semantics.
		ep.URL = strings.TrimRight(req.APIBase, "/")
	}
	return ep, nil
}

// scanLLMClientForRequest is the swallow-error wrapper around
// buildScanLLMClient used at scanSession construction. The
// /api/scan precondition has already short-circuited the
// errUnknownProviderProfile case so any error here is a transient
// "the underlying file lock contended" / "profile race-deleted"
// shape; logging and returning nil keeps the scan running with the
// agent's default client (and surfaces the credential gap at first
// chat call) rather than tearing down the scan goroutine.
//
// Validates: B1 (per-scan provider_profile resolver wiring).
func (s *Server) scanLLMClientForRequest(req ScanRequest, scanCfg *config.Config) *llm.Client {
	client, err := s.buildScanLLMClient(context.Background(), req, scanCfg)
	if err != nil {
		log.Printf("[scan] resolver wiring failed for instance=%q profile=%q: %v (falling back to default client)", req.InstanceID, req.ProviderProfile, err)
		return nil
	}
	return client
}

// buildScanLLMClient returns a *llm.Client primed with a fixed
// resolver that reflects this scan's resolved provider_profile (or
// the legacy / catalog-default fallback when ProviderProfile is
// empty). Callers thread the returned client into agent.NewAgent
// via agent.WithLLMClient so the scan goroutine's outbound LLM
// traffic carries the operator's chosen credentials — which closes
// the B1 gap where a per-scan provider_profile setting was silently
// ignored because runScanInstance only built llm.NewClient(cfg)
// with no resolver attached.
//
// The Endpoint baked into the resolver is whatever
// resolveScanCredentials produced: the same precedence-merged
// (URL, model, headerStyle, auth, credentials) the /api/scan
// precondition check already validated. We deliberately do NOT
// re-evaluate the catalog/legacy gate at chat-call time — doing so
// would let a mid-scan catalog edit silently retarget the in-flight
// scan, which is a worse property than freezing the endpoint at
// scan start.
//
// On any resolver error (errUnknownProviderProfile or otherwise)
// buildScanLLMClient surfaces the error to the caller so the scan
// never starts with a half-resolved client. The legacy "no
// configuration anywhere" fallback is preserved by handing back a
// no-resolver client when the resolver returned a zero Endpoint
// without an error — the LLM client's own composite resolver path
// then gets a chance to surface a *ConfigError at first chat call
// with the same message it always did.
//
// Validates: B1 (per-scan provider_profile resolver wiring).
func (s *Server) buildScanLLMClient(ctx context.Context, req ScanRequest, cfg *config.Config) (*llm.Client, error) {
	ep, err := s.resolveScanCredentials(ctx, req, cfg)
	if err != nil {
		return nil, err
	}
	if isZeroEndpoint(ep) {
		// No useful routing info → defer to the LLM client's
		// own composite resolver so legacy installs without any
		// provider configuration still get the canonical
		// *ConfigError at first chat call.
		return llm.NewClient(cfg), nil
	}
	return llm.NewClient(cfg, llm.WithResolver(llm.NewFixedResolver(ep))), nil
}

// isZeroEndpoint reports whether ep carries no useful routing
// information — used by buildScanLLMClient to decide whether to
// install a fixed resolver or to fall back to the LLM client's
// default resolver. A nonzero URL is the strongest signal of
// usefulness; APIKey / AccessToken alone (with no URL) means the
// operator pasted credentials but did not steer them anywhere, so
// the legacy resolver's providerBases-derived URL still applies.
func isZeroEndpoint(ep llm.Endpoint) bool {
	return ep.URL == "" && ep.Model == "" && ep.APIKey == "" && ep.AccessToken == ""
}

// buildEndpoint assembles the (url, model, headerStyle) tuple for a
// single (Catalog_Entry, Auth_Profile) pair. The URL builder mirrors
// the three header-style branches in internal/llm/resolver.go's
// catalogResolver so profile-driven scans hit the same outbound URLs
// the catalog resolver would have built for a default pick.
//
// API_Key_Profile records honor APIBaseOverride per Requirement 4.5
// — that's the per-profile escape hatch for proxying through a
// custom gateway without touching the catalog entry's BaseURL.
// OAuth_Profile records do not expose a base override because the
// access token is bound to the catalog entry's authorization server.
//
// Validates: Requirements 2.3 (preserved endpoint shape), 11.2.
func buildEndpoint(entry providers.Entry, prof auth.Profile) (url, model, headerStyle string) {
	base := entry.BaseURL
	if prof.Type == auth.APIKey && prof.APIBaseOverride != "" {
		base = prof.APIBaseOverride
	}
	base = strings.TrimRight(base, "/")
	headerStyle = entry.HeaderStyle
	if len(entry.Models) > 0 {
		model = entry.Models[0]
	}

	switch headerStyle {
	case "anthropic":
		// Anthropic uses /v1/messages. Append /v1 only when the
		// configured base does not already include a version
		// segment.
		if !strings.HasSuffix(strings.ToLower(base), "/messages") {
			if !strings.HasSuffix(base, "/v1") && !strings.Contains(base, "/v1/") {
				base += "/v1"
			}
			base += "/messages"
		}
	case "gemini":
		// Google Gemini uses /v1beta/models/MODEL:generateContent.
		// Strip any trailing /v1 first so we don't produce
		// /v1/v1beta when the base URL was configured with the
		// version segment baked in.
		base = strings.TrimSuffix(base, "/v1")
		base += "/v1beta/models/" + model + ":generateContent"
	default:
		// "openai" (and any future OpenAI-compatible header style
		// validateEntry happens to allow): /v1/chat/completions.
		if !strings.HasSuffix(strings.ToLower(base), "/chat/completions") {
			if !strings.HasSuffix(base, "/v1") && !strings.Contains(base, "/v1/") {
				base += "/v1"
			}
			base += "/chat/completions"
		}
	}
	url = base
	return
}

// legacyOrCatalogDefaultEndpoint is the fallback resolver consulted
// when ScanRequest.ProviderProfile is empty. The selection order
// mirrors the LLM client's composite resolver (Wave D task 4.1):
//
//  1. Catalog non-empty → first catalog entry + first matching
//     profile, built via buildEndpoint. This is the "current default
//     provider" view the dashboard renders for the Settings page.
//  2. Catalog empty AND XALGORIX_LLM matches Legacy_Provider_Shape
//     → defer to llm.NewCompositeResolver(WithLegacy(cfg)) and
//     return its Resolve result. This is the Legacy_Fallback path
//     (Requirements 2.1, 2.3).
//  3. Otherwise → return a zero Endpoint. The caller may still
//     populate it through ad-hoc Model/APIKey/APIBase overrides
//     (Requirement 11.4). When even those are empty, the actual
//     LLM client call later in the scan will surface a *ConfigError
//     through its own Resolver path — there's no point producing a
//     duplicate "no provider configured" error here.
//
// Validates: Requirements 2.1, 2.2, 2.3, 11.3.
func (s *Server) legacyOrCatalogDefaultEndpoint(ctx context.Context, cfg *config.Config) llm.Endpoint {
	// Branch 1 — catalog default pick.
	if s.catalog != nil && !s.catalog.IsEmpty() {
		entries, err := s.catalog.List(ctx)
		if err == nil && len(entries) > 0 {
			entry := entries[0]
			if s.profiles != nil {
				profs, err := s.profiles.List(ctx)
				if err == nil {
					for _, p := range profs {
						if p.Provider != entry.ID {
							continue
						}
						url, model, headerStyle := buildEndpoint(entry, p)
						ep := llm.Endpoint{
							URL:         url,
							Model:       model,
							HeaderStyle: headerStyle,
						}
						if p.Type == auth.OAuth {
							ep.Auth = llm.AuthOAuthBearer
							ep.AccessToken = p.AccessToken
						} else {
							ep.Auth = llm.AuthAPIKey
							ep.APIKey = p.APIKey
						}
						return ep
					}
				}
			}
		}
	}

	// Branch 2 — Legacy_Fallback. Only engages when the operator's
	// XALGORIX_LLM names one of the eight known legacy slugs;
	// arbitrary custom values fall through to branch 3.
	if cfg != nil && llm.LegacyProviderShape(cfg.LLM) {
		r := llm.NewCompositeResolver(llm.WithLegacy(cfg))
		if ep, err := r.Resolve(ctx); err == nil {
			return ep
		}
	}

	// Branch 3 — neither a catalog default nor a legacy match.
	// Return a zero Endpoint and let the ad-hoc override merge
	// (or, ultimately, the LLM client's own resolver) decide what
	// to do. This avoids stamping a stale URL onto the request
	// when the operator is supplying APIBase/APIKey/Model fields
	// directly.
	return llm.Endpoint{}
}
