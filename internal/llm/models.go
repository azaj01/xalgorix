// Package llm — model name → provider resolution (LiteLLM-style).
//
// ResolveProvider examines a model string and determines which
// compiled-in catalog provider should handle it. Three resolution
// modes, evaluated in order:
//
//  1. Explicit prefix:  "openai/gpt-4o"  → provider "openai", bare model "gpt-4o"
//  2. Exact match:      "gpt-4o"         → scan builtin catalog Models lists
//  3. Pattern match:    "gpt-4.1-turbo"  → match against well-known prefixes
//
// The model index is built lazily on first call from
// providers.Builtin() and cached for the process lifetime.
package llm

import (
	"strings"
	"sync"

	"github.com/xalgord/xalgorix/v4/internal/providers"
)

// modelIndexOnce guards lazy initialization of the model index.
var modelIndexOnce sync.Once

// exactIndex maps exact model names to provider IDs. Built from
// every entry's Models slice in the builtin catalog.
var exactIndex map[string]string

// patternRules are ordered prefix/substring rules for well-known
// model families. Evaluated after exact-match fails. Order matters:
// more specific patterns come first.
var patternRules []patternRule

type patternRule struct {
	prefix     string // match model name prefix (lowercased)
	providerID string
}

// canonicalProviders lists provider IDs that are the "true origin"
// for their models. When multiple catalog entries list the same
// model name (e.g., copilot and openai both list "gpt-4o"),
// canonical providers win. Non-canonical entries (gateways, proxies)
// only populate the index for models not claimed by a canonical.
var canonicalProviders = map[string]bool{
	"openai":    true,
	"anthropic": true,
	"google":    true,
	"deepseek":  true,
	"mistral":   true,
	"xai":       true,
	"groq":      true,
	"qwen":      true,
	"moonshot":  true,
	"minimax":   true,
	"nvidia":    true,
	"cohere":    true,
}

// initModelIndex builds the exact-match index and pattern rules
// from the compiled-in catalog. Called once via sync.Once.
//
// Two-pass strategy: first index canonical providers (the model
// originators), then fill gaps with non-canonical entries
// (gateways, proxies, wrappers). This ensures "gpt-4o" resolves
// to "openai" rather than "copilot" or "litellm".
func initModelIndex() {
	catalog := providers.Builtin()
	exactIndex = make(map[string]string, len(catalog)*3)

	// Pass 1: canonical providers (true model origins)
	for _, e := range catalog {
		if e.ID == "custom" || e.ID == "litellm" {
			continue
		}
		if !canonicalProviders[e.ID] {
			continue
		}
		for _, m := range e.Models {
			lower := strings.ToLower(m)
			if _, exists := exactIndex[lower]; !exists {
				exactIndex[lower] = e.ID
			}
		}
	}

	// Pass 2: non-canonical providers (gateways, wrappers)
	for _, e := range catalog {
		if e.ID == "custom" || e.ID == "litellm" {
			continue
		}
		if canonicalProviders[e.ID] {
			continue // already indexed
		}
		for _, m := range e.Models {
			lower := strings.ToLower(m)
			if _, exists := exactIndex[lower]; !exists {
				exactIndex[lower] = e.ID
			}
		}
	}

	// Well-known model family prefixes. These catch models not
	// explicitly listed in the catalog (e.g., "gpt-4.1-turbo",
	// "claude-3-haiku", "gemini-2.0-flash-exp").
	//
	// Order: more specific prefixes first.
	patternRules = []patternRule{
		// OpenAI
		{"gpt-", "openai"},
		{"o1", "openai"},
		{"o3", "openai"},
		{"o4", "openai"},
		{"chatgpt-", "openai"},
		{"dall-e-", "openai"},
		{"whisper-", "openai"},
		{"tts-", "openai"},
		{"text-embedding-", "openai"},
		{"gpt-5", "openai"},
		// Anthropic
		{"claude-", "anthropic"},
		// Google
		{"gemini-", "google"},
		// DeepSeek
		{"deepseek-", "deepseek"},
		// xAI
		{"grok-", "xai"},
		// Mistral
		{"mistral-", "mistral"},
		{"open-mistral-", "mistral"},
		{"open-mixtral-", "mistral"},
		{"codestral-", "mistral"},
		// Qwen
		{"qwen-", "qwen"},
		// Meta Llama (generic — matches if no specific provider)
		{"llama-", "groq"},
		{"llama3", "groq"},
		// Moonshot / Kimi
		{"moonshot-", "moonshot"},
		{"kimi-", "moonshot"},
		// MiniMax
		{"minimax-", "minimax"},
		// NVIDIA-hosted model ids
		{"nvidia/", "nvidia"},
		{"meta/llama-", "nvidia"},
		// Cohere
		{"command-", "cohere"},
	}
}

// ResolveProvider determines the provider ID and bare model name
// for a given model string. Returns (providerID, bareModel, true)
// on success, or ("", model, false) if unresolvable.
//
// Resolution precedence:
//  1. Explicit prefix: "anthropic/claude-3.5-sonnet" → ("anthropic", "claude-3.5-sonnet", true)
//  2. Exact match: "gpt-4o" found in catalog → ("openai", "gpt-4o", true)
//  3. Pattern match: "gpt-4.1-nano" starts with "gpt-" → ("openai", "gpt-4.1-nano", true)
func ResolveProvider(model string) (providerID, bareModel string, ok bool) {
	modelIndexOnce.Do(initModelIndex)

	model = strings.TrimSpace(model)
	if model == "" {
		return "", "", false
	}

	// 1. Explicit provider prefix: "openai/gpt-4o"
	if idx := strings.IndexByte(model, '/'); idx > 0 {
		prefix := strings.ToLower(model[:idx])
		bare := model[idx+1:]
		// Verify the prefix is a known provider ID
		for _, e := range providers.Builtin() {
			if e.ID == prefix {
				return prefix, bare, true
			}
		}
		// Special case: some models use org/model format
		// (e.g., "meta-llama/Llama-3.1-70B-Instruct") that
		// aren't provider prefixes. Fall through to exact match.
	}

	// 2. Exact match against catalog entries
	lower := strings.ToLower(model)
	if pid, found := exactIndex[lower]; found {
		return pid, model, true
	}

	// 3. Pattern match against well-known prefixes
	for _, rule := range patternRules {
		if strings.HasPrefix(lower, rule.prefix) {
			return rule.providerID, model, true
		}
	}

	return "", model, false
}

// KnownProviderIDs returns all provider IDs that the model
// resolver can route to. Used by the settings UI to show which
// providers support auto-routing.
func KnownProviderIDs() []string {
	modelIndexOnce.Do(initModelIndex)
	seen := make(map[string]bool)
	var ids []string
	for _, pid := range exactIndex {
		if !seen[pid] {
			seen[pid] = true
			ids = append(ids, pid)
		}
	}
	for _, rule := range patternRules {
		if !seen[rule.providerID] {
			seen[rule.providerID] = true
			ids = append(ids, rule.providerID)
		}
	}
	return ids
}
