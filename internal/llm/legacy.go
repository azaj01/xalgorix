package llm

import "strings"

// LegacyProviderShape reports whether xalgorixLLM names one of the
// historical provider slugs that the legacy resolver in client.go
// understands. It lowercases the input, takes the prefix before the
// first '/', and returns true for any of the eight known slugs.
//
// Validates: Requirements 2.1, 2.4.
func LegacyProviderShape(xalgorixLLM string) bool {
	s := strings.ToLower(xalgorixLLM)
	if i := strings.Index(s, "/"); i >= 0 {
		s = s[:i]
	}
	switch s {
	case "openai", "anthropic", "minimax", "deepseek",
		"groq", "ollama", "google", "gemini":
		return true
	}
	return false
}
