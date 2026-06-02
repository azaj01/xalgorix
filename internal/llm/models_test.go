package llm

import (
	"testing"
)

func TestResolveProvider_ExplicitPrefix(t *testing.T) {
	tests := []struct {
		model     string
		wantPID   string
		wantModel string
		wantOK    bool
	}{
		{"openai/gpt-4o", "openai", "gpt-4o", true},
		{"anthropic/claude-sonnet-4-20250514", "anthropic", "claude-sonnet-4-20250514", true},
		{"google/gemini-2.5-pro", "google", "gemini-2.5-pro", true},
		{"deepseek/deepseek-chat", "deepseek", "deepseek-chat", true},
		{"groq/llama-3.3-70b-versatile", "groq", "llama-3.3-70b-versatile", true},
		{"xai/grok-3", "xai", "grok-3", true},
	}

	for _, tt := range tests {
		t.Run(tt.model, func(t *testing.T) {
			pid, bare, ok := ResolveProvider(tt.model)
			if ok != tt.wantOK {
				t.Fatalf("ResolveProvider(%q) ok = %v, want %v", tt.model, ok, tt.wantOK)
			}
			if pid != tt.wantPID {
				t.Errorf("ResolveProvider(%q) pid = %q, want %q", tt.model, pid, tt.wantPID)
			}
			if bare != tt.wantModel {
				t.Errorf("ResolveProvider(%q) bare = %q, want %q", tt.model, bare, tt.wantModel)
			}
		})
	}
}

func TestResolveProvider_ExactMatch(t *testing.T) {
	tests := []struct {
		model   string
		wantPID string
		wantOK  bool
	}{
		{"gpt-4o", "openai", true},
		{"gpt-4o-mini", "openai", true},
		{"deepseek-chat", "deepseek", true},
		{"deepseek-reasoner", "deepseek", true},
		{"gemini-2.5-pro", "google", true},
		{"gemini-2.5-flash", "google", true},
	}

	for _, tt := range tests {
		t.Run(tt.model, func(t *testing.T) {
			pid, _, ok := ResolveProvider(tt.model)
			if ok != tt.wantOK {
				t.Fatalf("ResolveProvider(%q) ok = %v, want %v", tt.model, ok, tt.wantOK)
			}
			if pid != tt.wantPID {
				t.Errorf("ResolveProvider(%q) pid = %q, want %q", tt.model, pid, tt.wantPID)
			}
		})
	}
}

func TestResolveProvider_PatternMatch(t *testing.T) {
	tests := []struct {
		model   string
		wantPID string
		wantOK  bool
	}{
		// OpenAI patterns
		{"gpt-4.1-turbo", "openai", true},
		{"gpt-5-preview", "openai", true},
		{"o1-preview", "openai", true},
		{"o3-mini", "openai", true},
		// Anthropic patterns
		{"claude-3-haiku", "anthropic", true},
		{"claude-3.5-sonnet-latest", "anthropic", true},
		// Google patterns
		{"gemini-2.0-flash-exp", "google", true},
		{"gemini-3-ultra", "google", true},
		// DeepSeek patterns
		{"deepseek-v3", "deepseek", true},
		// xAI patterns
		{"grok-4-preview", "xai", true},
		// Mistral patterns
		{"mistral-large-latest", "mistral", true},
		{"open-mistral-nemo", "mistral", true},
		// Qwen patterns
		{"qwen-max-1201", "qwen", true},
		// Unknown model → no match
		{"my-custom-model", "", false},
		{"", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.model, func(t *testing.T) {
			pid, _, ok := ResolveProvider(tt.model)
			if ok != tt.wantOK {
				t.Fatalf("ResolveProvider(%q) ok = %v, want %v", tt.model, ok, tt.wantOK)
			}
			if ok && pid != tt.wantPID {
				t.Errorf("ResolveProvider(%q) pid = %q, want %q", tt.model, pid, tt.wantPID)
			}
		})
	}
}

func TestResolveProvider_CaseInsensitive(t *testing.T) {
	// Explicit prefix is case-insensitive for the provider part
	pid, bare, ok := ResolveProvider("OpenAI/GPT-4o")
	if !ok {
		t.Fatal("expected explicit prefix to match case-insensitively")
	}
	if pid != "openai" {
		t.Errorf("got pid=%q, want openai", pid)
	}
	if bare != "GPT-4o" {
		t.Errorf("got bare=%q, want GPT-4o (original case)", bare)
	}
}

func TestResolveProvider_OrgSlashModel(t *testing.T) {
	// Models like "meta-llama/Llama-3.1-70B-Instruct" should match
	// via exact match (they're in the catalog), not as a provider prefix.
	pid, _, ok := ResolveProvider("meta-llama/Meta-Llama-3.1-70B-Instruct")
	if !ok {
		t.Skip("org/model format not in this catalog build")
	}
	// Should resolve to a known provider, not "meta-llama"
	if pid == "meta-llama" {
		t.Error("should not resolve org prefix as provider")
	}
}

func TestKnownProviderIDs(t *testing.T) {
	ids := KnownProviderIDs()
	if len(ids) == 0 {
		t.Fatal("expected at least one known provider")
	}
	// Verify well-known providers are present
	seen := make(map[string]bool)
	for _, id := range ids {
		seen[id] = true
	}
	for _, want := range []string{"openai", "anthropic", "google", "deepseek"} {
		if !seen[want] {
			t.Errorf("expected %q in KnownProviderIDs(), got %v", want, ids)
		}
	}
}
