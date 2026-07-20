package llm

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/config"
)

// Newer OpenAI models (GPT-5 family, o-series reasoning models) reject the
// legacy `max_tokens` param and require `max_completion_tokens`. Regression
// guard for issue #236 ("Unsupported parameter: 'max_tokens' ... Use
// 'max_completion_tokens' instead").
func TestUsesMaxCompletionTokens(t *testing.T) {
	cases := map[string]bool{
		"gpt-5":          true,
		"gpt-5.4":        true,
		"gpt-5-mini":     true,
		"openai/gpt-5.4": true,
		"o1":             true,
		"o1-mini":        true,
		"o3":             true,
		"o3-mini":        true,
		"o4-mini":        true,

		"gpt-4o":          false,
		"gpt-4.1":         false,
		"gpt-4-turbo":     false,
		"deepseek-v4-pro": false,
		"claude-sonnet-4": false,
		"minimax-01":      false,
		"llama3.1":        false,
	}
	for model, want := range cases {
		if got := usesMaxCompletionTokens(model); got != want {
			t.Errorf("usesMaxCompletionTokens(%q) = %v, want %v", model, got, want)
		}
	}
}

func TestBuildChatRequest_GPT5UsesMaxCompletionTokens(t *testing.T) {
	c := NewClient(&config.Config{LLM: "openai/gpt-5.4", APIKey: "k", MaxOutputTokens: 4096})
	req := c.buildChatRequest("gpt-5.4", []Message{{Role: "user", Content: "hi"}},
		"https://api.openai.com/v1/chat/completions", false)
	body, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	s := string(body)
	if !strings.Contains(s, `"max_completion_tokens":4096`) {
		t.Errorf("expected max_completion_tokens:4096, got %s", s)
	}
	if strings.Contains(s, `"max_tokens"`) {
		t.Errorf("gpt-5 request must NOT contain max_tokens, got %s", s)
	}
	// GPT-5 / o-series only accept the default temperature — it must be omitted.
	if strings.Contains(s, `"temperature"`) {
		t.Errorf("gpt-5 request must NOT contain temperature, got %s", s)
	}
}

func TestBuildChatRequest_LegacyModelUsesMaxTokens(t *testing.T) {
	c := NewClient(&config.Config{LLM: "openai/gpt-4o", APIKey: "k", MaxOutputTokens: 4096})
	req := c.buildChatRequest("gpt-4o", []Message{{Role: "user", Content: "hi"}},
		"https://api.openai.com/v1/chat/completions", false)
	body, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	s := string(body)
	if !strings.Contains(s, `"max_tokens":4096`) {
		t.Errorf("expected max_tokens:4096, got %s", s)
	}
	if strings.Contains(s, `"max_completion_tokens"`) {
		t.Errorf("legacy model request must NOT contain max_completion_tokens, got %s", s)
	}
}
