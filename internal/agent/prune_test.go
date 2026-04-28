package agent

import (
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/llm"
)

// TestAlignPruneCutoff exercises the regression case the review flagged:
// pruneMessages used to slice at an arbitrary index, which could land in
// the middle of an assistant→tool-result pair. Some providers (Anthropic
// in particular) reject the resulting message list with a 400. The
// alignment helper advances the cutoff to the next assistant message so
// the synthetic continuation user message slots in cleanly.
func TestAlignPruneCutoff(t *testing.T) {
	mk := func(roles ...string) []llm.Message {
		out := make([]llm.Message, len(roles))
		for i, r := range roles {
			out[i] = llm.Message{Role: r, Content: r}
		}
		return out
	}

	t.Run("already on assistant boundary", func(t *testing.T) {
		msgs := mk("system", "user", "assistant", "user", "assistant", "user")
		// Caller wants to keep messages[3:]. Index 3 is "user" — advance.
		got := alignPruneCutoff(msgs, 3)
		if got != 4 {
			t.Errorf("cutoff = %d, want 4 (assistant)", got)
		}
	})

	t.Run("cutoff lands inside tool_result run", func(t *testing.T) {
		// system, user, asst, tool_result, asst, user, asst, user
		msgs := mk("system", "user", "assistant", "tool", "assistant", "user", "assistant", "user")
		// Caller picked 3 (tool_result) — advance to next assistant at 4.
		got := alignPruneCutoff(msgs, 3)
		if got != 4 {
			t.Errorf("cutoff = %d, want 4", got)
		}
	})

	t.Run("cutoff already on assistant", func(t *testing.T) {
		msgs := mk("system", "user", "assistant", "user", "assistant")
		got := alignPruneCutoff(msgs, 4)
		if got != 4 {
			t.Errorf("cutoff = %d, want 4 (no advance needed)", got)
		}
	})

	t.Run("no assistant after start - fallback to last", func(t *testing.T) {
		msgs := mk("system", "assistant", "user", "tool", "user")
		// Start at 2 — only "user"/"tool"/"user" remain. Should fall back
		// to the last index (4), not run off the end.
		got := alignPruneCutoff(msgs, 2)
		if got != 4 {
			t.Errorf("cutoff = %d, want 4 (last-message fallback)", got)
		}
	})

	t.Run("start clamped to 1 (never below system prompt)", func(t *testing.T) {
		msgs := mk("system", "user", "assistant", "user")
		got := alignPruneCutoff(msgs, 0)
		// Start clamps to 1, then advances past "user" at 1 to "assistant" at 2.
		if got != 2 {
			t.Errorf("cutoff = %d, want 2", got)
		}
	})

	t.Run("only system+user — degenerate", func(t *testing.T) {
		msgs := mk("system", "user")
		got := alignPruneCutoff(msgs, 1)
		// No assistant at all → fallback to last index = 1.
		if got != 1 {
			t.Errorf("cutoff = %d, want 1", got)
		}
	})
}
