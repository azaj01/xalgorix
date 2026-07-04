package agent

import (
	"fmt"
	"log"
	"strings"

	"github.com/xalgord/xalgorix/v4/internal/llm"
	"github.com/xalgord/xalgorix/v4/internal/tools"
	"github.com/xalgord/xalgorix/v4/internal/tools/notes"
)

// formatToolResult formats tool execution results with helpful suggestions
func formatToolResult(toolName string, result tools.Result) string {
	output := result.Output
	errorMsg := result.Error

	var msg string
	if errorMsg != "" {
		msg = fmt.Sprintf("Tool '%s' error: %s\n", toolName, errorMsg)
		msg += getToolSuggestion(toolName, errorMsg)
	} else if output != "" {
		msg = fmt.Sprintf("Tool '%s' result:\n%s", toolName, output)
	} else {
		msg = fmt.Sprintf("Tool '%s' completed successfully (no output)", toolName)
	}

	return msg
}

// getToolSuggestion provides helpful suggestions when a tool fails
func getToolSuggestion(toolName, errorMsg string) string {
	lower := strings.ToLower(errorMsg)

	switch {
	case strings.Contains(toolName, "terminal") || strings.Contains(toolName, "browser"):
		if strings.Contains(lower, "not found") || strings.Contains(lower, "no such file") {
			return "Suggestion: The command or tool was not found. Try using a different approach or check if the tool is installed.\n"
		}
		if strings.Contains(lower, "permission denied") || strings.Contains(lower, "access denied") {
			return "Suggestion: Permission denied. Try running with elevated privileges or use a different method.\n"
		}
		if strings.Contains(lower, "cancel") {
			return "Suggestion: Command was canceled. The agent may have been stopped or the command was taking too long.\n"
		}
		if strings.Contains(lower, "connection") || strings.Contains(lower, "network") {
			return "Suggestion: Network error. Check the target URL and try again.\n"
		}

	case strings.Contains(toolName, "python"):
		if strings.Contains(lower, "no module") || strings.Contains(lower, "import error") {
			return "Suggestion: Missing Python module. Try installing the required package or use an alternative approach.\n"
		}
		if strings.Contains(lower, "syntax") {
			return "Suggestion: Python syntax error. Check the script for errors.\n"
		}

	case strings.Contains(toolName, "browser"):
		if strings.Contains(lower, "chrome") || strings.Contains(lower, "chromium") {
			return "Suggestion: Browser automation issue. Try using send_request instead for HTTP interactions.\n"
		}

	case strings.Contains(toolName, "proxy"):
		if strings.Contains(lower, "connection refused") {
			return "Suggestion: Proxy connection failed. Make sure Caido is running or use direct HTTP requests.\n"
		}
	}

	return ""
}

// pruneMessages trims the message history to prevent context window overflow.
// Strategy: keep system prompt (msg[0]), keep last N messages, and re-inject
// all saved notes so the agent retains accumulated knowledge.
// alignPruneCutoff returns an index >= start such that messages[idx:]
// begins with an "assistant" message (or, if no assistant message remains
// after start, the last message). pruneMessages inserts a synthetic "user"
// message right before the kept tail; advancing the cutoff to an assistant
// boundary preserves user/assistant alternation, which Anthropic enforces
// strictly. Pure function so it's straightforward to regression-test.
func alignPruneCutoff(messages []llm.Message, start int) int {
	if start < 1 {
		start = 1
	}
	cutoff := start
	for cutoff < len(messages) && messages[cutoff].Role != "assistant" {
		cutoff++
	}
	if cutoff >= len(messages) {
		// No assistant message remains after `start`. Keep at least the
		// last message rather than pruning everything below the system
		// prompt.
		cutoff = len(messages) - 1
		if cutoff < 1 {
			cutoff = 1
		}
	}
	return cutoff
}

// pruneThresholdBytes is the serialized message-buffer ceiling used by
// shouldPruneBeforeLLM. ~800 KiB ≈ ~200K tokens at ~4 bytes per token,
// safely below the smallest provider context window we target while
// leaving headroom for the system prompt + a multi-turn tool dialog.
const pruneThresholdBytes = 800 * 1024

// perMessageOverheadBytes accounts for role tags, JSON delimiters, and
// per-message structural overhead added by the provider serializer that
// is not visible in Message.Content alone.
const perMessageOverheadBytes = 50

// shouldPruneBeforeLLM reports whether the agent's current message buffer
// would serialize larger than pruneThresholdBytes and therefore should be
// pruned before the next outbound LLM call. Cheap byte-count heuristic:
// no tokenizer dependency and no allocations beyond the message slice.
//
// Implements Requirement 2.3 (bounded message history before LLM calls)
// and underwrites Property P2.3.
func (a *Agent) shouldPruneBeforeLLM() bool {
	a.msgMu.Lock()
	defer a.msgMu.Unlock()

	size := 0
	for i := range a.messages {
		size += len(a.messages[i].Content) + perMessageOverheadBytes
		if size > pruneThresholdBytes {
			return true
		}
	}
	return false
}

func (a *Agent) pruneMessages() {
	a.msgMu.Lock()
	defer a.msgMu.Unlock()

	const maxMessages = 100

	if len(a.messages) <= maxMessages {
		return
	}

	// Keep system prompt (index 0) + the most recent keepRecent messages
	keepRecent := 60
	if keepRecent > len(a.messages)-1 {
		keepRecent = len(a.messages) - 1
	}

	originalLen := len(a.messages)

	// Build pruned list: system prompt + compacted history + recent messages
	cutoff := alignPruneCutoff(a.messages, len(a.messages)-keepRecent)

	// Compact the pruned messages into a structured digest
	digest := compactMessages(a.messages[1:cutoff]) // skip system prompt

	pruned := make([]llm.Message, 0, len(a.messages)-cutoff+2)
	pruned = append(pruned, a.messages[0]) // system prompt

	// Build continuation message with compacted history + notes
	notesContext := notes.FormatForContextID(a.scanCtx.ID)
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("[CONTEXT PRUNED: %d older messages were compacted to save context space.]\n\n", cutoff-1))
	sb.WriteString("## Compacted History\n")
	sb.WriteString(digest)
	if notesContext != "" {
		sb.WriteString("\n\n## Your Saved Notes\n")
		sb.WriteString(notesContext)
	}
	sb.WriteString("\n\nYou are still in the MIDDLE of your scan. DO NOT call finish — continue testing from where you left off.")

	pruned = append(pruned, llm.Message{
		Role:    "user",
		Content: sb.String(),
	})

	// Keep recent messages intact
	pruned = append(pruned, a.messages[cutoff:]...)
	a.messages = pruned

	log.Printf("[agent] Pruned message history: kept %d messages (was %d), compacted %d messages into digest, notes injected: %v",
		len(a.messages), originalLen, cutoff-1, notesContext != "")
}

// forcePruneMessages aggressively trims the conversation to recover from
// context window overflow. Instead of silently dropping old messages, it
// compacts them into a structured digest that preserves the agent's working
// memory (tools run, findings, endpoints tested).
func (a *Agent) forcePruneMessages() {
	a.msgMu.Lock()
	defer a.msgMu.Unlock()

	if len(a.messages) <= 3 {
		// Nothing meaningful to prune — truncate the system prompt if huge
		if len(a.messages) > 0 && len(a.messages[0].Content) > 8000 {
			a.messages[0].Content = a.messages[0].Content[:8000] + "\n\n[SYSTEM PROMPT TRUNCATED TO FIT CONTEXT WINDOW]"
			log.Printf("[agent] Force-pruned: truncated oversized system prompt")
		}
		return
	}

	originalLen := len(a.messages)

	// Aggressive: keep system prompt + last 20 messages (or fewer if small)
	keepRecent := 20
	if keepRecent > len(a.messages)-1 {
		keepRecent = len(a.messages) - 1
	}

	cutoff := alignPruneCutoff(a.messages, len(a.messages)-keepRecent)

	// ── Compact the pruned messages into a structured digest ──
	digest := compactMessages(a.messages[1:cutoff]) // skip system prompt

	pruned := make([]llm.Message, 0, keepRecent+2)
	pruned = append(pruned, a.messages[0]) // system prompt

	// Build continuation with compacted history + saved notes
	notesContext := notes.FormatForContextID(a.scanCtx.ID)
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("[CONTEXT COMPACTED: %d older messages were summarized to fit context window.]\n\n", cutoff-1))
	sb.WriteString("## Compacted History\n")
	sb.WriteString(digest)
	if notesContext != "" {
		sb.WriteString("\n\n## Your Saved Notes\n")
		sb.WriteString(notesContext)
	}
	sb.WriteString("\n\nYou are still in the MIDDLE of your scan. DO NOT call finish — continue testing from where you left off.")

	pruned = append(pruned, llm.Message{Role: "user", Content: sb.String()})

	// Keep recent messages, but truncate any that are excessively long
	const maxMsgLen = 12000 // ~3K tokens per message max
	for _, msg := range a.messages[cutoff:] {
		if len(msg.Content) > maxMsgLen {
			msg.Content = msg.Content[:maxMsgLen] + "\n\n[OUTPUT TRUNCATED TO FIT CONTEXT WINDOW]"
		}
		pruned = append(pruned, msg)
	}

	a.messages = pruned
	log.Printf("[agent] Force-pruned message history: kept %d messages (was %d), compacted %d messages into digest, notes injected: %v",
		len(a.messages), originalLen, cutoff-1, notesContext != "")
}

// compactMessages extracts a structured digest from a slice of messages.
// Parses tool calls/results, findings, and endpoints to preserve the agent's
// working memory without consuming excessive tokens.
func compactMessages(msgs []llm.Message) string {
	var sb strings.Builder
	toolsRun := make(map[string]int)   // tool_name -> count
	endpoints := make(map[string]bool) // unique endpoints/URLs seen
	var findings []string              // key findings extracted
	var errors []string                // errors encountered

	for _, msg := range msgs {
		content := msg.Content

		// Extract tool calls and counts
		if msg.Role == "assistant" {
			// Count tool call patterns: <function=tool_name>
			for _, line := range strings.Split(content, "\n") {
				if strings.HasPrefix(strings.TrimSpace(line), "<function=") {
					name := strings.TrimPrefix(strings.TrimSpace(line), "<function=")
					name = strings.TrimSuffix(name, ">")
					if name != "" {
						toolsRun[name]++
					}
				}
			}
		}

		// Extract tool results with findings
		if msg.Role == "user" {
			// Look for vulnerability/finding indicators in tool results
			lower := strings.ToLower(content)
			if strings.Contains(lower, "vulnerability") || strings.Contains(lower, "injection") ||
				strings.Contains(lower, "xss") || strings.Contains(lower, "sqli") ||
				strings.Contains(lower, "rce") || strings.Contains(lower, "ssrf") ||
				strings.Contains(lower, "idor") || strings.Contains(lower, "bypass") ||
				strings.Contains(lower, "leak") || strings.Contains(lower, "exposed") {
				// Extract first meaningful line as finding summary
				for _, line := range strings.Split(content, "\n") {
					line = strings.TrimSpace(line)
					if len(line) > 20 && len(line) < 200 {
						findings = append(findings, line)
						break
					}
				}
			}

			// Extract error patterns
			if strings.Contains(content, "error:") || strings.Contains(content, "Error:") {
				for _, line := range strings.Split(content, "\n") {
					if strings.Contains(line, "error") || strings.Contains(line, "Error") {
						line = strings.TrimSpace(line)
						if len(line) > 10 && len(line) < 150 {
							errors = append(errors, line)
							break
						}
					}
				}
			}
		}

		// Extract URLs/endpoints from any message
		for _, word := range strings.Fields(content) {
			if (strings.HasPrefix(word, "http://") || strings.HasPrefix(word, "https://")) && len(word) < 200 {
				// Clean trailing punctuation
				word = strings.TrimRight(word, ".,;:)\"'`")
				endpoints[word] = true
			}
		}
	}

	// Format the digest
	if len(toolsRun) > 0 {
		sb.WriteString("### Tools Executed\n")
		for tool, count := range toolsRun {
			sb.WriteString(fmt.Sprintf("- %s (×%d)\n", tool, count))
		}
	}

	if len(endpoints) > 0 {
		sb.WriteString("\n### Endpoints Tested\n")
		count := 0
		for ep := range endpoints {
			if count >= 30 { // cap to avoid bloat
				sb.WriteString(fmt.Sprintf("- ... and %d more\n", len(endpoints)-30))
				break
			}
			sb.WriteString(fmt.Sprintf("- %s\n", ep))
			count++
		}
	}

	if len(findings) > 0 {
		sb.WriteString("\n### Key Findings\n")
		seen := make(map[string]bool)
		for _, f := range findings {
			if !seen[f] && len(seen) < 15 {
				sb.WriteString(fmt.Sprintf("- %s\n", f))
				seen[f] = true
			}
		}
	}

	if len(errors) > 0 {
		sb.WriteString("\n### Errors Encountered\n")
		seen := make(map[string]bool)
		for _, e := range errors {
			if !seen[e] && len(seen) < 5 {
				sb.WriteString(fmt.Sprintf("- %s\n", e))
				seen[e] = true
			}
		}
	}

	if sb.Len() == 0 {
		sb.WriteString("(No structured data could be extracted from pruned messages)\n")
	}

	return sb.String()
}
