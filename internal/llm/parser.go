// Package llm provides LLM client and tool call parsing.
package llm

import (
	"html"
	"regexp"
	"strings"
	"unicode"
)

// ToolCall represents a parsed tool invocation from LLM output.
type ToolCall struct {
	Name string            `json:"name"`
	Args map[string]string `json:"args"`
}

var (
	// Function matching — dotall for multi-line bodies
	fnRegex = regexp.MustCompile(`(?s)<function=([^>]+)>\n?(.*?)</function>`)

	// All parameter formats we need to handle — ALL dotall for multi-line values:
	// 1. Standard: <parameter=name>value</parameter>
	paramEqRegex = regexp.MustCompile(`(?s)<parameter=([^>]+)>(.*?)</parameter>`)
	// 2. Space variant: <parameter name>value</parameter>  (MiniMax)
	paramSpRegex = regexp.MustCompile(`(?s)<parameter\s+([^=>]+)>(.*?)</parameter>`)
	// 3. name= attr: <parameter name="X">value</parameter>
	paramAttrRegex = regexp.MustCompile(`(?s)<parameter\s+name=["']([^"']+)["']>(.*?)</parameter>`)

	// Alternate top-level format: <invoke name="X">...</invoke>
	invokeOpen   = regexp.MustCompile(`<invoke\s+name=["']([^"']+)["']>`)
	funcCallsTag = regexp.MustCompile(`</?function_calls>`)

	// Recover malformed tool-call OPEN tags. Some models intermittently mangle
	// the opening tag while still emitting a well-formed body and "</function>".
	// Observed variants (all counted as "no tool call" by the strict fnRegex):
	//     function=terminal_execute><parameter=command>id</parameter></function>   (no leading "<")
	//     =send_request><parameter=method>GET</parameter></function>               (no "<function")
	//     function=terminal_execute"><parameter=command>id</parameter></function>  (stray quote before ">")
	//     <function="terminal_execute"><parameter=...>                             (quoted name)
	// 15 such responses in a row force-stops the whole scan (observed in
	// production against bitbank.cc). This repair rebuilds the canonical
	// "<function=name>" form, tolerating an optional leading "<"/"<function",
	// optional surrounding quotes, and stray quotes/whitespace before the ">".
	// Requiring a "<parameter" or "</function>" immediately after makes it a
	// specific, low-false-positive signal (ordinary prose has no
	// "=word><parameter"), and correct "<function=name>" tags rewrite to the
	// identical form, so it is idempotent.
	repairFnOpenRe = regexp.MustCompile(`(?s)<?(?:function)?\s*=\s*["']?([A-Za-z_][A-Za-z0-9_-]*)["'\s]*>(\s*(?:<parameter|</function>))`)

	// Normalize quotes around = in tags: <function = "name"> → <function=name>
	stripQuotesRe = regexp.MustCompile(`<(function|parameter)\s*=\s*["']?([^>"']+?)["']?\s*>`)

	// CleanContent regexes — compiled once
	toolPattern    = regexp.MustCompile(`(?s)<function=[^>]+>.*?</function>`)
	incompleteFunc = regexp.MustCompile(`(?s)<function=[^>]+>.*$`)
	interAgentRe   = regexp.MustCompile(`(?is)<inter_agent_message>.*?</inter_agent_message>`)
	agentReportRe  = regexp.MustCompile(`(?is)<agent_completion_report>.*?</agent_completion_report>`)
	multiBlankRe   = regexp.MustCompile(`\n\s*\n`)

	// Strategy 2 lenient param matching (fallback)
	lenientParamRe = regexp.MustCompile(`(?s)<parameter[^>]*?(\w+)\s*>(.*?)</parameter>`)
	// Split identifier on punctuation/whitespace
	identSplitRe = regexp.MustCompile(`[.\s,;:!?]+`)
)

// ParseToolCalls extracts tool calls from LLM XML output.
func ParseToolCalls(content string) []ToolCall {
	content = normalizeFormat(content)
	content = fixIncomplete(content)

	var calls []ToolCall

	for _, match := range fnRegex.FindAllStringSubmatch(content, -1) {
		fnName := sanitizeParamName(strings.TrimSpace(match[1]))
		if fnName == "" {
			continue
		}

		body := match[2]
		args := extractParams(body)

		calls = append(calls, ToolCall{Name: fnName, Args: args})
	}

	return calls
}

// extractParams tries all known parameter formats to extract key-value pairs.
// Falls back to progressively more lenient parsing strategies.
func extractParams(body string) map[string]string {
	args := make(map[string]string)

	// Strategy 1: Try exact formats in priority order
	regexes := []*regexp.Regexp{paramEqRegex, paramAttrRegex, paramSpRegex}

	for _, re := range regexes {
		matches := re.FindAllStringSubmatch(body, -1)
		if len(matches) > 0 {
			for _, pm := range matches {
				pName := sanitizeParamName(pm[1])
				if pName == "" {
					continue
				}
				args[pName] = html.UnescapeString(strings.TrimSpace(pm[2]))
			}
			if len(args) > 0 {
				return args
			}
		}
	}

	// Strategy 2: Ultra-lenient — match anything that looks like <parameter...>...</parameter>
	// Catches: <parameter = command>, <parameter  command >, etc.
	for _, pm := range lenientParamRe.FindAllStringSubmatch(body, -1) {
		pName := sanitizeParamName(pm[1])
		if pName != "" {
			args[pName] = html.UnescapeString(strings.TrimSpace(pm[2]))
		}
	}
	if len(args) > 0 {
		return args
	}

	// Strategy 3: No parameter tags at all — treat raw body as single value.
	// Use the first word-like chunk after "=" or the trimmed body.
	trimmed := strings.TrimSpace(body)
	if trimmed != "" && !strings.Contains(trimmed, "<") {
		// Single unnamed param — callers (registry) can map it to the first required param
		args["_raw"] = trimmed
	}

	return args
}

// sanitizeParamName extracts a valid identifier from a potentially garbled name.
func sanitizeParamName(raw string) string {
	raw = strings.TrimSpace(raw)
	if isIdentifier(raw) {
		return raw
	}

	parts := identSplitRe.Split(raw, -1)
	for i := len(parts) - 1; i >= 0; i-- {
		p := strings.TrimSpace(parts[i])
		if isIdentifier(p) {
			return p
		}
	}
	return ""
}

func isIdentifier(s string) bool {
	if s == "" {
		return false
	}
	for i, r := range s {
		if i == 0 && !unicode.IsLetter(r) && r != '_' {
			return false
		}
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '_' {
			return false
		}
	}
	return true
}

// normalizeFormat converts alternative XML formats to the expected one.
func normalizeFormat(content string) string {
	// Handle <invoke name="X"> ... </invoke> format
	if strings.Contains(content, "<invoke") || strings.Contains(content, "<function_calls") {
		content = funcCallsTag.ReplaceAllString(content, "")
		content = invokeOpen.ReplaceAllString(content, "<function=$1>")
		content = strings.ReplaceAll(content, "</invoke>", "</function>")
	}

	// Repair malformed function-open tags (missing leading "<" / "<function").
	content = repairFnOpenRe.ReplaceAllString(content, "<function=${1}>${2}")

	// Normalize quotes/spaces around = signs: <function = "name"> → <function=name>
	content = stripQuotesRe.ReplaceAllStringFunc(content, func(s string) string {
		m := stripQuotesRe.FindStringSubmatch(s)
		if len(m) < 3 {
			return s
		}
		val := strings.TrimSpace(m[2])
		return "<" + m[1] + "=" + val + ">"
	})

	return content
}

// fixIncomplete adds a missing closing tag to the last unclosed tool-call
// block in content. Earlier blocks are matched normally by the regex; only
// the trailing one (the most common LLM truncation) is repaired here.
func fixIncomplete(content string) string {
	countOpen := strings.Count(content, "<function=") + strings.Count(content, "<invoke ")
	countClose := strings.Count(content, "</function>") + strings.Count(content, "</invoke>")

	if countOpen <= countClose {
		return content
	}

	// At least one open tag has no matching close. Append a single closing
	// tag — even if multiple tags are unclosed, the regex is non-greedy and
	// will pick up the well-formed pairs first.
	content = strings.TrimRight(content, " \t\n\r")
	if strings.HasSuffix(content, "</") {
		return content + "function>"
	}
	return content + "\n</function>"
}

// FormatToolCall formats a tool call back into XML for display.
func FormatToolCall(name string, args map[string]string) string {
	var b strings.Builder
	b.WriteString("<function=")
	b.WriteString(name)
	b.WriteString(">\n")
	for k, v := range args {
		b.WriteString("<parameter=")
		b.WriteString(k)
		b.WriteString(">")
		b.WriteString(v)
		b.WriteString("</parameter>\n")
	}
	b.WriteString("</function>")
	return b.String()
}

// CleanContent removes tool call XML from content for display.
func CleanContent(content string) string {
	content = normalizeFormat(content)
	content = fixIncomplete(content)

	cleaned := toolPattern.ReplaceAllString(content, "")
	cleaned = incompleteFunc.ReplaceAllString(cleaned, "")
	cleaned = interAgentRe.ReplaceAllString(cleaned, "")
	cleaned = agentReportRe.ReplaceAllString(cleaned, "")
	cleaned = multiBlankRe.ReplaceAllString(cleaned, "\n\n")

	return strings.TrimSpace(cleaned)
}
