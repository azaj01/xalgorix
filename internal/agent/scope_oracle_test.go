package agent

// Frozen oracle snapshot of the agent-side scope guard as it exists
// before the scope-guard-local-only fix. The names here are
// intentionally unexported and prefixed with `oracle` so they cannot
// be confused with the production symbols. The bodies below MUST
// remain byte-frozen for the duration of the spec — they are the
// pre-fix `F` against which the post-fix `F'` is compared in
// preservation property tests (task 2 of the
// scope-guard-local-only spec).
//
// Captured from internal/agent/agent.go as of the unfixed baseline:
//   - shouldBlockForOutOfScope        → oracleShouldBlockForOutOfScope
//   - extractHostsFromArgs            → oracleExtractHostsFromArgs
//   - extractHostFromTokenForScope    → oracleExtractHostFromTokenForScope
//   - hostInScope                     → oracleHostInScope
//   - looksLikeFilename               → oracleLooksLikeFilename
//   - isVersionLike                   → oracleIsVersionLike
//   - scopeHostTokenSplit             → oracleScopeHostTokenSplit
//   - scopeTokenSeparator             → oracleScopeTokenSeparator
//   - extractEmbeddedURLs             → oracleExtractEmbeddedURLs
//   - argScanLimitBytes               → oracleArgScanLimitBytes
//   - truncateForScopeScan            → oracleTruncateForScopeScan
//
// Resolver indirection is deliberately oracle-local
// (oracleLookupHost) so that when task 3.3 swaps the production
// resolver to scopeguard.LookupHost the oracle keeps reading from
// its own var. Tests inject a stub by overwriting oracleLookupHost
// directly. The oracle body never calls oracleLookupHost today —
// the unfixed agent guard does no DNS itself — but the variable is
// declared so the helper test infrastructure can wrap it for the
// DNS-lookup-count sub-property without touching production code.

import (
	"fmt"
	"net"
	"net/url"
	"strings"
	"unicode/utf8"
)

// oracleLookupHost is the agent oracle's frozen resolver indirection.
// The unfixed agent guard does not perform DNS itself (only the
// web-side isBlockedTarget did), but the variable is declared so
// preservation tests can wrap it with a counter when exercising the
// DNS-lookup-count sub-property without touching production code.
var oracleLookupHost = net.LookupHost

const oracleArgScanLimitBytes = 8192

// oracleShouldBlockForOutOfScope is the byte-frozen pre-fix copy of
// (*Agent).shouldBlockForOutOfScope. It accepts a non-nil *Agent so
// the test surface mirrors the production call site (a.activityHosts
// is read directly).
func oracleShouldBlockForOutOfScope(a *Agent, toolName string, toolArgs map[string]string) (bool, string) {
	if len(a.activityHosts) == 0 {
		return false, ""
	}

	lowerTool := strings.ToLower(toolName)
	switch lowerTool {
	case "terminal_execute", "python_action", "browser_action", "page_agent", "pageagent",
		"report_vulnerability":
		// gated
	default:
		return false, ""
	}

	hosts := oracleExtractHostsFromArgs(toolArgs)
	if len(hosts) == 0 {
		return false, ""
	}

	for _, h := range hosts {
		if !oracleHostInScope(h, a.activityHosts) {
			return true, fmt.Sprintf(
				"%q is not in scope. Configured target hosts: %s. Stay on the configured target — do NOT pivot to discovered third-party hosts, related infrastructure, or sibling services. If the agent thinks the host is part of the engagement, it must be added to the scan request, not probed implicitly.",
				h, strings.Join(a.activityHosts, ", "),
			)
		}
	}

	if lowerTool == "report_vulnerability" {
		rawTarget := strings.ToLower(strings.TrimSpace(toolArgs["target"]))
		rawEndpoint := strings.ToLower(strings.TrimSpace(toolArgs["endpoint"]))
		for _, raw := range []string{rawTarget, rawEndpoint} {
			if raw == "" {
				continue
			}
			h := oracleExtractHostFromTokenForScope(raw)
			if h == "" {
				continue
			}
			if !oracleHostInScope(h, a.activityHosts) {
				return true, fmt.Sprintf(
					"report_vulnerability target %q is out of scope. Configured target hosts: %s. Refusing to file a finding against a host the operator did not authorize. Re-target the report to one of the configured hosts, or drop the finding.",
					h, strings.Join(a.activityHosts, ", "),
				)
			}
		}
	}

	return false, ""
}

func oracleExtractHostsFromArgs(toolArgs map[string]string) []string {
	seen := make(map[string]bool)
	var out []string
	for _, raw := range toolArgs {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		raw = oracleTruncateForScopeScan(raw)
		for _, span := range oracleExtractEmbeddedURLs(raw) {
			h := oracleExtractHostFromTokenForScope(span)
			if h == "" || seen[h] {
				continue
			}
			seen[h] = true
			out = append(out, h)
		}
		for _, tok := range oracleScopeHostTokenSplit(raw) {
			h := oracleExtractHostFromTokenForScope(tok)
			if h == "" || seen[h] {
				continue
			}
			seen[h] = true
			out = append(out, h)
		}
	}
	return out
}

func oracleScopeHostTokenSplit(s string) []string {
	return strings.FieldsFunc(s, oracleScopeTokenSeparator)
}

func oracleExtractHostFromTokenForScope(token string) string {
	token = strings.TrimSpace(token)
	if token == "" {
		return ""
	}
	token = strings.Trim(token, ".,;:?!(){}\"'`<>")

	if strings.Contains(token, "://") {
		if u, err := url.Parse(token); err == nil && u.Hostname() != "" {
			return strings.ToLower(u.Hostname())
		}
	}

	if h, _, err := net.SplitHostPort(token); err == nil && h != "" {
		h = strings.TrimPrefix(h, "[")
		h = strings.TrimSuffix(h, "]")
		return strings.ToLower(h)
	}

	if ip := net.ParseIP(token); ip != nil {
		return strings.ToLower(token)
	}
	if strings.HasPrefix(token, "[") && strings.HasSuffix(token, "]") {
		inner := token[1 : len(token)-1]
		if net.ParseIP(inner) != nil {
			return strings.ToLower(inner)
		}
	}
	if strings.Contains(token, ".") && !strings.ContainsAny(token, " /\\") {
		if strings.HasPrefix(token, "./") || strings.HasPrefix(token, "../") || strings.HasPrefix(token, "/") {
			return ""
		}
		if oracleIsVersionLike(token) {
			return ""
		}
		if oracleLooksLikeFilename(token) {
			return ""
		}
		return strings.ToLower(token)
	}
	return ""
}

func oracleLooksLikeFilename(token string) bool {
	idx := strings.LastIndex(token, ".")
	if idx <= 0 || idx == len(token)-1 {
		return false
	}
	ext := strings.ToLower(token[idx+1:])
	switch ext {
	case "txt", "json", "csv", "log", "yaml", "yml", "xml", "html", "htm",
		"md", "sh", "py", "js", "ts", "tsx", "jsx", "go", "rs", "rb",
		"php", "java", "cpp", "tar", "gz", "zip", "tgz",
		"pdf", "png", "jpg", "jpeg", "gif", "svg", "webp", "ico",
		"sql", "db", "sqlite", "pem", "key", "crt", "pcap", "har":
		return true
	}
	return false
}

func oracleIsVersionLike(s string) bool {
	s = strings.TrimPrefix(s, "v")
	if s == "" {
		return false
	}
	for _, r := range s {
		if !(r == '.' || (r >= '0' && r <= '9')) {
			return false
		}
	}
	return strings.Contains(s, ".")
}

func oracleHostInScope(host string, scopeHosts []string) bool {
	host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	if host == "" {
		return true
	}
	for _, s := range scopeHosts {
		s = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(s), "."))
		if s == "" {
			continue
		}
		if host == s {
			return true
		}
		if strings.HasSuffix(host, "."+s) {
			return true
		}
	}
	return false
}

func oracleTruncateForScopeScan(v string) string {
	if len(v) <= oracleArgScanLimitBytes {
		return v
	}
	end := oracleArgScanLimitBytes
	for end > 0 && !utf8.RuneStart(v[end]) {
		end--
	}
	return v[:end]
}

func oracleExtractEmbeddedURLs(s string) []string {
	if s == "" {
		return nil
	}
	var out []string
	n := len(s)
	for i := 0; i < n; {
		prefixLen := 0
		switch {
		case i+7 <= n && strings.EqualFold(s[i:i+7], "http://"):
			prefixLen = 7
		case i+8 <= n && strings.EqualFold(s[i:i+8], "https://"):
			prefixLen = 8
		}
		if prefixLen == 0 {
			i++
			continue
		}
		end := i + prefixLen
	span:
		for end < n {
			r, size := utf8.DecodeRuneInString(s[end:])
			if size == 0 {
				size = 1
			}
			if oracleScopeTokenSeparator(r) {
				break span
			}
			end += size
		}
		out = append(out, s[i:end])
		i = end
	}
	return out
}

func oracleScopeTokenSeparator(r rune) bool {
	switch r {
	case ' ', '\t', '\n', '\r',
		'"', '\'', '`',
		'(', ')', '{', '}', '[', ']',
		',', ';', '|', '&', '<', '>',
		'=', '?', '#', '@':
		return true
	}
	return false
}
