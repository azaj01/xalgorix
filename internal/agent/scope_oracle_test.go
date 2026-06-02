package agent

// Updated oracle snapshot of the agent-side scope guard matching the
// scope-guard-local-only rewrite. The names here are intentionally
// unexported and prefixed with `oracle` so they cannot be confused
// with the production symbols. The oracle is an INDEPENDENT
// reimplementation of the post-fix rule (not a call into production)
// so the preservation property tests compare two separate code paths.
//
// Post-fix rule (mirrors scopeguard.IsLocalOrListener): a Gated_Tool
// call is blocked only when one of its argument hosts is a
// Local_Or_Listener_Host — loopback, unspecified, the operator's
// configured listener, or an IP literal that matches one of this
// machine's interface addresses. RFC1918, link-local (including the
// 169.254.169.254 cloud-metadata address), and arbitrary public OOS
// hostnames are NOT blocked — those are legitimate scan targets.
//
// DNS semantics: like the pre-fix oracle, this oracle performs NO DNS
// resolution itself. It classifies IP literals and textual locals
// only; any host that would require resolution is treated as
// not-local (allow). Production resolves hostnames via
// scopeguard.LookupHost, but no preservation row exercises a public
// hostname that secretly resolves to a local address, so the two
// paths agree across the whole preservation matrix. The
// oracleLookupHost var is retained purely so the DNS-lookup-count
// sub-property can wrap it and assert it is never called.
//
// Captured tokenizer helpers (still byte-faithful to production):
//   - extractHostsFromArgs            → oracleExtractHostsFromArgs
//   - extractHostFromTokenForScope    → oracleExtractHostFromTokenForScope
//   - looksLikeFilename               → oracleLooksLikeFilename
//   - isVersionLike                   → oracleIsVersionLike
//   - scopeHostTokenSplit             → oracleScopeHostTokenSplit
//   - scopeTokenSeparator             → oracleScopeTokenSeparator
//   - extractEmbeddedURLs             → oracleExtractEmbeddedURLs
//   - argScanLimitBytes               → oracleArgScanLimitBytes
//   - truncateForScopeScan            → oracleTruncateForScopeScan

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/xalgord/xalgorix/v4/internal/scopeguard"
)

// oracleLookupHost is the agent oracle's resolver indirection. The
// oracle does not perform DNS itself; the variable is declared so
// preservation tests can wrap it with a counter when exercising the
// DNS-lookup-count sub-property without touching production code.
var oracleLookupHost = net.LookupHost

const oracleArgScanLimitBytes = 8192

// oracleShouldBlockForOutOfScope is the independent post-fix copy of
// (*Agent).shouldBlockForOutOfScope. It accepts a non-nil *Agent so
// the test surface mirrors the production call site (a.activityHosts
// and a.localGuard are read directly).
//
// The empty-scope short-circuit is retained deliberately: it pins the
// Requirement 3.7 asymmetry exercised by the preservation matrix
// (oracle allows on empty-scope-+-Local; production blocks). Every
// non-empty-scope row is compared strictly against production.
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
	for _, h := range hosts {
		if oracleIsLocalOrListener(a.localGuard, h) {
			return true, fmt.Sprintf(
				"%q points at the operator's machine or local network. "+
					"Refusing to probe localhost / RFC1918 / the dashboard's "+
					"listener from a Gated_Tool.", h,
			)
		}
	}

	if lowerTool == "report_vulnerability" {
		rawTarget := strings.TrimSpace(toolArgs["target"])
		rawEndpoint := strings.TrimSpace(toolArgs["endpoint"])
		for _, raw := range []string{rawTarget, rawEndpoint} {
			if raw == "" {
				continue
			}
			if oracleIsLocalOrListener(a.localGuard, raw) {
				return true, fmt.Sprintf(
					"report_vulnerability target/endpoint %q points at the operator's machine or local network. "+
						"Refusing to probe localhost / RFC1918 / the dashboard's "+
						"listener from a Gated_Tool.", raw,
				)
			}
		}
	}

	return false, ""
}

// oracleIsLocalOrListener is the oracle's DNS-free reimplementation of
// scopeguard.IsLocalOrListener. It blocks only provable self-references
// expressible without DNS: textual loopback/unspecified, the
// configured listener bind:port, and IP literals that are
// loopback/unspecified or match a local interface. Anything requiring
// name resolution (and every RFC1918/link-local/public host) is
// treated as not-local.
func oracleIsLocalOrListener(cfg scopeguard.Config, target string) bool {
	host := target
	hostPort := ""
	if u, err := url.Parse(target); err == nil && u.Host != "" {
		host = u.Hostname()
		hostPort = u.Port()
	}
	if h, p, err := net.SplitHostPort(host); err == nil {
		host = h
		if hostPort == "" {
			hostPort = p
		}
	}

	if hostPort != "" {
		if portNum, err := strconv.Atoi(hostPort); err == nil && portNum == cfg.Port {
			bind := strings.ToLower(strings.TrimSpace(cfg.BindAddr))
			if bind == "" {
				bind = "127.0.0.1"
			}
			lowerHost := strings.ToLower(strings.TrimSpace(host))
			if lowerHost == bind || lowerHost == "0.0.0.0" || lowerHost == "::" {
				return true
			}
		}
	}

	lower := strings.ToLower(host)
	if lower == "localhost" || lower == "0.0.0.0" || lower == "[::1]" || lower == "::1" {
		return true
	}

	// IP literals only — the oracle performs no DNS.
	ip := net.ParseIP(host)
	if ip == nil {
		if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
			ip = net.ParseIP(host[1 : len(host)-1])
		}
	}
	if ip == nil {
		return false
	}
	if ip.IsLoopback() || ip.IsUnspecified() {
		return true
	}
	return oracleIPsMatchLocalInterface([]net.IP{ip})
}

// oracleIPsMatchLocalInterface mirrors scopeguard.ipsMatchLocalInterface:
// it returns true if any supplied IP equals one of this machine's
// interface addresses. No DNS is performed.
func oracleIPsMatchLocalInterface(ips []net.IP) bool {
	if len(ips) == 0 {
		return false
	}
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return false
	}
	for _, ip := range ips {
		if ip == nil {
			continue
		}
		for _, a := range addrs {
			var aIP net.IP
			switch v := a.(type) {
			case *net.IPNet:
				aIP = v.IP
			case *net.IPAddr:
				aIP = v.IP
			}
			if aIP != nil && aIP.Equal(ip) {
				return true
			}
		}
	}
	return false
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
		if r != '.' && (r < '0' || r > '9') {
			return false
		}
	}
	return strings.Contains(s, ".")
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
