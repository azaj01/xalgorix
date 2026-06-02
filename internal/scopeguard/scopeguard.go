// Package scopeguard owns the authoritative definition of
// "Local_Or_Listener_Host" — the host classification both the web-side
// fetcher (internal/web/server.go) and the agent-side gate
// (internal/agent/agent.go) consult.
//
// The package is intentionally a leaf: it imports nothing from the
// xalgorix tree so the agent can take a dependency on it without
// pulling in the web package. Its single semantic entry point is
// IsLocalOrListener, which classifies a target string (bare host,
// host:port, scheme://host[:port][/path], or [ipv6][:port]) against
// the operator's listener identity (Config) and the machine's actual
// network interfaces.
//
// DESIGN PRINCIPLE: only block IPs that provably belong to the
// operator's own machine. Do NOT blanket-block entire private ranges
// (RFC1918, link-local) — the agent is a security scanner that needs
// to test SSRF payloads like 169.254.169.254 (cloud metadata) and
// internal IPs that belong to the TARGET, not the operator.
//
// What we block:
//   - Loopback addresses (127.0.0.0/8, ::1) — always self
//   - Unspecified addresses (0.0.0.0, ::) — always self
//   - "localhost" hostname — always self
//   - IPs matching any local network interface — the operator's machine
//   - Self-listener textual match (bind addr + port)
//
// What we ALLOW (that the old code incorrectly blocked):
//   - RFC1918 (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16) — unless
//     they match a local interface
//   - Link-local (169.254.0.0/16) including 169.254.169.254 cloud
//     metadata — unless they match a local interface
//   - IPv6 ULA (fc00::/7) and link-local (fe80::/10) — unless they
//     match a local interface
package scopeguard

import (
	"net"
	"net/url"
	"strconv"
	"strings"
)

// Config carries the operator's listener identity. Callers set
// BindAddr to the configured XALGORIX_BIND value and Port to the
// listener port. An empty BindAddr is treated as "127.0.0.1" — the
// same default the web server applies when no bind override is
// provided.
type Config struct {
	BindAddr string
	Port     int
}

// LookupHost is the package-level resolver indirection. Tests
// overwrite this var to feed deterministic resolutions; production
// uses net.LookupHost. Single var, single call site (inside
// IsLocalOrListener), mirroring the per-package lookupHost
// indirection that previously lived in internal/web/server.go.
var LookupHost = net.LookupHost

// IsLocalOrListener returns true when target — a bare host,
// host:port, scheme://host[:port][/path], or [ipv6][:port] —
// classifies as pointing at the operator's own machine.
//
// The check is smart: it only blocks loopback, unspecified, and IPs
// that match one of this machine's network interfaces. It does NOT
// blanket-block RFC1918 or link-local ranges — those are legitimate
// SSRF targets (e.g. 169.254.169.254 cloud metadata, internal IPs
// on the target's network).
func IsLocalOrListener(cfg Config, target string) bool {
	// Strip scheme if present (http://127.0.0.1 → 127.0.0.1)
	host := target
	hostPort := ""
	if u, err := url.Parse(target); err == nil && u.Host != "" {
		host = u.Hostname()
		hostPort = u.Port()
	}
	// Also handle host:port without scheme
	if h, p, err := net.SplitHostPort(host); err == nil {
		host = h
		if hostPort == "" {
			hostPort = p
		}
	}

	// Self-listener textual fast-path. Block if the target's port
	// matches our own listening port AND the host textually matches
	// our bind address (or 0.0.0.0 / ::). This fires before DNS
	// resolution and catches the most common self-probe patterns.
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

	// Explicit textual matches (fast path) — these always mean "self"
	lower := strings.ToLower(host)
	if lower == "localhost" || lower == "0.0.0.0" || lower == "[::1]" || lower == "::1" {
		return true
	}

	// Resolve the target host to one or more IPs exactly once for the
	// remainder of this call. IP literals skip DNS entirely; otherwise
	// a single LookupHost feeds every downstream check. An empty or
	// failing resolution falls back to "allow" (matching prior
	// behavior) so unreachable hostnames are not blocked solely on
	// lookup failure — the request will fail naturally further down.
	var resolvedIPs []net.IP
	if ip := net.ParseIP(host); ip != nil {
		resolvedIPs = []net.IP{ip}
	} else {
		addrs, err := LookupHost(host)
		if err != nil || len(addrs) == 0 {
			return false // can't resolve — let it through, will fail naturally
		}
		for _, a := range addrs {
			if parsed := net.ParseIP(a); parsed != nil {
				resolvedIPs = append(resolvedIPs, parsed)
			}
		}
		if len(resolvedIPs) == 0 {
			return false
		}
	}

	// Check each resolved IP against the operator's own machine.
	// We block ONLY:
	//   1. Loopback (127.x.x.x, ::1) — always the local machine
	//   2. Unspecified (0.0.0.0, ::) — binds to all local interfaces
	//   3. IPs matching a local network interface — the operator's machine
	//
	// Everything else is allowed, including RFC1918, link-local,
	// cloud metadata (169.254.169.254), IPv6 ULA, etc. — these may
	// be legitimate targets on the scanned host's network.
	for _, ip := range resolvedIPs {
		if ip.IsLoopback() || ip.IsUnspecified() {
			return true
		}
	}

	// Self-host interface check. Block ANY target whose resolved IP
	// matches one of this machine's network interface addresses —
	// regardless of port. This prevents the agent from probing the
	// operator's own public-facing services (SSH, Grafana, CUPS, etc.)
	// even when the probed port differs from the dashboard listener.
	if ipsMatchLocalInterface(resolvedIPs) {
		return true
	}

	return false
}

// ipsMatchLocalInterface returns true if any IP in the supplied
// slice matches one of this machine's interface addresses. Issues a
// single net.InterfaceAddrs call and walks ips × addrs so callers
// can resolve a hostname once and reuse the result for every
// downstream check.
func ipsMatchLocalInterface(ips []net.IP) bool {
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
			if aIP == nil {
				continue
			}
			if aIP.Equal(ip) {
				return true
			}
		}
	}
	return false
}
