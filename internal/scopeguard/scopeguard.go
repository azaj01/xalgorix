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
// the operator's listener identity (Config) and a fixed table of
// private/loopback/link-local/ULA CIDRs.
//
// Centralising the classifier here makes Requirement 3.8 of the
// scope-guard-local-only bugfix structurally true: the web guard and
// the agent guard literally call the same function, so the verdict
// for any input is identical by construction.
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

// privateCIDRListLiterals is the source-of-truth list of CIDR
// strings the package classifies as Local_Or_Listener_Host. It is
// kept as a string slice both for documentation and so the unit
// test in scopeguard_test.go can assert that every parsed entry in
// privateCIDRs round-trips back to one of these literals.
var privateCIDRListLiterals = []string{
	"10.0.0.0/8",
	"172.16.0.0/12",
	"192.168.0.0/16",
	"127.0.0.0/8",
	"169.254.0.0/16", // link-local
	"::1/128",
	"fc00::/7",  // IPv6 unique local
	"fe80::/10", // IPv6 link-local
}

// privateCIDRs is the parsed form of privateCIDRListLiterals,
// initialised once in init() so the per-call body of
// IsLocalOrListener doesn't re-parse the same eight strings on
// every invocation. Structural cleanup over the previous
// per-call parse — verdict on every input is identical.
var privateCIDRs []*net.IPNet

func init() {
	privateCIDRs = make([]*net.IPNet, 0, len(privateCIDRListLiterals))
	for _, cidr := range privateCIDRListLiterals {
		_, subnet, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		privateCIDRs = append(privateCIDRs, subnet)
	}
}

// IsLocalOrListener returns true when target — a bare host,
// host:port, scheme://host[:port][/path], or [ipv6][:port] —
// classifies as a Local_Or_Listener_Host: literal loopback /
// link-local / unspecified / RFC1918 IPv4 or IPv6, hostname that
// resolves to a local-interface address or to a private CIDR, or a
// host string equal (case-insensitive) to cfg.BindAddr (default
// "127.0.0.1") or to "0.0.0.0" / "::" when paired with cfg.Port.
//
// Body is the byte-for-byte port of (*Server).isBlockedTarget from
// internal/web/server.go with s.cfg.BindAddr / s.port replaced by
// cfg.BindAddr / cfg.Port and the package-local lookupHost
// indirection replaced by LookupHost.
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

	// Explicit textual matches (fast path)
	lower := strings.ToLower(host)
	if lower == "localhost" || lower == "0.0.0.0" || lower == "[::1]" || lower == "::1" {
		return true
	}

	// Resolve the target host to one or more IPs exactly once for the
	// remainder of this call. IP literals skip DNS entirely; otherwise
	// a single LookupHost feeds every downstream check. An empty or
	// failing resolution falls back to "allow" (matching prior
	// behaviour) so unreachable hostnames are not blocked solely on
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

	// Self-host interface check. Block ANY target whose resolved IP
	// matches one of this machine's network interface addresses —
	// regardless of port. This prevents the agent from probing the
	// operator's own public-facing services (SSH, Grafana, CUPS, etc.)
	// even when the probed port differs from the dashboard listener.
	// Without this unconditional check, the agent can self-scan its
	// host on non-dashboard ports (e.g. :22, :9999) because the
	// public IP is neither private nor loopback.
	if ipsMatchLocalInterface(resolvedIPs) {
		return true
	}

	// Check blocked ranges across the entire resolved set: a single
	// loopback/link-local/unspecified hit is enough to block.
	for _, ip := range resolvedIPs {
		if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
			return true
		}
	}

	// RFC 1918 private ranges and friends — pre-parsed at init().
	for _, ip := range resolvedIPs {
		for _, subnet := range privateCIDRs {
			if subnet.Contains(ip) {
				return true
			}
		}
	}
	return false
}

// ipsMatchLocalInterface returns true if any IP in the supplied
// slice matches one of this machine's interface addresses. Issues a
// single net.InterfaceAddrs call and walks ips × addrs so callers
// can resolve a hostname once and reuse the result for every
// downstream check.
//
// Relocated verbatim from internal/web/server.go as part of the
// scope-guard-local-only spec (task 3.1). The unused
// ipMatchesLocalInterface (no callers in the current tree) is NOT
// relocated — it gets cleaned up incidentally by task 3.2.
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
