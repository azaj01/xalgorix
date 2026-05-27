package web

// Frozen oracle snapshot of the web-side scope guard
// (isBlockedTarget) as it exists before the
// scope-guard-local-only fix. The names here are intentionally
// unexported and prefixed with `oracle` so they cannot be confused
// with the production symbols. The bodies below MUST remain
// byte-frozen for the duration of the spec — they are the pre-fix
// `F` against which the post-fix `F'` is compared in preservation
// property tests (task 2 of the scope-guard-local-only spec).
//
// Captured from internal/web/server.go as of the unfixed baseline:
//   - (*Server).isBlockedTarget        → oracleIsBlockedTarget
//   - ipsMatchLocalInterface           → oracleIPsMatchLocalInterface
//   - lookupHost                       → oracleLookupHost
//
// Resolver indirection is deliberately oracle-local
// (oracleLookupHost) so when task 3.3 migrates the production
// resolver to scopeguard.LookupHost the oracle keeps reading from
// its own var. Tests inject a stub by overwriting oracleLookupHost
// directly. The oracle reproduces the per-call private-CIDR parse
// the unfixed implementation does — that's a structural quirk of
// the baseline `F` and the property tests pin it.

import (
	"net"
	"net/url"
	"strconv"
	"strings"
)

// oracleLookupHost is the web oracle's frozen resolver indirection.
// Tests overwrite this var to feed deterministic resolutions
// without depending on the production package-level lookupHost.
var oracleLookupHost = net.LookupHost

// oracleIsBlockedTarget is the byte-frozen pre-fix copy of
// (*Server).isBlockedTarget. It accepts a non-nil *Server so the
// test surface mirrors the production call site (s.cfg.BindAddr
// and s.port are read directly).
func oracleIsBlockedTarget(s *Server, target string) bool {
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

	portMatch := false
	if s != nil && hostPort != "" {
		if portNum, err := strconv.Atoi(hostPort); err == nil && portNum == s.port {
			portMatch = true
			bind := strings.ToLower(strings.TrimSpace(s.cfg.BindAddr))
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

	var resolvedIPs []net.IP
	if ip := net.ParseIP(host); ip != nil {
		resolvedIPs = []net.IP{ip}
	} else {
		addrs, err := oracleLookupHost(host)
		if err != nil || len(addrs) == 0 {
			return false
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

	if portMatch && oracleIPsMatchLocalInterface(resolvedIPs) {
		return true
	}

	for _, ip := range resolvedIPs {
		if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
			return true
		}
	}

	privateCIDRs := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",
		"169.254.0.0/16",
		"::1/128",
		"fc00::/7",
		"fe80::/10",
	}
	parsedSubnets := make([]*net.IPNet, 0, len(privateCIDRs))
	for _, cidr := range privateCIDRs {
		_, subnet, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		parsedSubnets = append(parsedSubnets, subnet)
	}
	for _, ip := range resolvedIPs {
		for _, subnet := range parsedSubnets {
			if subnet.Contains(ip) {
				return true
			}
		}
	}
	return false
}

// oracleIPsMatchLocalInterface mirrors the byte-frozen pre-fix
// copy of ipsMatchLocalInterface. Walks net.InterfaceAddrs once
// and checks ips × addrs.
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
