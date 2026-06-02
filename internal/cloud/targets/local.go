package targets

import (
	"net"
	"strings"
)

// loopbackV4 is the canonical 127.0.0.0/8 loopback range. Any IPv4 address
// in this block is considered loopback per RFC 1122 §3.2.1.3.
var loopbackV4 = &net.IPNet{
	IP:   net.IPv4(127, 0, 0, 0),
	Mask: net.CIDRMask(8, 32),
}

// IsLoopback reports whether the given host string refers to a loopback
// address. It returns true for the case-insensitive hostname "localhost",
// for any IPv4 address inside 127.0.0.0/8, and for the IPv6 loopback ::1.
//
// The host argument may be one of:
//   - a bare hostname or IP literal: "localhost", "127.0.0.1", "::1"
//   - a bracketed IPv6 literal: "[::1]"
//   - a host:port pair: "localhost:8080", "127.0.0.1:8080", "[::1]:8080"
//
// The port is stripped before classification using net.SplitHostPort.
// DNS is intentionally not consulted: a hostname like "example.com" that
// happens to resolve to a loopback address at runtime is not treated as
// loopback here, because the verifier short-circuit must be a static,
// syntactic decision that cannot be influenced by a malicious resolver.
//
// Implements the loopback short-circuit branch of Requirement 7.6.
func IsLoopback(host string) bool {
	h := strings.TrimSpace(host)
	if h == "" {
		return false
	}

	// Strip a trailing :port if present. SplitHostPort handles both
	// "host:port" and the bracketed "[ipv6]:port" form.
	if hh, _, err := net.SplitHostPort(h); err == nil {
		h = hh
	} else if len(h) >= 2 && h[0] == '[' && h[len(h)-1] == ']' {
		// Bare bracketed IPv6 literal with no port, e.g. "[::1]".
		h = h[1 : len(h)-1]
	}

	if strings.EqualFold(h, "localhost") {
		return true
	}

	ip := net.ParseIP(h)
	if ip == nil {
		return false
	}
	if v4 := ip.To4(); v4 != nil {
		return loopbackV4.Contains(v4)
	}
	return ip.Equal(net.IPv6loopback)
}

// VerificationStatusVerifiedLocal is the status assigned to targets whose
// hostname is a loopback address, per Requirement 7.6.
const VerificationStatusVerifiedLocal = "verified_local"

// VerificationStatusUnverified is the default status for targets that
// require an external ownership check (DNS TXT, file, or meta tag).
const VerificationStatusUnverified = "unverified"

// ClassifyVerification returns the initial verification status for a
// target host. Loopback hostnames receive "verified_local" and skip the
// external ownership check; every other host starts as "unverified" and
// must be promoted by one of the verifier dispatchers in tasks 7.2–7.4.
//
// Implements Requirement 7.6.
func ClassifyVerification(host string) string {
	if IsLoopback(host) {
		return VerificationStatusVerifiedLocal
	}
	return VerificationStatusUnverified
}
