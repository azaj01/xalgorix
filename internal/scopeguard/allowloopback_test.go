package scopeguard

import "testing"

// TestAllowLoopbackPorts covers the per-scan provisioned-target exception used
// by "provision" code scans (Option 2). A loopback host on an explicitly
// allowlisted port is NOT classified as self; everything else — including the
// dashboard listener port and non-allowlisted loopback ports — stays blocked.
func TestAllowLoopbackPorts(t *testing.T) {
	const dashboardPort = 9137
	const provisionPort = 3000

	base := Config{BindAddr: "127.0.0.1", Port: dashboardPort}
	allow := Config{BindAddr: "127.0.0.1", Port: dashboardPort, AllowLoopbackPorts: []int{provisionPort}}

	cases := []struct {
		name        string
		cfg         Config
		target      string
		wantBlocked bool
	}{
		// Without an allowlist, loopback is always self.
		{"loopback no allowlist", base, "http://127.0.0.1:3000/", true},
		{"localhost no allowlist", base, "http://localhost:3000/", true},

		// With the allowlist, the exact provisioned loopback port is allowed.
		{"allowed 127.0.0.1 port", allow, "http://127.0.0.1:3000/", false},
		{"allowed localhost port", allow, "http://localhost:3000/", false},
		{"allowed ipv6 loopback port", allow, "http://[::1]:3000/", false},

		// A different loopback port is still blocked even with an allowlist.
		{"other loopback port blocked", allow, "http://127.0.0.1:5000/", true},

		// The dashboard's own port is NEVER allowed, even if the target port
		// matches an (accidental) allowlist entry equal to the listener.
		{"dashboard port never allowed", Config{BindAddr: "127.0.0.1", Port: dashboardPort, AllowLoopbackPorts: []int{dashboardPort}}, "http://127.0.0.1:9137/", true},

		// A loopback target with no port is still self (no port to match).
		{"loopback no port blocked", allow, "http://127.0.0.1/", true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := IsLocalOrListener(tc.cfg, tc.target)
			if got != tc.wantBlocked {
				t.Fatalf("IsLocalOrListener(%q) = %v, want %v", tc.target, got, tc.wantBlocked)
			}
		})
	}
}
