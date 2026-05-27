package scopeguard

import (
	"errors"
	"net"
	"testing"
)

// withStubLookupHost swaps the package-level LookupHost indirection
// for the duration of a single test. Restoration runs via t.Cleanup
// so every test exits with the original net.LookupHost binding in
// place, regardless of failure or skip. The test functions below
// MUST NOT call t.Parallel() because LookupHost is package-level
// state.
func withStubLookupHost(t *testing.T, stub func(string) ([]string, error)) {
	t.Helper()
	prev := LookupHost
	LookupHost = stub
	t.Cleanup(func() { LookupHost = prev })
}

// TestPrivateCIDRs_MatchesLiterals asserts that the parsed
// privateCIDRs slice round-trips back to the literal source-of-truth
// strings in privateCIDRListLiterals. Pins the structural cleanup
// (move + memoise) — the parsed CIDR set MUST be identical to the
// per-call slice the unfixed isBlockedTarget body parsed.
//
// Validates: Requirement 3.8 (verdict preservation across the
// per-call → init() refactor).
func TestPrivateCIDRs_MatchesLiterals(t *testing.T) {
	if got, want := len(privateCIDRs), len(privateCIDRListLiterals); got != want {
		t.Fatalf("privateCIDRs length = %d, want %d", got, want)
	}
	for i, lit := range privateCIDRListLiterals {
		_, want, err := net.ParseCIDR(lit)
		if err != nil {
			t.Fatalf("source-of-truth literal %q failed to parse: %v", lit, err)
		}
		got := privateCIDRs[i]
		if got.String() != want.String() {
			t.Errorf("privateCIDRs[%d] = %q, want %q (from literal %q)",
				i, got.String(), want.String(), lit)
		}
	}
}

// isLocalOrListenerRow is one row in the table-driven test surface
// for IsLocalOrListener. The rows mirror every cell the web-side
// preservation property (internal/web/server_test.go →
// webPreservationRows) exercises, plus dedicated coverage for the
// self-listener leg, the localhost / [::1] fast-path, the public
// hostname allow, the IP-literal-skips-DNS contract, and the
// DNS-failure-allows fallback.
type isLocalOrListenerRow struct {
	cell           string
	name           string
	cfg            Config
	target         string
	stubLookup     func(string) ([]string, error) // nil = no resolver swap
	wantBlocked    bool
	wantDNSCalls   int  // expected number of LookupHost invocations
	wantDNSCheckOn bool // assert wantDNSCalls when true
}

func isLocalOrListenerRows() []isLocalOrListenerRow {
	const listenerPort = 9000

	cfg := Config{BindAddr: "127.0.0.1", Port: listenerPort}

	return []isLocalOrListenerRow{
		// ── Local_Or_Listener_Host literals ─────────────────────────
		{cell: "local-literal", name: "loopback ipv4", cfg: cfg, target: "http://127.0.0.1/admin", wantBlocked: true, wantDNSCheckOn: true, wantDNSCalls: 0},
		{cell: "local-literal", name: "loopback ipv4 with port", cfg: cfg, target: "http://127.0.0.1:9000/x", wantBlocked: true, wantDNSCheckOn: true, wantDNSCalls: 0},
		{cell: "local-literal", name: "localhost name", cfg: cfg, target: "http://localhost/x", wantBlocked: true, wantDNSCheckOn: true, wantDNSCalls: 0},
		{cell: "local-literal", name: "ipv6 loopback bracket", cfg: cfg, target: "http://[::1]:8080/", wantBlocked: true, wantDNSCheckOn: true, wantDNSCalls: 0},
		{cell: "local-literal", name: "rfc1918 10/8", cfg: cfg, target: "http://10.0.0.1/", wantBlocked: true, wantDNSCheckOn: true, wantDNSCalls: 0},
		{cell: "local-literal", name: "rfc1918 172.16/12", cfg: cfg, target: "http://172.16.5.5/", wantBlocked: true, wantDNSCheckOn: true, wantDNSCalls: 0},
		{cell: "local-literal", name: "rfc1918 192.168/16", cfg: cfg, target: "http://192.168.1.1/", wantBlocked: true, wantDNSCheckOn: true, wantDNSCalls: 0},
		{cell: "local-literal", name: "link-local ipv4 169.254", cfg: cfg, target: "http://169.254.169.254/latest/meta-data/", wantBlocked: true, wantDNSCheckOn: true, wantDNSCalls: 0},
		{cell: "local-literal", name: "ipv6 link-local fe80", cfg: cfg, target: "http://[fe80::1]/", wantBlocked: true, wantDNSCheckOn: true, wantDNSCalls: 0},
		{cell: "local-literal", name: "ipv6 unique-local fc00", cfg: cfg, target: "http://[fc00::1]/", wantBlocked: true, wantDNSCheckOn: true, wantDNSCalls: 0},
		{cell: "local-literal", name: "unspecified 0.0.0.0", cfg: cfg, target: "http://0.0.0.0/", wantBlocked: true, wantDNSCheckOn: true, wantDNSCalls: 0},

		// ── Self-listener leg ───────────────────────────────────────
		{
			cell:           "self-listener",
			name:           "0.0.0.0:<listener-port>",
			cfg:            cfg,
			target:         "http://0.0.0.0:9000/",
			wantBlocked:    true,
			wantDNSCheckOn: true,
			wantDNSCalls:   0,
		},
		{
			cell:           "self-listener",
			name:           "::: paired with listener port",
			cfg:            cfg,
			target:         "http://[::]:9000/",
			wantBlocked:    true,
			wantDNSCheckOn: true,
			wantDNSCalls:   0,
		},
		{
			cell:           "self-listener",
			name:           "configured bind addr with listener port",
			cfg:            cfg,
			target:         "http://127.0.0.1:9000/",
			wantBlocked:    true,
			wantDNSCheckOn: true,
			wantDNSCalls:   0,
		},
		{
			// Empty BindAddr → defaults to "127.0.0.1". Asserts the
			// default-listener branch fires when the operator hasn't
			// configured an explicit bind address.
			cell:           "self-listener",
			name:           "empty BindAddr defaults to 127.0.0.1",
			cfg:            Config{BindAddr: "", Port: listenerPort},
			target:         "http://127.0.0.1:9000/",
			wantBlocked:    true,
			wantDNSCheckOn: true,
			wantDNSCalls:   0,
		},

		// ── Hostname → private IP via LookupHost swap ───────────────
		{
			cell:   "hostname-resolves-private",
			name:   "hostname resolves to 10.0.0.5",
			cfg:    cfg,
			target: "https://internal.example/",
			stubLookup: func(host string) ([]string, error) {
				return []string{"10.0.0.5"}, nil
			},
			wantBlocked:    true,
			wantDNSCheckOn: true,
			wantDNSCalls:   1,
		},
		{
			cell:   "hostname-resolves-private",
			name:   "hostname resolves to 169.254.169.254",
			cfg:    cfg,
			target: "https://metadata.example/",
			stubLookup: func(host string) ([]string, error) {
				return []string{"169.254.169.254"}, nil
			},
			wantBlocked:    true,
			wantDNSCheckOn: true,
			wantDNSCalls:   1,
		},
		{
			cell:   "hostname-resolves-private",
			name:   "hostname resolves to ::1",
			cfg:    cfg,
			target: "https://lb6.example/",
			stubLookup: func(host string) ([]string, error) {
				return []string{"::1"}, nil
			},
			wantBlocked:    true,
			wantDNSCheckOn: true,
			wantDNSCalls:   1,
		},

		// ── Public host (allow) ─────────────────────────────────────
		{
			cell:   "public-host",
			name:   "hostname resolves to public IP",
			cfg:    cfg,
			target: "https://example.com/",
			stubLookup: func(host string) ([]string, error) {
				return []string{"93.184.216.34"}, nil
			},
			wantBlocked:    false,
			wantDNSCheckOn: true,
			wantDNSCalls:   1,
		},
		{
			cell:           "public-host",
			name:           "public IP literal skips DNS",
			cfg:            cfg,
			target:         "http://203.0.113.10/",
			wantBlocked:    false,
			wantDNSCheckOn: true,
			wantDNSCalls:   0,
		},

		// ── DNS failure → allow ─────────────────────────────────────
		{
			cell:   "dns-failure",
			name:   "lookup error falls back to allow",
			cfg:    cfg,
			target: "https://nope.example/",
			stubLookup: func(host string) ([]string, error) {
				return nil, errors.New("simulated NXDOMAIN")
			},
			wantBlocked:    false,
			wantDNSCheckOn: true,
			wantDNSCalls:   1,
		},
		{
			cell:   "dns-failure",
			name:   "empty result falls back to allow",
			cfg:    cfg,
			target: "https://void.example/",
			stubLookup: func(host string) ([]string, error) {
				return []string{}, nil
			},
			wantBlocked:    false,
			wantDNSCheckOn: true,
			wantDNSCalls:   1,
		},
	}
}

// TestIsLocalOrListener_Table is the unit test surface for
// IsLocalOrListener. Carries every row from the current
// isBlockedTarget table in internal/web/server_test.go (the
// webPreservationRows partition) plus self-listener and DNS-edge
// rows. Covers both literal targets and LookupHost swap cases per
// design.md → "Unit Tests" final bullet.
//
// Validates: Requirements 3.1, 3.2, 3.3, 3.4, 3.8.
func TestIsLocalOrListener_Table(t *testing.T) {
	for _, row := range isLocalOrListenerRows() {
		row := row
		t.Run(row.cell+"/"+row.name, func(t *testing.T) {
			var calls int
			if row.stubLookup != nil {
				stub := row.stubLookup
				withStubLookupHost(t, func(host string) ([]string, error) {
					calls++
					return stub(host)
				})
			} else {
				// Even rows that should NOT trigger DNS still install a
				// counter-only stub. If the production code regresses
				// and starts looking up an IP literal, the assertion
				// catches it.
				withStubLookupHost(t, func(host string) ([]string, error) {
					calls++
					return nil, errors.New("DNS should not have been invoked for this row")
				})
			}

			got := IsLocalOrListener(row.cfg, row.target)
			if got != row.wantBlocked {
				t.Fatalf("IsLocalOrListener(%q) = %v, want %v",
					row.target, got, row.wantBlocked)
			}
			if row.wantDNSCheckOn && calls != row.wantDNSCalls {
				t.Fatalf("LookupHost calls for %q = %d, want %d",
					row.target, calls, row.wantDNSCalls)
			}
		})
	}
}

// TestIsLocalOrListener_SingleLookupAcrossTwoCalls asserts that two
// back-to-back calls each perform exactly one DNS lookup (no
// caching across calls). Mirrors
// TestIsBlockedTarget_SingleLookup in internal/web/server_test.go.
//
// Validates: Requirement 3.3 (single DNS lookup per call).
func TestIsLocalOrListener_SingleLookupAcrossTwoCalls(t *testing.T) {
	cfg := Config{BindAddr: "127.0.0.1", Port: 9000}

	var calls int
	withStubLookupHost(t, func(host string) ([]string, error) {
		calls++
		return []string{"203.0.113.10"}, nil
	})

	if blocked := IsLocalOrListener(cfg, "https://oos.example/"); blocked {
		t.Fatalf("public-IP-resolving target reported blocked = true")
	}
	if calls != 1 {
		t.Fatalf("LookupHost call count after first call = %d, want 1", calls)
	}

	if blocked := IsLocalOrListener(cfg, "https://oos.example/"); blocked {
		t.Fatalf("second call to public-IP-resolving target reported blocked = true")
	}
	if calls != 2 {
		t.Fatalf("LookupHost call count after second call = %d, want 2", calls)
	}
}
