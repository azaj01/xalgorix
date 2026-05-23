package main

import (
	"strings"
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/config"
)

// TestIsNewer covers the semver comparison used by the auto-update path.
// Pre-release ordering is intentionally not modeled (the comment in main.go
// documents this): we only need the major/minor/patch numeric comparison
// to behave correctly so the updater doesn't try to "upgrade" to a stale
// or older tag.
func TestIsNewer(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		// Strict greater
		{"4.2.3", "4.2.2", true},
		{"4.3.0", "4.2.99", true},
		{"5.0.0", "4.99.99", true},
		// Strict less
		{"4.2.1", "4.2.2", false},
		{"4.2.99", "4.3.0", false},
		{"4.99.99", "5.0.0", false},
		// Equal — isNewer returns false (only "newer", not "newer-or-equal")
		{"4.2.2", "4.2.2", false},
		// More segments win when leading parts match
		{"4.2.2.1", "4.2.2", true},
		{"4.2.2", "4.2.2.1", false},
		// Non-numeric segments compare as 0 (permissive — pre-release
		// ordering is intentionally not modeled). For a "4.2.2" vs
		// "4.2.2-rc1" pair this happens to give the right answer: the
		// final parts "2" (=2) vs "2-rc1" (=0 on parse failure) make the
		// release strictly greater than its rc, which matches semver
		// intuition. The reverse direction returns false for the same
		// reason.
		{"4.2.2", "4.2.2-rc1", true},
		{"4.2.2-rc1", "4.2.2", false},
		// Empty-string edge cases — should not panic and return false.
		{"", "", false},
		{"1.0.0", "", true},
	}

	for _, tc := range cases {
		got := isNewer(tc.a, tc.b)
		if got != tc.want {
			t.Errorf("isNewer(%q, %q) = %v, want %v", tc.a, tc.b, got, tc.want)
		}
	}
}

func TestServiceUnitUsesDedicatedWorkspaceAndContinuesAfterChildOOM(t *testing.T) {
	unit := serviceUnitContent("/root", "/root/xalgorix-workspace", "/usr/local/bin/xalgorix")

	for _, want := range []string{
		"WorkingDirectory=/root/xalgorix-workspace",
		`Environment="XALGORIX_WORKSPACE=/root/xalgorix-workspace"`,
		"OOMScoreAdjust=-500",
		"OOMPolicy=continue",
	} {
		if !strings.Contains(unit, want) {
			t.Fatalf("service unit missing %q:\n%s", want, unit)
		}
	}
}

func TestServiceAccessLinesLoopbackExplainExternalSetup(t *testing.T) {
	lines := strings.Join(serviceAccessLines(&config.Config{BindAddr: "127.0.0.1"}, defaultWebPort), "\n")

	for _, want := range []string{
		"Web UI: http://localhost:9137 (loopback only)",
		"XALGORIX_BIND=0.0.0.0",
		"XALGORIX_USERNAME",
		"restart",
	} {
		if !strings.Contains(lines, want) {
			t.Fatalf("service access lines missing %q:\n%s", want, lines)
		}
	}
}

func TestServiceAccessLinesNetworkExposed(t *testing.T) {
	lines := strings.Join(serviceAccessLines(&config.Config{
		BindAddr:     "0.0.0.0",
		Username:     "admin",
		PasswordHash: "$2a$10$example",
	}, defaultWebPort), "\n")

	for _, want := range []string{
		"Web UI: http://<server-ip>:9137 (network-exposed)",
		"open TCP port 9137",
	} {
		if !strings.Contains(lines, want) {
			t.Fatalf("service access lines missing %q:\n%s", want, lines)
		}
	}
	if strings.Contains(lines, "will refuse to start") {
		t.Fatalf("authenticated external bind should not warn that startup will be refused:\n%s", lines)
	}
}

func TestServiceAccessLinesExternalWithoutAuthWarns(t *testing.T) {
	lines := strings.Join(serviceAccessLines(&config.Config{BindAddr: "0.0.0.0"}, defaultWebPort), "\n")

	if !strings.Contains(lines, "external bind requires XALGORIX_USERNAME") ||
		!strings.Contains(lines, "will refuse to start without auth") {
		t.Fatalf("missing external bind auth warning:\n%s", lines)
	}
}
