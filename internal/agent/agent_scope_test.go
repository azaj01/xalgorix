package agent

import (
	"strings"
	"testing"
)

// TestShouldBlockForOutOfScope_BlocksThirdPartyHost is the regression
// test for the "agent reports findings on unrelated host" bug
// (Grafana on 159.223.74.62:9999 turning up in a scan of
// pentest-ground.com). The agent must reject any tool call whose
// arguments name a host that isn't the configured target or a
// subdomain of it.
func TestShouldBlockForOutOfScope_BlocksThirdPartyHost(t *testing.T) {
	a := &Agent{}
	a.SetActivityPolicy("active", "active", []string{"https://pentest-ground.com"})

	cases := []struct {
		name string
		tool string
		args map[string]string
	}{
		{
			name: "terminal_execute against unrelated IP",
			tool: "terminal_execute",
			args: map[string]string{
				"command": "curl http://159.223.74.62:9999/?title=%22%3E%3Csvg/onload=alert(1)%3E",
			},
		},
		{
			name: "report_vulnerability with unrelated target field",
			tool: "report_vulnerability",
			args: map[string]string{
				"title":    "XSS in Grafana",
				"target":   "http://159.223.74.62:9999",
				"endpoint": "http://159.223.74.62:9999/?title=%3Csvg",
				"severity": "high",
			},
		},
		{
			name: "browser_action navigating to unrelated host",
			tool: "browser_action",
			args: map[string]string{
				"action": "navigate",
				"url":    "https://attacker.example/callback",
			},
		},
		{
			name: "python_action requesting unrelated host",
			tool: "python_action",
			args: map[string]string{
				"code": "import requests; requests.get('http://example.org/admin')",
			},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			blocked, reason := a.shouldBlockForOutOfScope(tc.tool, tc.args)
			if !blocked {
				t.Fatalf("expected %s with args %v to be blocked, got allow", tc.tool, tc.args)
			}
			if reason == "" {
				t.Fatalf("expected non-empty rejection reason")
			}
		})
	}
}

// TestShouldBlockForOutOfScope_AllowsInScope confirms the guard does
// not block legitimate tool calls against the configured target or
// its subdomains.
func TestShouldBlockForOutOfScope_AllowsInScope(t *testing.T) {
	a := &Agent{}
	a.SetActivityPolicy("active", "active", []string{"https://pentest-ground.com"})

	cases := []struct {
		name string
		tool string
		args map[string]string
	}{
		{
			name: "exact target",
			tool: "terminal_execute",
			args: map[string]string{"command": "nmap -sV pentest-ground.com"},
		},
		{
			name: "subdomain",
			tool: "terminal_execute",
			args: map[string]string{"command": "curl https://api.pentest-ground.com/v1/users"},
		},
		{
			name: "URL form with port",
			tool: "browser_action",
			args: map[string]string{"url": "https://app.pentest-ground.com:8443/admin"},
		},
		{
			name: "report_vulnerability against subdomain",
			tool: "report_vulnerability",
			args: map[string]string{
				"target":   "https://api.pentest-ground.com",
				"endpoint": "https://api.pentest-ground.com/v1/users",
				"title":    "IDOR",
				"severity": "high",
			},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			if blocked, reason := a.shouldBlockForOutOfScope(tc.tool, tc.args); blocked {
				t.Fatalf("expected %s with args %v to be allowed, got blocked: %s", tc.tool, tc.args, reason)
			}
		})
	}
}

// TestShouldBlockForOutOfScope_AllowsHostlessCommands confirms tool
// calls that don't name any host (local artifact analysis like grep,
// awk, jq over recon output files) are allowed.
func TestShouldBlockForOutOfScope_AllowsHostlessCommands(t *testing.T) {
	a := &Agent{}
	a.SetActivityPolicy("active", "active", []string{"https://pentest-ground.com"})

	cases := []map[string]string{
		{"command": "ls -la"},
		{"command": "grep 'password' notes.json"},
		{"command": "jq '.vulns[]' scan.json"},
		{"command": "wc -l live_subdomains.txt"},
	}
	for _, args := range cases {
		if blocked, reason := a.shouldBlockForOutOfScope("terminal_execute", args); blocked {
			t.Fatalf("hostless command %v should be allowed, got blocked: %s", args, reason)
		}
	}
}

// TestShouldBlockForOutOfScope_DisabledWhenNoScope confirms the gate
// is a no-op when no activity hosts are configured. A scope-less scan
// (CLI mode without targets piped in) shouldn't fail every tool call.
func TestShouldBlockForOutOfScope_DisabledWhenNoScope(t *testing.T) {
	a := &Agent{}
	// activityHosts left empty
	if blocked, _ := a.shouldBlockForOutOfScope("terminal_execute",
		map[string]string{"command": "curl http://anywhere.example"}); blocked {
		t.Fatal("expected guard to be disabled when activityHosts is empty")
	}
}

// TestExtractHostFromTokenForScope tests the host-extraction primitive
// for the variety of token shapes the agent emits.
func TestExtractHostFromTokenForScope(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"https://example.com/path", "example.com"},
		{"http://example.com:8080/path", "example.com"},
		{"example.com:8080", "example.com"},
		{"example.com", "example.com"},
		{"159.223.74.62", "159.223.74.62"},
		{"159.223.74.62:9999", "159.223.74.62"},
		{"[2001:db8::1]:443", "2001:db8::1"},
		{"./script.sh", ""},
		{"/tmp/foo.txt", ""},
		{"../etc/passwd", ""},
		{"v1.2.3", ""},
		{"1.2.3", ""},
		{"--rate-limit", ""},
		{"", ""},
	}
	for _, tc := range cases {
		got := extractHostFromTokenForScope(tc.in)
		if got != tc.want {
			t.Errorf("extractHostFromTokenForScope(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestHostInScope tests the scope membership primitive.
func TestHostInScope(t *testing.T) {
	hosts := []string{"pentest-ground.com", "another.example"}
	cases := []struct {
		in   string
		want bool
	}{
		{"pentest-ground.com", true},
		{"api.pentest-ground.com", true},
		{"deep.nested.api.pentest-ground.com", true},
		{"another.example", true},
		{"sub.another.example", true},
		// Suffix attack: must not match.
		{"evilpentest-ground.com", false},
		{"pentest-ground.com.attacker.example", false},
		// Unrelated.
		{"159.223.74.62", false},
		{"google.com", false},
		// Empty host = always in-scope (caller's call).
		{"", true},
	}
	for _, tc := range cases {
		got := hostInScope(tc.in, hosts)
		if got != tc.want {
			t.Errorf("hostInScope(%q, %v) = %v, want %v", tc.in, hosts, got, tc.want)
		}
	}
}

// TestExtractHostsFromArgs verifies multi-token extraction.
func TestExtractHostsFromArgs(t *testing.T) {
	args := map[string]string{
		"command": `curl -H "Host: api.example.com" https://example.com/foo && nmap evil.org`,
	}
	hosts := extractHostsFromArgs(args)
	got := strings.Join(hosts, ",")
	// Order is insertion-order; the actual hosts must include the three
	// distinct ones from the command.
	for _, want := range []string{"api.example.com", "example.com", "evil.org"} {
		if !strings.Contains(got, want) {
			t.Errorf("extractHostsFromArgs(%v) = %v, missing %q", args, hosts, want)
		}
	}
}
