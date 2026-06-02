package targets

import "testing"

func TestIsLoopback(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		host string
		want bool
	}{
		// Loopback hostnames and IPs.
		{"hostname localhost", "localhost", true},
		{"hostname localhost mixed case", "LocalHost", true},
		{"ipv4 127.0.0.1", "127.0.0.1", true},
		{"ipv4 127.10.0.1 in 127.0.0.0/8", "127.10.0.1", true},
		{"ipv4 boundary 127.0.0.0", "127.0.0.0", true},
		{"ipv4 boundary 127.255.255.255", "127.255.255.255", true},
		{"ipv6 ::1 bare", "::1", true},
		{"ipv6 ::1 bracketed", "[::1]", true},
		{"ipv6 long form ::1", "0:0:0:0:0:0:0:1", true},

		// host:port forms.
		{"localhost with port", "localhost:8080", true},
		{"127.0.0.1 with port", "127.0.0.1:8080", true},
		{"[::1] with port", "[::1]:8080", true},

		// Non-loopback hosts.
		{"example.com hostname", "example.com", false},
		{"public ipv4 10.0.0.1", "10.0.0.1", false},
		{"public ipv4 192.168.1.1", "192.168.1.1", false},
		{"public ipv4 8.8.8.8", "8.8.8.8", false},
		{"ipv4 boundary 128.0.0.0 outside /8", "128.0.0.0", false},
		{"ipv4 boundary 126.255.255.255 outside /8", "126.255.255.255", false},
		{"public ipv6", "2001:db8::1", false},
		{"public ipv6 bracketed", "[2001:db8::1]", false},
		{"public host with port", "example.com:443", false},
		{"public ipv4 with port", "10.0.0.1:8080", false},
		{"empty string", "", false},
		{"whitespace only", "   ", false},
		{"garbage input", "not-an-ip-or-host!", false},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := IsLoopback(tc.host)
			if got != tc.want {
				t.Fatalf("IsLoopback(%q) = %v, want %v", tc.host, got, tc.want)
			}
		})
	}
}

func TestClassifyVerification(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		host string
		want string
	}{
		{"localhost short-circuits", "localhost", VerificationStatusVerifiedLocal},
		{"127.0.0.1 short-circuits", "127.0.0.1", VerificationStatusVerifiedLocal},
		{"127.10.0.1 short-circuits", "127.10.0.1", VerificationStatusVerifiedLocal},
		{"::1 short-circuits", "::1", VerificationStatusVerifiedLocal},
		{"[::1] short-circuits", "[::1]", VerificationStatusVerifiedLocal},
		{"localhost:8080 short-circuits", "localhost:8080", VerificationStatusVerifiedLocal},
		{"example.com requires external check", "example.com", VerificationStatusUnverified},
		{"10.0.0.1 requires external check", "10.0.0.1", VerificationStatusUnverified},
		{"public ipv6 requires external check", "2001:db8::1", VerificationStatusUnverified},
		{"empty host requires external check", "", VerificationStatusUnverified},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := ClassifyVerification(tc.host)
			if got != tc.want {
				t.Fatalf("ClassifyVerification(%q) = %q, want %q", tc.host, got, tc.want)
			}
		})
	}
}
