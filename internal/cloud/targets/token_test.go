// Copyright (c) Xalgorix.
// SPDX-License-Identifier: AGPL-3.0-only

package targets

import (
	"strings"
	"testing"
)

const expectedPrefix = "xalgorix-site-verification="

// TestGenerateVerificationToken_Shape asserts that a freshly generated
// token has the exact shape required by Requirement 7.3:
// `xalgorix-site-verification=<32 base32 chars>`.
func TestGenerateVerificationToken_Shape(t *testing.T) {
	t.Parallel()

	token, err := GenerateVerificationToken()
	if err != nil {
		t.Fatalf("GenerateVerificationToken returned error: %v", err)
	}

	if !strings.HasPrefix(token, expectedPrefix) {
		t.Fatalf("token %q is missing prefix %q", token, expectedPrefix)
	}

	value := strings.TrimPrefix(token, expectedPrefix)
	if got, want := len(value), 32; got != want {
		t.Fatalf("value section length = %d, want %d (token=%q)", got, want, token)
	}

	for i, b := range []byte(value) {
		if !isBase32Upper(b) {
			t.Fatalf("value byte %d (%q) is outside the uppercase RFC 4648 base32 alphabet", i, b)
		}
	}
}

// TestGenerateVerificationToken_Entropy provides a sanity check that two
// successive generations do not collide. With 160 bits of entropy a real
// collision is astronomically unlikely; observing one would mean rand.Read
// has been replaced or the implementation has stopped reading entropy.
func TestGenerateVerificationToken_Entropy(t *testing.T) {
	t.Parallel()

	a, err := GenerateVerificationToken()
	if err != nil {
		t.Fatalf("first GenerateVerificationToken: %v", err)
	}
	b, err := GenerateVerificationToken()
	if err != nil {
		t.Fatalf("second GenerateVerificationToken: %v", err)
	}
	if a == b {
		t.Fatalf("two successive tokens were identical: %q", a)
	}
}

// TestGenerateVerificationToken_PassesValidator closes the loop by
// confirming that anything we generate is also accepted by
// IsValidTokenFormat. If this ever fails the issuer and the verifier have
// drifted apart, which would silently break ownership checks.
func TestGenerateVerificationToken_PassesValidator(t *testing.T) {
	t.Parallel()

	for i := 0; i < 32; i++ {
		token, err := GenerateVerificationToken()
		if err != nil {
			t.Fatalf("iteration %d: GenerateVerificationToken: %v", i, err)
		}
		if !IsValidTokenFormat(token) {
			t.Fatalf("iteration %d: IsValidTokenFormat rejected own output %q", i, token)
		}
	}
}

// TestIsValidTokenFormat is a table-driven check of every shape rule
// documented on IsValidTokenFormat: prefix presence, exact-32 value length,
// case-sensitive alphabet, no padding.
func TestIsValidTokenFormat(t *testing.T) {
	t.Parallel()

	const (
		valid32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567" // 32 chars, all alphabet
		short31 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ23456"  // 31 chars
		long33  = "ABCDEFGHIJKLMNOPQRSTUVWXYZ2345677" // 33 chars
	)

	cases := []struct {
		name  string
		token string
		want  bool
	}{
		{
			name:  "happy path",
			token: expectedPrefix + valid32,
			want:  true,
		},
		{
			name:  "empty string",
			token: "",
			want:  false,
		},
		{
			name:  "missing prefix",
			token: valid32,
			want:  false,
		},
		{
			name:  "wrong prefix casing",
			token: "Xalgorix-Site-Verification=" + valid32,
			want:  false,
		},
		{
			name:  "prefix only",
			token: expectedPrefix,
			want:  false,
		},
		{
			name:  "value too short",
			token: expectedPrefix + short31,
			want:  false,
		},
		{
			name:  "value too long",
			token: expectedPrefix + long33,
			want:  false,
		},
		{
			name:  "lowercase letter in value",
			token: expectedPrefix + "aBCDEFGHIJKLMNOPQRSTUVWXYZ234567",
			want:  false,
		},
		{
			name:  "digit 0 (not in base32 alphabet)",
			token: expectedPrefix + "0BCDEFGHIJKLMNOPQRSTUVWXYZ234567",
			want:  false,
		},
		{
			name:  "digit 1 (not in base32 alphabet)",
			token: expectedPrefix + "1BCDEFGHIJKLMNOPQRSTUVWXYZ234567",
			want:  false,
		},
		{
			name:  "digit 8 (not in base32 alphabet)",
			token: expectedPrefix + "8BCDEFGHIJKLMNOPQRSTUVWXYZ234567",
			want:  false,
		},
		{
			name:  "padding character",
			token: expectedPrefix + "=BCDEFGHIJKLMNOPQRSTUVWXYZ234567",
			want:  false,
		},
		{
			name:  "trailing padding",
			token: expectedPrefix + "ABCDEFGHIJKLMNOPQRSTUVWXYZ23456=",
			want:  false,
		},
		{
			name:  "trailing whitespace",
			token: expectedPrefix + valid32 + " ",
			want:  false,
		},
		{
			name:  "embedded space",
			token: expectedPrefix + "ABCDEFGH IJKLMNOPQRSTUVWXYZ234567",
			want:  false,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := IsValidTokenFormat(tc.token); got != tc.want {
				t.Fatalf("IsValidTokenFormat(%q) = %v, want %v", tc.token, got, tc.want)
			}
		})
	}
}
