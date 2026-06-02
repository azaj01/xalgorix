// Copyright (c) Xalgorix.
// SPDX-License-Identifier: AGPL-3.0-only

package targets

import (
	"crypto/rand"
	"encoding/base32"
	"fmt"
	"strings"
)

// tokenPrefix is the user-visible label that customers paste into a DNS TXT
// record, .well-known file, or HTML <meta> tag in order to prove ownership of
// a Target. The shape and uniqueness rules are pinned by Requirement 7.3
// (display token of the form `xalgorix-site-verification=<32-char-base32>`)
// and Requirement 7.8 (a single verification token must not verify more than
// one Workspace; the database column `targets.verification_token` carries a
// platform-wide UNIQUE constraint).
const tokenPrefix = "xalgorix-site-verification="

// tokenValueLen is the number of base32 characters in the value section of
// the token. 20 random bytes RFC 4648 base32-encoded produce exactly 32
// characters with no padding (5 bytes → 8 chars), which matches the spec.
const tokenValueLen = 32

// tokenEntropyBytes is the amount of cryptographically random bytes fed to
// the base32 encoder. 20 bytes ⇒ 160 bits of entropy, well above the 128-bit
// floor we want for a public, eventually-broadcast identifier.
const tokenEntropyBytes = 20

// tokenEncoding is RFC 4648 base32 with no padding. The alphabet is
// uppercase A–Z2–7 by definition, which is exactly what Requirement 7.3
// asks for ("32-char-base32"). We reject any padding character on input and
// never emit one on output.
var tokenEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// GenerateVerificationToken produces a fresh ownership-verification token of
// the form `xalgorix-site-verification=<32 base32 chars>`. The 32-character
// value section is derived from 20 cryptographically random bytes, encoded
// with RFC 4648 base32 (uppercase, no padding).
//
// The returned string is suitable for direct persistence into
// `targets.verification_token`, which carries a platform-wide UNIQUE
// constraint (design.md, Requirement 7.8). Collisions on 160 bits of entropy
// are vanishingly unlikely; callers are still expected to treat a unique
// constraint violation as a retryable condition rather than an internal
// error.
//
// The only error this function can return is a `crypto/rand.Read` failure,
// which on a healthy host is itself fatal — callers should propagate it
// rather than fall back to a weaker source.
func GenerateVerificationToken() (string, error) {
	buf := make([]byte, tokenEntropyBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("targets: read entropy for verification token: %w", err)
	}

	encoded := tokenEncoding.EncodeToString(buf)
	// Defensive sanity check: a base32-no-padding encoding of 20 bytes is
	// always exactly 32 characters. If this ever changes we want to fail
	// loudly rather than persist a malformed token.
	if len(encoded) != tokenValueLen {
		return "", fmt.Errorf("targets: encoded token has length %d, want %d", len(encoded), tokenValueLen)
	}

	return tokenPrefix + encoded, nil
}

// IsValidTokenFormat reports whether token has the exact shape
// `xalgorix-site-verification=<32 base32 chars>`. It does not consult the
// database; callers that need to confirm the token is bound to a particular
// Target must additionally look it up in `targets.verification_token`.
//
// The check is deliberately strict:
//   - the prefix match is case-sensitive,
//   - the value section must be exactly 32 characters,
//   - every value character must come from the RFC 4648 base32 alphabet
//     (uppercase A–Z, digits 2–7),
//   - no padding character (`=`) is permitted.
//
// This shape is what verifiers (DNS TXT, file, meta tag) compare against
// when scraping customer infrastructure, so any drift here would silently
// break ownership checks.
func IsValidTokenFormat(token string) bool {
	if !strings.HasPrefix(token, tokenPrefix) {
		return false
	}
	value := token[len(tokenPrefix):]
	if len(value) != tokenValueLen {
		return false
	}
	for i := 0; i < len(value); i++ {
		if !isBase32Upper(value[i]) {
			return false
		}
	}
	return true
}

// isBase32Upper reports whether b is a character in the RFC 4648 base32
// alphabet (uppercase). We hand-roll the check rather than reuse
// tokenEncoding.DecodeString because the latter accepts lowercase input on
// some platforms and would also tolerate stray padding when the input
// length is a multiple of 8.
func isBase32Upper(b byte) bool {
	return (b >= 'A' && b <= 'Z') || (b >= '2' && b <= '7')
}
