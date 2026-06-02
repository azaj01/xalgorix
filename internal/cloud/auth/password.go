package auth

// File password.go implements task 2.1 of the xalgorix-saas spec:
//
//   - Hash:   Argon2id with time=2, memory=64 MiB, threads=2, key length 32,
//             16-byte random salt, encoded in PHC format
//             "$argon2id$v=19$m=65536,t=2,p=2$<saltB64>$<hashB64>".
//   - Verify: parses the PHC string, recomputes the hash with the encoded
//             parameters and salt, and compares in constant time.
//   - EnforcePolicy: minimum 12 characters and at least one letter and one
//             digit (per Decisions and Defaults / Requirement 3.3).
//
// HIBP k-anonymity checking is implemented separately by task 2.2 in
// hibp.go.
//
// Requirements: 3.3

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"unicode"

	"golang.org/x/crypto/argon2"
)

// Argon2id parameters fixed by task 2.1. They are part of the encoded PHC
// string so that future tuning remains backwards compatible.
const (
	argonTime    uint32 = 2
	argonMemory  uint32 = 64 * 1024 // 64 MiB, expressed in KiB
	argonThreads uint8  = 2
	argonKeyLen  uint32 = 32
	saltLen      int    = 16
)

// Password policy thresholds (Requirement 3.3 / Decisions and Defaults).
const minPasswordLength = 12

// Sentinel errors. Callers compare with errors.Is so that the HTTP layer can
// translate each policy violation into a 422 response that names the rule.
var (
	// ErrPasswordTooShort is returned when the password has fewer than
	// minPasswordLength characters.
	ErrPasswordTooShort = errors.New("password must be at least 12 characters")
	// ErrPasswordMissingLetter is returned when the password contains no
	// letter.
	ErrPasswordMissingLetter = errors.New("password must contain at least one letter")
	// ErrPasswordMissingDigit is returned when the password contains no
	// digit.
	ErrPasswordMissingDigit = errors.New("password must contain at least one digit")
	// ErrInvalidEncodedHash is returned by Verify when the supplied PHC
	// string is malformed or uses unsupported parameters.
	ErrInvalidEncodedHash = errors.New("invalid argon2id encoded hash")
)

// Hash returns the Argon2id PHC encoding of password using a fresh random
// salt. The returned string has the form
//
//	$argon2id$v=19$m=65536,t=2,p=2$<saltB64>$<hashB64>
//
// where saltB64 and hashB64 use unpadded standard base64.
func Hash(password string) (string, error) {
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("auth: read salt: %w", err)
	}
	hash := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	return encodeHash(salt, hash, argonTime, argonMemory, argonThreads), nil
}

// Verify reports whether password produces hash when re-hashed with the
// parameters and salt encoded in encoded. It performs the comparison in
// constant time so callers cannot infer prefix matches from timing.
//
// A non-nil error is returned only when encoded is malformed; in that case
// the boolean result is always false. A correct, mismatching password yields
// (false, nil).
func Verify(password, encoded string) (bool, error) {
	salt, hash, t, m, p, err := decodeHash(encoded)
	if err != nil {
		return false, err
	}
	other := argon2.IDKey([]byte(password), salt, t, m, p, uint32(len(hash)))
	if subtle.ConstantTimeCompare(hash, other) == 1 {
		return true, nil
	}
	return false, nil
}

// EnforcePolicy returns nil if password satisfies the platform password
// policy: at least 12 characters, with at least one letter and one digit.
// Each rule maps to a sentinel error so the API layer can name the violated
// rule in its 422 response (Requirement 3.3).
//
// EnforcePolicy operates on the rune length so that multi-byte characters
// count as single characters; it does not mutate or trim the input.
func EnforcePolicy(password string) error {
	if len([]rune(password)) < minPasswordLength {
		return ErrPasswordTooShort
	}
	var hasLetter, hasDigit bool
	for _, r := range password {
		switch {
		case unicode.IsLetter(r):
			hasLetter = true
		case unicode.IsDigit(r):
			hasDigit = true
		}
		if hasLetter && hasDigit {
			break
		}
	}
	if !hasLetter {
		return ErrPasswordMissingLetter
	}
	if !hasDigit {
		return ErrPasswordMissingDigit
	}
	return nil
}

// encodeHash assembles the PHC string for an Argon2id hash with the supplied
// parameters. The base64 encoding is unpadded standard (RFC 4648 §3.2 with
// padding stripped), consistent with the reference Argon2 PHC format.
func encodeHash(salt, hash []byte, t, m uint32, p uint8) string {
	enc := base64.RawStdEncoding
	return fmt.Sprintf(
		"$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, m, t, p,
		enc.EncodeToString(salt),
		enc.EncodeToString(hash),
	)
}

// decodeHash parses a PHC-encoded Argon2id hash and returns the salt, hash,
// and the time, memory, and parallelism parameters used to derive it. It
// rejects any encoding that does not target argon2id with the version
// recognised by this package.
func decodeHash(encoded string) (salt, hash []byte, t, m uint32, p uint8, err error) {
	parts := strings.Split(encoded, "$")
	// Expected: ["", "argon2id", "v=19", "m=...,t=...,p=...", "<saltB64>", "<hashB64>"]
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" {
		err = ErrInvalidEncodedHash
		return
	}

	var version int
	if _, e := fmt.Sscanf(parts[2], "v=%d", &version); e != nil {
		err = ErrInvalidEncodedHash
		return
	}
	if version != argon2.Version {
		err = ErrInvalidEncodedHash
		return
	}

	if _, e := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &m, &t, &p); e != nil {
		err = ErrInvalidEncodedHash
		return
	}
	if t == 0 || m == 0 || p == 0 {
		err = ErrInvalidEncodedHash
		return
	}

	enc := base64.RawStdEncoding
	salt, e := enc.DecodeString(parts[4])
	if e != nil {
		err = ErrInvalidEncodedHash
		return
	}
	hash, e = enc.DecodeString(parts[5])
	if e != nil {
		err = ErrInvalidEncodedHash
		return
	}
	if len(salt) == 0 || len(hash) == 0 {
		err = ErrInvalidEncodedHash
		return
	}
	return salt, hash, t, m, p, nil
}
