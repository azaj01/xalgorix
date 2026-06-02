package auth

// File mfa.go implements task 2.9 of the xalgorix-saas spec:
//
//   - EnableTOTP:      mints a 20-byte TOTP secret, base32-encodes it, builds
//                      the matching otpauth:// URL with issuer "Xalgorix" and
//                      label "<email>", persists the KMS-envelope ciphertext
//                      of the secret in account_mfa.totp_secret_enc, and
//                      generates 10 random 12-character recovery codes whose
//                      HMAC-SHA256 hashes are stored in
//                      account_mfa.recovery_codes.
//   - VerifyTOTP:      RFC 6238 6-digit / 30-second / SHA-1 verification with
//                      ±1 window tolerance to absorb clock drift and the
//                      common "user typed during a step boundary" race.
//   - ConsumeRecovery: HMAC-SHA256 the supplied code with the platform key,
//                      compare in constant time against the stored hash list
//                      and, on match, atomically remove the consumed entry
//                      so a recovery code is single-use.
//
// The envelope encryption indirection keeps unit tests free of KMS
// dependencies: production callers pass a KMS-backed Envelope, while tests
// pass IdentityEnvelope so the raw secret round-trips unchanged.
//
// Requirements: 3.6, 3.7
// Design: design.md → "MFA" (TOTP RFC 6238, 6-digit, 30s window; 10
//                            HMAC-stored recovery codes).

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // RFC 6238 specifies HMAC-SHA1 for TOTP
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// TOTP parameters fixed by RFC 6238 and the design document. They are
// constants rather than configurables so that two cooperating callers
// (an authenticator app and the API_Server) cannot drift apart.
const (
	// TOTPDigits is the number of decimal digits in a TOTP code.
	TOTPDigits = 6
	// TOTPPeriodSeconds is the time step in seconds.
	TOTPPeriodSeconds = 30
	// TOTPSecretBytes is the size of a freshly minted TOTP secret. RFC
	// 4226 §4 recommends at least 128 bits; we use 160 bits which
	// matches the SHA-1 block-derived HMAC length.
	TOTPSecretBytes = 20
	// TOTPIssuer is embedded in the otpauth:// URL so authenticator
	// apps display "Xalgorix" alongside the account email.
	TOTPIssuer = "Xalgorix"
)

// Recovery code parameters (Requirement 3.7 / design "MFA").
const (
	// RecoveryCodeCount is the number of recovery codes generated when
	// MFA is enabled. Each code is single-use.
	RecoveryCodeCount = 10
	// RecoveryCodeLength is the number of characters in each recovery
	// code drawn from recoveryAlphabet.
	RecoveryCodeLength = 12
)

// recoveryAlphabet is a 32-character Crockford-style alphabet that
// excludes visually ambiguous characters (0/O, 1/I/L). 32 divides 256
// evenly so a single uniform byte selects a character without bias.
const recoveryAlphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"

// minMFAHMACKeyBytes is the minimum length of the recovery-code HMAC
// signing key. The key is platform-wide and rotated via KMS; tests
// supply a fixed 32-byte key.
const minMFAHMACKeyBytes = 32

// Sentinel errors. The HTTP layer maps these onto user-facing error
// codes; the strings here are intentionally generic so they do not
// leak which factor failed (TOTP vs recovery).
var (
	// ErrMFANotEnabled is returned by VerifyTOTP / ConsumeRecovery when
	// the account has no account_mfa row. Callers should treat it as
	// "MFA challenge not applicable" rather than as an authentication
	// failure.
	ErrMFANotEnabled = errors.New("auth: mfa not enabled")
)

// MFARepo is the persistence contract used by MFAService. It is
// scoped narrowly so that tests can ship a fake without standing up a
// Postgres instance, while production wires it to the real
// account_mfa table via pgx.
type MFARepo interface {
	// AccountEmail returns the primary email for the account so that
	// EnableTOTP can populate the otpauth:// label.
	AccountEmail(ctx context.Context, accountID string) (string, error)
	// SaveMFA upserts the encrypted TOTP secret and recovery hash
	// list for accountID. It is called once per EnableTOTP and again
	// whenever recovery codes are regenerated.
	SaveMFA(ctx context.Context, accountID string, totpSecretEnc []byte, recoveryHashes []string) error
	// LoadMFA returns the encrypted TOTP secret and recovery hash
	// list. It returns ErrMFANotEnabled when the account has no row.
	LoadMFA(ctx context.Context, accountID string) (totpSecretEnc []byte, recoveryHashes []string, err error)
	// UpdateRecoveryHashes replaces the recovery hash list. It is
	// invoked by ConsumeRecovery to drop the consumed entry. The
	// production implementation uses array_remove inside a single
	// statement so concurrent consumes cannot resurrect a code.
	UpdateRecoveryHashes(ctx context.Context, accountID string, recoveryHashes []string) error
}

// Envelope wraps the KMS envelope-encryption helper so callers can
// substitute an in-process implementation for tests. Encrypt and
// Decrypt are inverses for any input.
type Envelope interface {
	Encrypt(ctx context.Context, plaintext []byte) ([]byte, error)
	Decrypt(ctx context.Context, ciphertext []byte) ([]byte, error)
}

// IdentityEnvelope is a no-op Envelope used by unit tests. Production
// code MUST NOT use it; the MFAService panics if no envelope is
// supplied to make accidental misuse loud.
type IdentityEnvelope struct{}

// Encrypt returns a copy of plaintext.
func (IdentityEnvelope) Encrypt(_ context.Context, plaintext []byte) ([]byte, error) {
	return append([]byte(nil), plaintext...), nil
}

// Decrypt returns a copy of ciphertext.
func (IdentityEnvelope) Decrypt(_ context.Context, ciphertext []byte) ([]byte, error) {
	return append([]byte(nil), ciphertext...), nil
}

// MFAService is the application-level facade for TOTP MFA and
// recovery-code consumption. It is safe for concurrent use; the
// underlying repo and envelope are expected to be safe as well.
type MFAService struct {
	repo     MFARepo
	envelope Envelope
	hmacKey  []byte
	now      func() time.Time
	rand     io.Reader
}

// NewMFAService constructs an MFAService. It panics if repo or
// envelope is nil, or if hmacKey is shorter than minMFAHMACKeyBytes;
// each is a deploy-time misconfiguration that must surface at boot
// rather than during an MFA challenge.
func NewMFAService(repo MFARepo, envelope Envelope, hmacKey []byte) *MFAService {
	if repo == nil {
		panic("auth: NewMFAService requires a non-nil repo")
	}
	if envelope == nil {
		panic("auth: NewMFAService requires a non-nil envelope")
	}
	if len(hmacKey) < minMFAHMACKeyBytes {
		panic(fmt.Sprintf("auth: NewMFAService requires an hmacKey of at least %d bytes", minMFAHMACKeyBytes))
	}
	keyCopy := append([]byte(nil), hmacKey...)
	return &MFAService{
		repo:     repo,
		envelope: envelope,
		hmacKey:  keyCopy,
		now:      time.Now,
		rand:     rand.Reader,
	}
}

// EnableTOTP creates a fresh TOTP secret for accountID, builds the
// otpauth:// provisioning URL, persists the KMS-envelope ciphertext,
// and generates ten single-use recovery codes whose HMAC-SHA256
// hashes are stored alongside the secret. It returns the base32
// secret, the otpauth URL (suitable for QR rendering), and the raw
// recovery codes — these are the only times the platform sees the
// recovery codes in plaintext, so the caller MUST display them to the
// account immediately and discard the slice.
func (s *MFAService) EnableTOTP(ctx context.Context, accountID string) (string, string, []string, error) {
	if accountID == "" {
		return "", "", nil, errors.New("auth: EnableTOTP requires a non-empty account id")
	}

	email, err := s.repo.AccountEmail(ctx, accountID)
	if err != nil {
		return "", "", nil, fmt.Errorf("auth: lookup account email: %w", err)
	}
	if email == "" {
		return "", "", nil, errors.New("auth: account has no email for otpauth label")
	}

	secret := make([]byte, TOTPSecretBytes)
	if _, err := io.ReadFull(s.rand, secret); err != nil {
		return "", "", nil, fmt.Errorf("auth: read totp secret entropy: %w", err)
	}
	secretB32 := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(secret)

	otpauthURL := buildOTPAuthURL(TOTPIssuer, email, secretB32)

	enc, err := s.envelope.Encrypt(ctx, secret)
	if err != nil {
		return "", "", nil, fmt.Errorf("auth: encrypt totp secret: %w", err)
	}

	codes := make([]string, RecoveryCodeCount)
	hashes := make([]string, RecoveryCodeCount)
	for i := 0; i < RecoveryCodeCount; i++ {
		code, err := s.generateRecoveryCode()
		if err != nil {
			return "", "", nil, err
		}
		codes[i] = code
		hashes[i] = s.hashRecoveryCode(code)
	}

	if err := s.repo.SaveMFA(ctx, accountID, enc, hashes); err != nil {
		return "", "", nil, fmt.Errorf("auth: save mfa: %w", err)
	}

	return secretB32, otpauthURL, codes, nil
}

// VerifyTOTP returns true when code matches the RFC 6238 HOTP value
// for accountID at the current time step or one step on either side.
// The ±1 window tolerance absorbs both clock drift and the race where
// a user types the code as the step boundary rolls over.
//
// VerifyTOTP returns ErrMFANotEnabled when the account has no
// account_mfa row. A malformed code (wrong length / non-numeric) is
// returned as (false, nil) so callers cannot distinguish "no MFA"
// from "wrong code".
func (s *MFAService) VerifyTOTP(ctx context.Context, accountID, code string) (bool, error) {
	if accountID == "" {
		return false, errors.New("auth: VerifyTOTP requires a non-empty account id")
	}
	code = strings.TrimSpace(code)
	if len(code) != TOTPDigits {
		return false, nil
	}
	for i := 0; i < TOTPDigits; i++ {
		if code[i] < '0' || code[i] > '9' {
			return false, nil
		}
	}

	enc, _, err := s.repo.LoadMFA(ctx, accountID)
	if err != nil {
		return false, err
	}
	secret, err := s.envelope.Decrypt(ctx, enc)
	if err != nil {
		return false, fmt.Errorf("auth: decrypt totp secret: %w", err)
	}

	step := s.now().Unix() / int64(TOTPPeriodSeconds)
	codeBytes := []byte(code)
	matched := false
	// We walk all three windows even after a hit so the function does
	// not leak which window matched via timing.
	for offset := int64(-1); offset <= 1; offset++ {
		want := hotp(secret, uint64(step+offset), TOTPDigits)
		if subtle.ConstantTimeCompare(codeBytes, []byte(want)) == 1 {
			matched = true
		}
	}
	return matched, nil
}

// ConsumeRecovery looks up the HMAC of code in accountID's stored
// recovery hashes; on match, the consumed entry is removed so the
// code cannot be reused. It returns true on a successful consume,
// false on no match, and surfaces ErrMFANotEnabled when the account
// has no account_mfa row.
//
// The match scan compares every entry with subtle.ConstantTimeCompare
// to avoid leaking the position of the matching code via early-exit
// timing.
func (s *MFAService) ConsumeRecovery(ctx context.Context, accountID, code string) (bool, error) {
	if accountID == "" {
		return false, errors.New("auth: ConsumeRecovery requires a non-empty account id")
	}
	normalized := normalizeRecoveryCode(code)
	if len(normalized) != RecoveryCodeLength {
		return false, nil
	}

	_, hashes, err := s.repo.LoadMFA(ctx, accountID)
	if err != nil {
		return false, err
	}
	target := s.hashRecoveryCode(normalized)
	targetBytes := []byte(target)

	matchedIdx := -1
	for i, h := range hashes {
		if subtle.ConstantTimeCompare([]byte(h), targetBytes) == 1 {
			matchedIdx = i
		}
	}
	if matchedIdx < 0 {
		return false, nil
	}

	updated := make([]string, 0, len(hashes)-1)
	updated = append(updated, hashes[:matchedIdx]...)
	updated = append(updated, hashes[matchedIdx+1:]...)
	if err := s.repo.UpdateRecoveryHashes(ctx, accountID, updated); err != nil {
		return false, fmt.Errorf("auth: update recovery hashes: %w", err)
	}
	return true, nil
}

// generateRecoveryCode returns a fresh RecoveryCodeLength-character
// code drawn uniformly from recoveryAlphabet. The 32-character
// alphabet divides 256 evenly so the modulo selection is unbiased.
func (s *MFAService) generateRecoveryCode() (string, error) {
	raw := make([]byte, RecoveryCodeLength)
	if _, err := io.ReadFull(s.rand, raw); err != nil {
		return "", fmt.Errorf("auth: read recovery entropy: %w", err)
	}
	out := make([]byte, RecoveryCodeLength)
	for i, b := range raw {
		out[i] = recoveryAlphabet[int(b)%len(recoveryAlphabet)]
	}
	return string(out), nil
}

// hashRecoveryCode returns the lowercase hex HMAC-SHA256 of code
// using the service's signing key. The code is normalized first so
// two textually different but semantically identical inputs (e.g.
// trailing whitespace, mixed case) hash to the same value.
func (s *MFAService) hashRecoveryCode(code string) string {
	mac := hmac.New(sha256.New, s.hmacKey)
	mac.Write([]byte(normalizeRecoveryCode(code)))
	return hex.EncodeToString(mac.Sum(nil))
}

// normalizeRecoveryCode strips whitespace and inner separators
// (hyphens / spaces inserted by users when transcribing the code)
// and uppercases the result so it matches recoveryAlphabet.
func normalizeRecoveryCode(code string) string {
	var b strings.Builder
	b.Grow(len(code))
	for _, r := range strings.ToUpper(strings.TrimSpace(code)) {
		if r == ' ' || r == '-' || r == '\t' {
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// hotp implements RFC 4226 dynamic truncation. RFC 6238 layers TOTP
// on top by setting the counter to floor(unix_time / period). The
// function is package-private so VerifyTOTP and tests can share it.
func hotp(secret []byte, counter uint64, digits int) string {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], counter)
	mac := hmac.New(sha1.New, secret)
	mac.Write(buf[:])
	sum := mac.Sum(nil)
	offset := int(sum[len(sum)-1] & 0x0f)
	value := (uint32(sum[offset]&0x7f) << 24) |
		(uint32(sum[offset+1]) << 16) |
		(uint32(sum[offset+2]) << 8) |
		uint32(sum[offset+3])
	mod := uint32(1)
	for i := 0; i < digits; i++ {
		mod *= 10
	}
	code := value % mod
	return fmt.Sprintf("%0*d", digits, code)
}

// buildOTPAuthURL composes the otpauth:// URL that authenticator apps
// scan from a QR code. The label is "<issuer>:<email>" per the Key
// URI Format spec; the issuer is also surfaced as a query parameter
// so non-compliant apps still display it correctly.
func buildOTPAuthURL(issuer, email, secretB32 string) string {
	label := url.PathEscape(issuer + ":" + email)
	q := url.Values{}
	q.Set("secret", secretB32)
	q.Set("issuer", issuer)
	q.Set("algorithm", "SHA1")
	q.Set("digits", strconv.Itoa(TOTPDigits))
	q.Set("period", strconv.Itoa(TOTPPeriodSeconds))
	return "otpauth://totp/" + label + "?" + q.Encode()
}
