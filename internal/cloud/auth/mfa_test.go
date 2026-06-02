package auth

import (
	"context"
	"crypto/hmac"
	"crypto/sha1" //nolint:gosec // RFC 6238 specifies HMAC-SHA1 for TOTP
	"encoding/base32"
	"errors"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeMFARepo is an in-memory MFARepo used for unit tests. It is
// goroutine-safe so tests can exercise concurrent verify paths if
// they choose; today only the single-goroutine paths are covered.
type fakeMFARepo struct {
	mu       sync.Mutex
	emails   map[string]string
	secrets  map[string][]byte
	recovery map[string][]string

	saveErr      error
	loadErr      error
	updateErr    error
	emailErr     error
	loadNotFound bool
}

func newFakeRepo() *fakeMFARepo {
	return &fakeMFARepo{
		emails:   map[string]string{},
		secrets:  map[string][]byte{},
		recovery: map[string][]string{},
	}
}

func (r *fakeMFARepo) AccountEmail(_ context.Context, accountID string) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.emailErr != nil {
		return "", r.emailErr
	}
	email, ok := r.emails[accountID]
	if !ok {
		return "", errors.New("account not found")
	}
	return email, nil
}

func (r *fakeMFARepo) SaveMFA(_ context.Context, accountID string, totpSecretEnc []byte, recoveryHashes []string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.saveErr != nil {
		return r.saveErr
	}
	r.secrets[accountID] = append([]byte(nil), totpSecretEnc...)
	r.recovery[accountID] = append([]string(nil), recoveryHashes...)
	return nil
}

func (r *fakeMFARepo) LoadMFA(_ context.Context, accountID string) ([]byte, []string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.loadErr != nil {
		return nil, nil, r.loadErr
	}
	if r.loadNotFound {
		return nil, nil, ErrMFANotEnabled
	}
	enc, ok := r.secrets[accountID]
	if !ok {
		return nil, nil, ErrMFANotEnabled
	}
	return append([]byte(nil), enc...), append([]string(nil), r.recovery[accountID]...), nil
}

func (r *fakeMFARepo) UpdateRecoveryHashes(_ context.Context, accountID string, recoveryHashes []string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.updateErr != nil {
		return r.updateErr
	}
	r.recovery[accountID] = append([]string(nil), recoveryHashes...)
	return nil
}

// mfaHMACKey returns a fixed 32-byte HMAC key. Tests share a constant
// key so recovery-code hashes are deterministic across runs.
func mfaHMACKey() []byte {
	k := make([]byte, 32)
	for i := range k {
		k[i] = byte(i + 7)
	}
	return k
}

// newTestMFAService stitches together the fake repo, the identity
// envelope, and a deterministic clock so timing-sensitive tests can
// pin the TOTP step without sleeping.
func newTestMFAService(t *testing.T, repo *fakeMFARepo) (*MFAService, func(time.Time)) {
	t.Helper()
	svc := NewMFAService(repo, IdentityEnvelope{}, mfaHMACKey())
	current := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	svc.now = func() time.Time { return current }
	return svc, func(tm time.Time) { current = tm }
}

// TestEnableTOTPGeneratesArtifacts asserts the enable flow: the
// returned secret is a valid 32-character base32 string, the URL is
// parseable and carries the expected query parameters, and exactly
// ten recovery codes are produced and persisted.
func TestEnableTOTPGeneratesArtifacts(t *testing.T) {
	t.Parallel()
	repo := newFakeRepo()
	repo.emails["acc-1"] = "alice@example.com"
	svc, _ := newTestMFAService(t, repo)

	secretB32, otpURL, codes, err := svc.EnableTOTP(context.Background(), "acc-1")
	if err != nil {
		t.Fatalf("EnableTOTP: %v", err)
	}

	// Secret must round-trip through base32 to TOTPSecretBytes raw bytes.
	raw, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secretB32)
	if err != nil {
		t.Fatalf("base32 decode: %v", err)
	}
	if len(raw) != TOTPSecretBytes {
		t.Fatalf("secret length = %d, want %d", len(raw), TOTPSecretBytes)
	}

	// otpauth URL: scheme/host/path/query.
	u, err := url.Parse(otpURL)
	if err != nil {
		t.Fatalf("parse otpauth url: %v", err)
	}
	if u.Scheme != "otpauth" || u.Host != "totp" {
		t.Fatalf("otpauth url scheme/host = %q/%q", u.Scheme, u.Host)
	}
	if got := u.Query().Get("secret"); got != secretB32 {
		t.Fatalf("otpauth secret = %q, want %q", got, secretB32)
	}
	if got := u.Query().Get("issuer"); got != TOTPIssuer {
		t.Fatalf("otpauth issuer = %q, want %q", got, TOTPIssuer)
	}
	if got := u.Query().Get("digits"); got != "6" {
		t.Fatalf("otpauth digits = %q, want \"6\"", got)
	}
	if got := u.Query().Get("period"); got != "30" {
		t.Fatalf("otpauth period = %q, want \"30\"", got)
	}
	// Path includes "Xalgorix:alice@example.com" per the Key URI spec.
	if !strings.Contains(u.Path, "Xalgorix") || !strings.Contains(u.Path, "alice@example.com") {
		t.Fatalf("otpauth label missing issuer/email: %q", u.Path)
	}

	// Recovery codes: exactly RecoveryCodeCount, each
	// RecoveryCodeLength characters drawn from recoveryAlphabet, and
	// every code unique.
	if len(codes) != RecoveryCodeCount {
		t.Fatalf("recovery codes length = %d, want %d", len(codes), RecoveryCodeCount)
	}
	seen := map[string]struct{}{}
	for i, c := range codes {
		if len(c) != RecoveryCodeLength {
			t.Fatalf("code %d length = %d, want %d", i, len(c), RecoveryCodeLength)
		}
		for _, r := range c {
			if !strings.ContainsRune(recoveryAlphabet, r) {
				t.Fatalf("code %d contains out-of-alphabet rune %q", i, r)
			}
		}
		if _, dup := seen[c]; dup {
			t.Fatalf("duplicate recovery code at index %d", i)
		}
		seen[c] = struct{}{}
	}

	// Repo must hold the encrypted secret (identity envelope: same
	// bytes as raw) and exactly RecoveryCodeCount HMAC hashes.
	if got := repo.secrets["acc-1"]; len(got) != TOTPSecretBytes {
		t.Fatalf("stored secret length = %d, want %d", len(got), TOTPSecretBytes)
	}
	if got := repo.recovery["acc-1"]; len(got) != RecoveryCodeCount {
		t.Fatalf("stored recovery hashes length = %d, want %d", len(got), RecoveryCodeCount)
	}
}

// TestVerifyTOTPKnownTimestep proves VerifyTOTP accepts the code an
// authenticator app would compute for the *current* TOTP step. This
// is the canonical happy path and pins the algorithm to RFC 6238.
func TestVerifyTOTPKnownTimestep(t *testing.T) {
	t.Parallel()
	repo := newFakeRepo()
	repo.emails["acc-known"] = "bob@example.com"
	svc, setNow := newTestMFAService(t, repo)

	_, _, _, err := svc.EnableTOTP(context.Background(), "acc-known")
	if err != nil {
		t.Fatalf("EnableTOTP: %v", err)
	}

	// Pick a deterministic time inside one TOTP step, then compute
	// the expected code with an independent reimplementation so a
	// regression in hotp() cannot mask the bug.
	fixed := time.Date(2025, 4, 1, 12, 34, 56, 0, time.UTC)
	setNow(fixed)
	step := uint64(fixed.Unix() / int64(TOTPPeriodSeconds))

	want := computeExpectedHOTP(t, repo.secrets["acc-known"], step)

	ok, err := svc.VerifyTOTP(context.Background(), "acc-known", want)
	if err != nil {
		t.Fatalf("VerifyTOTP: %v", err)
	}
	if !ok {
		t.Fatalf("VerifyTOTP returned false for the current step code %q", want)
	}
}

// TestVerifyTOTPWindowTolerance asserts the ±1 step tolerance: codes
// from the previous and next 30-second windows are accepted, while
// codes from ±2 are rejected.
func TestVerifyTOTPWindowTolerance(t *testing.T) {
	t.Parallel()
	repo := newFakeRepo()
	repo.emails["acc-window"] = "carol@example.com"
	svc, setNow := newTestMFAService(t, repo)

	if _, _, _, err := svc.EnableTOTP(context.Background(), "acc-window"); err != nil {
		t.Fatalf("EnableTOTP: %v", err)
	}

	fixed := time.Date(2025, 5, 15, 8, 0, 0, 0, time.UTC)
	setNow(fixed)
	step := uint64(fixed.Unix() / int64(TOTPPeriodSeconds))
	secret := repo.secrets["acc-window"]

	cases := []struct {
		name    string
		offset  int64
		wantOK  bool
		reason  string
	}{
		{"previous window", -1, true, "±1 tolerance must accept t-1"},
		{"current window", 0, true, "current step must always verify"},
		{"next window", 1, true, "±1 tolerance must accept t+1"},
		{"two steps behind", -2, false, "drift beyond ±1 must be rejected"},
		{"two steps ahead", 2, false, "drift beyond ±1 must be rejected"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			code := computeExpectedHOTP(t, secret, step+uint64(tc.offset)) //nolint:gosec // intentional signed/unsigned add
			ok, err := svc.VerifyTOTP(context.Background(), "acc-window", code)
			if err != nil {
				t.Fatalf("VerifyTOTP: %v", err)
			}
			if ok != tc.wantOK {
				t.Fatalf("offset %d: VerifyTOTP = %v, want %v (%s)", tc.offset, ok, tc.wantOK, tc.reason)
			}
		})
	}
}

// TestVerifyTOTPRejectsMalformedCodes documents that VerifyTOTP
// returns (false, nil) — not an error — when the supplied code is
// not 6 digits. This keeps the caller's "wrong code" path uniform.
func TestVerifyTOTPRejectsMalformedCodes(t *testing.T) {
	t.Parallel()
	repo := newFakeRepo()
	repo.emails["acc-mal"] = "dave@example.com"
	svc, _ := newTestMFAService(t, repo)
	if _, _, _, err := svc.EnableTOTP(context.Background(), "acc-mal"); err != nil {
		t.Fatalf("EnableTOTP: %v", err)
	}

	for _, bad := range []string{"", "abc123", "12345", "1234567", "12345a"} {
		ok, err := svc.VerifyTOTP(context.Background(), "acc-mal", bad)
		if err != nil {
			t.Fatalf("VerifyTOTP(%q) error = %v, want nil", bad, err)
		}
		if ok {
			t.Fatalf("VerifyTOTP(%q) returned true; want false", bad)
		}
	}
}

// TestVerifyTOTPSurfacesNotEnabled asserts that an account without an
// account_mfa row produces ErrMFANotEnabled rather than a silent false.
func TestVerifyTOTPSurfacesNotEnabled(t *testing.T) {
	t.Parallel()
	repo := newFakeRepo()
	svc, _ := newTestMFAService(t, repo)
	_, err := svc.VerifyTOTP(context.Background(), "acc-missing", "123456")
	if !errors.Is(err, ErrMFANotEnabled) {
		t.Fatalf("VerifyTOTP error = %v, want ErrMFANotEnabled", err)
	}
}

// TestConsumeRecoverySingleUse exercises the core recovery-code
// invariant: a code that matches once is consumed, and a second
// attempt with the same code fails because the hash was removed.
func TestConsumeRecoverySingleUse(t *testing.T) {
	t.Parallel()
	repo := newFakeRepo()
	repo.emails["acc-rec"] = "erin@example.com"
	svc, _ := newTestMFAService(t, repo)

	_, _, codes, err := svc.EnableTOTP(context.Background(), "acc-rec")
	if err != nil {
		t.Fatalf("EnableTOTP: %v", err)
	}
	if len(codes) != RecoveryCodeCount {
		t.Fatalf("expected %d codes, got %d", RecoveryCodeCount, len(codes))
	}

	target := codes[3]

	ok, err := svc.ConsumeRecovery(context.Background(), "acc-rec", target)
	if err != nil {
		t.Fatalf("ConsumeRecovery: %v", err)
	}
	if !ok {
		t.Fatalf("ConsumeRecovery returned false for a valid code")
	}
	if got := len(repo.recovery["acc-rec"]); got != RecoveryCodeCount-1 {
		t.Fatalf("post-consume recovery hash count = %d, want %d", got, RecoveryCodeCount-1)
	}

	// Replaying the same code must fail.
	ok, err = svc.ConsumeRecovery(context.Background(), "acc-rec", target)
	if err != nil {
		t.Fatalf("second ConsumeRecovery: %v", err)
	}
	if ok {
		t.Fatalf("second ConsumeRecovery returned true; recovery codes must be single-use")
	}

	// Other codes are still consumable.
	ok, err = svc.ConsumeRecovery(context.Background(), "acc-rec", codes[0])
	if err != nil {
		t.Fatalf("ConsumeRecovery[0]: %v", err)
	}
	if !ok {
		t.Fatalf("ConsumeRecovery[0] returned false; siblings of a consumed code must still verify")
	}
}

// TestConsumeRecoveryNormalizesInput documents that whitespace,
// hyphens, and case differences are tolerated so users can transcribe
// codes from a printed list without a verbatim match.
func TestConsumeRecoveryNormalizesInput(t *testing.T) {
	t.Parallel()
	repo := newFakeRepo()
	repo.emails["acc-norm"] = "frank@example.com"
	svc, _ := newTestMFAService(t, repo)
	_, _, codes, err := svc.EnableTOTP(context.Background(), "acc-norm")
	if err != nil {
		t.Fatalf("EnableTOTP: %v", err)
	}

	original := codes[5]
	// Insert a hyphen mid-string and lowercase the result.
	mangled := strings.ToLower(original[:4] + "-" + original[4:8] + " " + original[8:])

	ok, err := svc.ConsumeRecovery(context.Background(), "acc-norm", mangled)
	if err != nil {
		t.Fatalf("ConsumeRecovery: %v", err)
	}
	if !ok {
		t.Fatalf("ConsumeRecovery rejected normalized variant %q of %q", mangled, original)
	}
}

// TestConsumeRecoveryRejectsUnknown asserts a syntactically valid but
// never-issued code returns (false, nil) without error.
func TestConsumeRecoveryRejectsUnknown(t *testing.T) {
	t.Parallel()
	repo := newFakeRepo()
	repo.emails["acc-unk"] = "gus@example.com"
	svc, _ := newTestMFAService(t, repo)
	if _, _, _, err := svc.EnableTOTP(context.Background(), "acc-unk"); err != nil {
		t.Fatalf("EnableTOTP: %v", err)
	}

	bogus := strings.Repeat("A", RecoveryCodeLength)
	ok, err := svc.ConsumeRecovery(context.Background(), "acc-unk", bogus)
	if err != nil {
		t.Fatalf("ConsumeRecovery: %v", err)
	}
	if ok {
		t.Fatalf("ConsumeRecovery accepted a code that was never issued")
	}
	if got := len(repo.recovery["acc-unk"]); got != RecoveryCodeCount {
		t.Fatalf("recovery list mutated on miss: got %d entries", got)
	}
}

// TestConsumeRecoverySurfacesNotEnabled mirrors VerifyTOTP's contract.
func TestConsumeRecoverySurfacesNotEnabled(t *testing.T) {
	t.Parallel()
	repo := newFakeRepo()
	svc, _ := newTestMFAService(t, repo)
	_, err := svc.ConsumeRecovery(context.Background(), "acc-missing", strings.Repeat("A", RecoveryCodeLength))
	if !errors.Is(err, ErrMFANotEnabled) {
		t.Fatalf("ConsumeRecovery error = %v, want ErrMFANotEnabled", err)
	}
}

// TestNewMFAServicePanicsOnBadInputs documents the constructor's
// boot-time validation: nil repo, nil envelope, and short HMAC key
// each panic.
func TestNewMFAServicePanicsOnBadInputs(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		fn   func()
	}{
		{"nil repo", func() { NewMFAService(nil, IdentityEnvelope{}, mfaHMACKey()) }},
		{"nil envelope", func() { NewMFAService(newFakeRepo(), nil, mfaHMACKey()) }},
		{"short key", func() { NewMFAService(newFakeRepo(), IdentityEnvelope{}, []byte("too-short")) }},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			defer func() {
				if r := recover(); r == nil {
					t.Fatalf("expected panic for %s", tc.name)
				}
			}()
			tc.fn()
		})
	}
}

// computeExpectedHOTP is an independent RFC 4226 reimplementation
// used to cross-check VerifyTOTP. Keeping this helper out of the
// production package guards against the test accidentally validating
// itself.
func computeExpectedHOTP(t *testing.T, secret []byte, counter uint64) string {
	t.Helper()
	var buf [8]byte
	for i := 7; i >= 0; i-- {
		buf[i] = byte(counter & 0xff)
		counter >>= 8
	}
	mac := hmac.New(sha1.New, secret)
	mac.Write(buf[:])
	sum := mac.Sum(nil)
	offset := int(sum[len(sum)-1] & 0x0f)
	value := (uint32(sum[offset]&0x7f) << 24) |
		(uint32(sum[offset+1]) << 16) |
		(uint32(sum[offset+2]) << 8) |
		uint32(sum[offset+3])
	mod := uint32(1)
	for i := 0; i < TOTPDigits; i++ {
		mod *= 10
	}
	code := value % mod
	// Match production zero-padding.
	out := make([]byte, TOTPDigits)
	for i := TOTPDigits - 1; i >= 0; i-- {
		out[i] = byte('0' + code%10)
		code /= 10
	}
	return string(out)
}
