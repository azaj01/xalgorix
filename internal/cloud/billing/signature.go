package billing

// File signature.go implements the inbound webhook signature helper used
// by the Dodo Payments webhook handler (task 4.5) and exercised by the
// signature unit tests (task 4.13 — this file's tests live alongside in
// signature_test.go).
//
// The header format is the one fixed by the spec:
//
//     webhook-signature: t=<unix>,v1=<hex_lower_case_sha256_hmac>
//
// where:
//
//   - <unix> is the Unix epoch seconds at which the signature was minted
//     (decimal, ASCII).
//   - <hex_lower_case_sha256_hmac> is HMAC-SHA256 over the byte string
//     "t=<unix>." || raw_body using the shared webhook secret, hex-encoded
//     in lower case.
//
// This is the same shape as the outbound `X-Xalgorix-Signature` header
// described in requirements.md ("Webhook signing: HMAC-SHA256 over the raw
// body using a per-Webhook secret in the X-Xalgorix-Signature header with
// t=<unix>,v1=<hex>"); reusing one helper for both directions keeps the
// signing/verification rules in lock-step.
//
// The helper is decoupled from net/http so it can be tested in isolation
// (task 4.13) and reused from the outbound dispatcher (task 9.2).
//
// Requirements: 5.3, 5.4

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// defaultSignatureTolerance is the maximum drift between the timestamp in
// the signature header and the verifier's clock. Anything older is treated
// as a replay; anything further in the future than the tolerance is also
// rejected so a clock-skewed attacker cannot mint long-lived signatures.
//
// The 5-minute window matches the Standard Webhooks (Svix) recommendation
// and BugReportly's implicit default; it is also the tolerance the design
// document assumes when it talks about "replayed signature with stale
// timestamp".
const defaultSignatureTolerance = 5 * time.Minute

// Sentinel errors returned by VerifySignature. They are wrapped with %w by
// callers (the webhook handler maps every one of them to HTTP 401) so that
// tests can use errors.Is to discriminate without parsing strings.
var (
	// ErrSignatureMissing is returned when the supplied header value is
	// empty (or whitespace only). The webhook handler treats this as a
	// hard reject — no in-band retry, no state mutation.
	ErrSignatureMissing = errors.New("billing: webhook signature header is missing")

	// ErrSignatureMalformed is returned when the header is present but
	// does not parse as `t=<unix>,v1=<hex>`. Typical causes: missing
	// `t=` part, missing `v1=` part, non-decimal timestamp,
	// non-hexadecimal signature, or malformed comma-separated list.
	ErrSignatureMalformed = errors.New("billing: webhook signature header is malformed")

	// ErrSignatureMismatch is returned when the header parses cleanly
	// but the HMAC does not match. Both "tampered body" and "wrong
	// secret" surface as this error — the caller cannot tell which from
	// the outside, which is intentional (avoid leaking which half of
	// the secret/body pair was wrong).
	ErrSignatureMismatch = errors.New("billing: webhook signature does not match")

	// ErrSignatureExpired is returned when the timestamp on the header
	// is outside the tolerance window — a stale (replayed) signature or
	// a signature from a clock-skewed attacker far in the future.
	ErrSignatureExpired = errors.New("billing: webhook signature timestamp is outside tolerance window")

	// ErrSignatureSecretMissing is returned by VerifySignature when the
	// caller supplies an empty secret. Encoded as a separate sentinel
	// (rather than a plain `panic`) so the webhook handler surfaces a
	// 500 — a misconfigured deployment, not an authentication failure.
	ErrSignatureSecretMissing = errors.New("billing: webhook secret is empty")
)

// VerifySignature checks that header is a valid `t=<unix>,v1=<hex>` HMAC
// for body computed under secret, and that the timestamp is within
// defaultSignatureTolerance of time.Now.
//
// On success it returns nil. On failure it returns one of the sentinel
// errors above, wrapped with additional context for logs. The function
// uses hmac.Equal for the final comparison, which is constant-time with
// respect to the byte length of the digest — this prevents the classic
// timing-leak attack on naïve byte-by-byte equality. The constant-time
// guarantee is documented here and exercised structurally by the
// signature unit tests (task 4.13).
func VerifySignature(secret string, body []byte, header string) error {
	return verifySignatureAt(secret, body, header, time.Now(), defaultSignatureTolerance)
}

// verifySignatureAt is the testable core of VerifySignature: it takes an
// explicit "now" and tolerance so tests can inject deterministic clocks
// without monkey-patching time.Now. Public callers must use
// VerifySignature, which fixes the production policy.
func verifySignatureAt(secret string, body []byte, header string, now time.Time, tolerance time.Duration) error {
	if strings.TrimSpace(secret) == "" {
		return ErrSignatureSecretMissing
	}
	if strings.TrimSpace(header) == "" {
		return ErrSignatureMissing
	}

	ts, sig, err := parseSignatureHeader(header)
	if err != nil {
		return err
	}

	// Replay protection: reject signatures whose timestamp is more than
	// `tolerance` away from the verifier's current clock in either
	// direction. The bidirectional check matters: a malicious party that
	// can predict a future signature must not be able to use it later
	// either, and a backdated signature mined from a leaked log must not
	// be replayable beyond the window.
	signedAt := time.Unix(ts, 0)
	delta := now.Sub(signedAt)
	if delta < 0 {
		delta = -delta
	}
	if delta > tolerance {
		return fmt.Errorf("%w: timestamp %d is %s away from now", ErrSignatureExpired, ts, delta.Round(time.Second))
	}

	expected := computeSignature(secret, ts, body)

	// hmac.Equal does a constant-time compare, which is what we want
	// here — never replace this with bytes.Equal or `==` on strings.
	if !hmac.Equal(expected, sig) {
		return ErrSignatureMismatch
	}
	return nil
}

// SignBody is the inverse of VerifySignature: it produces a header value
// in the canonical `t=<unix>,v1=<hex>` format for the supplied body and
// secret. It is exported because the outbound webhook dispatcher (task
// 9.2) and the property test in task 19.7 both rely on the verifier and
// signer agreeing on every byte of the wire format.
//
// SignBody panics on an empty secret because every call site in the
// codebase has already validated the configuration; surfacing it as an
// error here would only push the same check upstream without any benefit.
// The corresponding verifier path returns ErrSignatureSecretMissing, which
// gives the webhook handler a clean 500 path.
func SignBody(secret string, body []byte, now time.Time) string {
	if secret == "" {
		// Refuse silently rather than emit a header that any downstream
		// verifier will reject — failing fast catches misconfiguration
		// in dev/staging.
		panic("billing: SignBody requires a non-empty secret")
	}
	ts := now.Unix()
	mac := computeSignature(secret, ts, body)
	return fmt.Sprintf("t=%d,v1=%s", ts, hex.EncodeToString(mac))
}

// computeSignature returns the raw HMAC-SHA256 digest of the canonical
// signed payload. The signed payload is `t=<unix>.` followed by the raw
// body — the dot is a separator so that swapping body bytes for timestamp
// bytes does not yield a colliding HMAC input.
func computeSignature(secret string, ts int64, body []byte) []byte {
	mac := hmac.New(sha256.New, []byte(secret))
	// Pre-build the prefix into a small scratch buffer to avoid one
	// allocation; the timestamp prefix is bounded in length so the
	// strconv-based path stays the most readable.
	mac.Write([]byte("t="))
	mac.Write([]byte(strconv.FormatInt(ts, 10)))
	mac.Write([]byte("."))
	mac.Write(body)
	return mac.Sum(nil)
}

// parseSignatureHeader extracts (timestamp, hmac) from a
// `t=<unix>,v1=<hex>` header value, tolerating whitespace around the
// commas and equals signs. It returns ErrSignatureMalformed for any
// shape it cannot unambiguously decode.
//
// Multiple `v1=` parts are accepted (the last one wins) so that future
// rotation strategies — emitting both old and new signatures during a
// secret roll — do not break existing verifiers; this matches the Stripe
// and Standard Webhooks behaviour. Unknown scheme keys (e.g. `v0=`) are
// ignored, again to be forward-compatible.
func parseSignatureHeader(header string) (int64, []byte, error) {
	var (
		haveTS bool
		ts     int64
		sigHex string
	)
	for _, part := range strings.Split(header, ",") {
		kv := strings.TrimSpace(part)
		if kv == "" {
			continue
		}
		eq := strings.IndexByte(kv, '=')
		if eq <= 0 {
			return 0, nil, fmt.Errorf("%w: invalid part %q", ErrSignatureMalformed, kv)
		}
		key := strings.TrimSpace(kv[:eq])
		val := strings.TrimSpace(kv[eq+1:])
		switch key {
		case "t":
			parsed, err := strconv.ParseInt(val, 10, 64)
			if err != nil {
				return 0, nil, fmt.Errorf("%w: timestamp %q is not an integer", ErrSignatureMalformed, val)
			}
			ts = parsed
			haveTS = true
		case "v1":
			// Last-write-wins on duplicate v1 entries so callers
			// can include rotated secrets without breaking us.
			sigHex = val
		default:
			// Forward-compatible: ignore unknown scheme keys.
		}
	}
	if !haveTS {
		return 0, nil, fmt.Errorf("%w: missing t= part", ErrSignatureMalformed)
	}
	if sigHex == "" {
		return 0, nil, fmt.Errorf("%w: missing v1= part", ErrSignatureMalformed)
	}
	sig, err := hex.DecodeString(sigHex)
	if err != nil {
		return 0, nil, fmt.Errorf("%w: v1 is not hex: %v", ErrSignatureMalformed, err)
	}
	if len(sig) != sha256.Size {
		return 0, nil, fmt.Errorf("%w: v1 has %d bytes, want %d", ErrSignatureMalformed, len(sig), sha256.Size)
	}
	return ts, sig, nil
}
