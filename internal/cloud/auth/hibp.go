// HIBP (Have I Been Pwned) k-anonymity password check for the Xalgorix
// Cloud_Platform.
//
// Implements task 2.2 of the xalgorix-saas spec:
//
//   - Pwner is the abstract interface used by the signup and password-reset
//     flows so they can be tested with an in-memory fake.
//   - HTTPPwner is the production implementation that calls the
//     Pwned Passwords range API
//     (https://api.pwnedpasswords.com/range/<sha1[0:5]>) using the
//     k-anonymity model: only the first five hex characters of the
//     SHA-1 of the candidate password leave the process. The remaining
//     35 characters are matched locally against the streamed response
//     body to determine whether the password appears in any breach
//     corpus.
//   - The check is fail-open by design (Requirement 3.3 / Decisions and
//     Defaults). Any timeout, network error, or non-200 response is
//     logged with the structured event "auth_hibp_unavailable" and the
//     password is treated as not pwned. This keeps signup and password
//     reset working when HIBP is degraded; the operational signal is
//     carried entirely in logs and metrics.
//
// Requirements: 3.3
package auth

import (
	"bufio"
	"context"
	"crypto/sha1" //nolint:gosec // SHA-1 prefix is the HIBP k-anonymity protocol; no security claim is made on the digest itself.
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/rs/zerolog"
)

// Defaults for HTTPPwner. Exposed as constants so tests and operators can
// reference the same values that ship in production. The 2-second timeout
// matches the spec verbatim and bounds tail latency on signup.
const (
	// hibpDefaultBaseURL is the production endpoint of the Pwned Passwords
	// range API.
	hibpDefaultBaseURL = "https://api.pwnedpasswords.com"
	// hibpDefaultTimeout is the wall-clock timeout for a single range
	// request, including connect, TLS handshake, headers and body read.
	hibpDefaultTimeout = 2 * time.Second
	// hibpUnavailableEvent is the structured log event name emitted on any
	// fail-open path. Operators alert on its rate.
	hibpUnavailableEvent = "auth_hibp_unavailable"
)

// Pwner reports whether plain appears in a known password breach corpus.
//
// Implementations are expected to fail open: a network error, timeout, or
// non-200 response from the upstream service must surface as (false, nil)
// with a structured warning log line, not as an error returned to the
// caller. Callers therefore never need to distinguish "pwned check failed"
// from "password is clean" — they always proceed to hash and store on a
// false return.
type Pwner interface {
	// Pwned returns true iff plain appears in the upstream breach list.
	// The error return is reserved for programmer errors (for example
	// ctx == nil); transient HTTP failures yield (false, nil).
	Pwned(ctx context.Context, plain string) (bool, error)
}

// HTTPPwner is the production Pwner that talks to the Pwned Passwords
// range API. The zero value is not ready for use; callers should obtain
// an instance via NewHTTPPwner or populate Client and BaseURL explicitly.
//
// Logger is the zerolog logger that fail-open events are written to. It
// must be safely usable concurrently — the standard zerolog.Logger value
// is. When Logger is the zero value the package falls back to the global
// zerolog default (zerolog.Nop in tests, the observability bootstrap in
// production), so a freshly constructed HTTPPwner is safe to use.
type HTTPPwner struct {
	// Client is the HTTP client used for range requests. It must enforce
	// the 2-second total timeout (Requirement 3.3). When nil the package
	// constructs a client with the default timeout on first use.
	Client *http.Client
	// BaseURL is the scheme + host of the Pwned Passwords endpoint. It
	// must not include the trailing "/range" path. When empty it defaults
	// to hibpDefaultBaseURL. Tests inject an httptest.Server URL here.
	BaseURL string
	// Logger receives structured warn events when the upstream is
	// unavailable. The zero value logs to the zerolog default.
	Logger zerolog.Logger
}

// NewHTTPPwner returns an HTTPPwner configured with the production base URL
// and a fresh http.Client whose Timeout matches Requirement 3.3 (2 seconds,
// covering connect through full body read). The supplied logger is used for
// structured fail-open events; pass zerolog.Nop() in tests that do not care
// about log output.
func NewHTTPPwner(logger zerolog.Logger) *HTTPPwner {
	return &HTTPPwner{
		Client:  &http.Client{Timeout: hibpDefaultTimeout},
		BaseURL: hibpDefaultBaseURL,
		Logger:  logger,
	}
}

// errHIBPUnavailable is a sentinel surfaced internally so the single
// fail-open emit point in Pwned can log a uniform warn line regardless of
// which underlying failure mode occurred. It never escapes the package.
var errHIBPUnavailable = errors.New("hibp range endpoint unavailable")

// Pwned implements Pwner against the Pwned Passwords range API.
//
// Protocol summary (k-anonymity, see https://haveibeenpwned.com/API/v3):
//
//  1. SHA-1 the candidate password, hex-encode, and uppercase.
//  2. Split into a 5-character prefix and a 35-character suffix.
//  3. GET {BaseURL}/range/{prefix} with the "Add-Padding: true" header so
//     the response length does not leak prefix popularity.
//  4. Stream the body line by line. Each line is "<SUFFIX>:<COUNT>\r\n".
//     If our suffix appears with a non-zero count the password is pwned.
//
// All failure modes (context cancellation, timeout, DNS error, TLS error,
// non-200 status, malformed body) are logged with the
// "auth_hibp_unavailable" event and converted to a (false, nil) return —
// the documented fail-open behaviour. Programmer-error returns are
// reserved for nil contexts.
func (h *HTTPPwner) Pwned(ctx context.Context, plain string) (bool, error) {
	if ctx == nil {
		return false, errors.New("auth: Pwned requires a non-nil context")
	}

	client := h.Client
	if client == nil {
		client = &http.Client{Timeout: hibpDefaultTimeout}
	}
	base := h.BaseURL
	if base == "" {
		base = hibpDefaultBaseURL
	}
	base = strings.TrimRight(base, "/")

	prefix, suffix := sha1Prefix(plain)
	url := base + "/range/" + prefix

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		h.warnUnavailable(err, prefix, 0)
		return false, nil
	}
	// Add-Padding asks the upstream to pad short responses to a constant
	// length, defeating an otherwise viable prefix-frequency side channel.
	req.Header.Set("Add-Padding", "true")
	// Identifying ourselves is required by the HIBP API terms.
	req.Header.Set("User-Agent", "xalgorix-cloud/1.0 (+https://xalgorix.com)")

	resp, err := client.Do(req)
	if err != nil {
		h.warnUnavailable(err, prefix, 0)
		return false, nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		h.warnUnavailable(fmt.Errorf("%w: status %d", errHIBPUnavailable, resp.StatusCode), prefix, resp.StatusCode)
		// Drain the body within a sensible bound so the underlying
		// connection can be reused; ignore read errors because we are
		// already on the fail-open path.
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
		return false, nil
	}

	pwned, err := scanForSuffix(resp.Body, suffix)
	if err != nil {
		h.warnUnavailable(err, prefix, resp.StatusCode)
		return false, nil
	}
	return pwned, nil
}

// sha1Prefix returns the 5-character uppercase hex prefix and the
// 35-character uppercase hex suffix of the SHA-1 of plain. The split point
// is fixed by the HIBP range API.
func sha1Prefix(plain string) (prefix, suffix string) {
	sum := sha1.Sum([]byte(plain)) //nolint:gosec // see file header.
	hexed := strings.ToUpper(hex.EncodeToString(sum[:]))
	return hexed[:5], hexed[5:]
}

// scanForSuffix streams body line by line looking for "<suffix>:<count>".
// The HIBP API documents lines terminated by "\r\n"; bufio.Scanner trims
// the trailing newline so we strip a remaining "\r" before comparing. A
// match with a strictly positive count returns true; everything else
// returns false. A scanner read error is surfaced so the caller can log
// the fail-open warning with cause attribution.
func scanForSuffix(body io.Reader, suffix string) (bool, error) {
	scanner := bufio.NewScanner(body)
	// HIBP responses can exceed the default 64 KiB scanner buffer when
	// padding is requested; allow up to 1 MiB lines just to be safe.
	scanner.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for scanner.Scan() {
		line := strings.TrimRight(scanner.Text(), "\r")
		colon := strings.IndexByte(line, ':')
		if colon <= 0 {
			continue
		}
		if !strings.EqualFold(line[:colon], suffix) {
			continue
		}
		// We do not parse the count strictly: any non-zero, non-empty
		// trailing token marks the password as pwned. Padding entries
		// are emitted with count=0 by the upstream when padding is on.
		count := strings.TrimSpace(line[colon+1:])
		if count == "" || count == "0" {
			return false, nil
		}
		return true, nil
	}
	if err := scanner.Err(); err != nil {
		return false, err
	}
	return false, nil
}

// warnUnavailable emits the single canonical "auth_hibp_unavailable"
// structured log line. Centralising this keeps every fail-open path
// observably indistinguishable to operators, which matters because the
// alert threshold is on the rate of this event, not on its cause.
func (h *HTTPPwner) warnUnavailable(cause error, prefix string, status int) {
	evt := h.Logger.Warn().
		Str("event", hibpUnavailableEvent).
		Str("prefix", prefix)
	if status > 0 {
		evt = evt.Int("status", status)
	}
	if cause != nil {
		evt = evt.Err(cause)
	}
	evt.Msg("hibp range endpoint unavailable; failing open")
}
