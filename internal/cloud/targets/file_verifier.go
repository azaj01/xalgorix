// Copyright (c) Xalgorix.
// SPDX-License-Identifier: AGPL-3.0-only

package targets

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// MaxFileVerifierBodyBytes caps the body read from the well-known endpoint
// during file-method ownership verification. Pinned by task 7.3 (and the
// design row "VerifyFile") at 256 KiB. The cap protects Cloud_Platform
// memory from a hostile target that streams an unbounded response.
const MaxFileVerifierBodyBytes = 256 * 1024

// DefaultFileVerifierTimeout is the total request timeout (dial + TLS +
// headers + body read) applied to the well-known fetch. Pinned by task 7.3
// at 5 seconds.
const DefaultFileVerifierTimeout = 5 * time.Second

// fileVerifierPath is the .well-known location specified by the design
// document ("internal/cloud/targets" → VerifyFile): customers place the
// IssueToken-issued token at https://{host}/.well-known/xalgorix-verification.txt.
const fileVerifierPath = "/.well-known/xalgorix-verification.txt"

// fileVerifierUserAgent identifies Cloud_Platform verification probes in
// customer access logs so Owners can audit who fetched the token file.
const fileVerifierUserAgent = "Xalgorix-Verifier/1.0 (+https://xalgorix.com)"

// maxFileVerifierRedirects bounds redirect chasing. Even within the same
// hostname an attacker who controls a path on the Target could otherwise
// loop us through many redirects to keep a connection open longer than
// the 5-second timeout would naively allow.
const maxFileVerifierRedirects = 5

// FileVerifier proves ownership of a Target by fetching a token file from
// https://{host}/.well-known/xalgorix-verification.txt and matching its
// contents (after trimming surrounding whitespace) against the
// IssueToken-issued token for that Target.
//
// Implements Requirement 7.2 (file-upload verification method) and
// Requirement 7.4 (the chosen check is performed from Cloud_Platform
// infrastructure).
//
// FileVerifier is safe for concurrent use as long as Client is.
type FileVerifier struct {
	// Client performs the GET. Callers may inject a custom *http.Client
	// to wire OTel instrumentation, custom dialers, or a test transport
	// that trusts an httptest TLS certificate. A nil Client falls back
	// to a default 5-second-timeout client with same-hostname redirect
	// enforcement.
	Client *http.Client
}

// NewFileVerifier returns a FileVerifier configured with the default
// 5-second timeout and same-hostname redirect policy.
func NewFileVerifier() *FileVerifier {
	return &FileVerifier{Client: defaultFileVerifierClient()}
}

// defaultFileVerifierClient builds the *http.Client used when no client is
// injected. Kept on its own so tests can wire an equivalent client around
// a custom Transport while keeping the timeout and redirect policy in one
// place.
func defaultFileVerifierClient() *http.Client {
	return &http.Client{
		Timeout:       DefaultFileVerifierTimeout,
		CheckRedirect: sameHostnameRedirectPolicy,
	}
}

// sameHostnameRedirectPolicy refuses to follow a redirect whose target
// hostname differs from the original request's hostname or whose scheme
// is not HTTPS, and bounds the redirect chain length. It returns
// http.ErrUseLastResponse so callers observe the 30x status and classify
// it as non-200 (i.e. (false, nil)). Requirement 7.4 pins the fetch to
// the customer's hostname; following a cross-host redirect could
// otherwise let an attacker satisfy the ownership check via a third-party
// domain they happen to control.
func sameHostnameRedirectPolicy(req *http.Request, via []*http.Request) error {
	if len(via) == 0 {
		return nil
	}
	if len(via) >= maxFileVerifierRedirects {
		return http.ErrUseLastResponse
	}
	if !strings.EqualFold(req.URL.Scheme, "https") {
		return http.ErrUseLastResponse
	}
	if !strings.EqualFold(req.URL.Hostname(), via[0].URL.Hostname()) {
		return http.ErrUseLastResponse
	}
	return nil
}

// Verify fetches the well-known token file for host and reports whether
// its trimmed body equals expectedToken.
//
// expectedToken is the full `xalgorix-site-verification=<32 base32>`
// value previously produced by GenerateVerificationToken; callers supply
// it as-is (no transformation, no extra whitespace).
//
// Behavior pinned by task 7.3:
//   - GET https://{host}/.well-known/xalgorix-verification.txt
//   - 5-second total timeout (provided by the default Client)
//   - Body cap of 256 KiB enforced via io.LimitReader
//   - Trimmed body equality (any leading/trailing whitespace ignored)
//     against expectedToken
//   - Non-200 status returns (false, nil) — verification simply failed,
//     not a transport error
//   - host must be a hostname; bare IP literals are refused outright
//     because the file method requires the customer to control the
//     authoritative origin, which is a DNS concept
//   - Redirects are followed only within the same hostname and only
//     over HTTPS; a cross-host or downgrade redirect is treated as a
//     non-200 response (false, nil)
//
// A non-nil error is returned only for argument-validation failures
// (empty host, empty token, IP-literal host) or transport-level failures
// (DNS, connection refused, TLS handshake failure, deadline exceeded).
// "The file simply did not match" is reported as (false, nil) so callers
// can record a verification attempt without escalating user-recoverable
// states.
func (v *FileVerifier) Verify(ctx context.Context, host, expectedToken string) (bool, error) {
	host = strings.TrimSpace(host)
	if host == "" {
		return false, errors.New("targets: empty host")
	}
	if expectedToken == "" {
		return false, errors.New("targets: empty expected token")
	}
	if err := requireFileVerifierHostname(host); err != nil {
		return false, err
	}

	target := &url.URL{
		Scheme: "https",
		Host:   host,
		Path:   fileVerifierPath,
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
	if err != nil {
		return false, fmt.Errorf("targets: build well-known request: %w", err)
	}
	req.Header.Set("User-Agent", fileVerifierUserAgent)
	req.Header.Set("Accept", "text/plain, */*;q=0.1")
	// We are an unauthenticated, side-effect-free probe; explicitly
	// refuse any cookies the server might try to set so a Set-Cookie
	// loop cannot accumulate state across retries.
	req.Header.Set("Cache-Control", "no-cache")

	client := v.Client
	if client == nil {
		client = defaultFileVerifierClient()
	}

	resp, err := client.Do(req)
	if err != nil {
		return false, fmt.Errorf("targets: fetch well-known token: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return false, nil
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxFileVerifierBodyBytes))
	if err != nil {
		return false, fmt.Errorf("targets: read well-known body: %w", err)
	}

	return strings.TrimSpace(string(body)) == expectedToken, nil
}

// requireFileVerifierHostname rejects host strings that are bare IP
// literals (with or without a port) or that smuggle a scheme/path. The
// file verifier is pinned to hostname-based fetches because:
//   - the .well-known method requires the customer to control the
//     authoritative DNS origin, which is meaningless for a raw IP;
//   - presenting a TLS certificate for an IP would force us to relax
//     server-name verification, which we never want to do here.
func requireFileVerifierHostname(host string) error {
	h := host
	if hh, _, err := net.SplitHostPort(host); err == nil {
		h = hh
	} else if len(host) >= 2 && host[0] == '[' && host[len(host)-1] == ']' {
		// Bare bracketed IPv6 literal with no port, e.g. "[::1]".
		h = host[1 : len(host)-1]
	}
	if strings.ContainsAny(h, "/?# \t\r\n") {
		return fmt.Errorf("targets: host %q must not include scheme, path, or whitespace", host)
	}
	if net.ParseIP(h) != nil {
		return fmt.Errorf("targets: host %q is an IP literal; file verification requires a hostname", host)
	}
	return nil
}
