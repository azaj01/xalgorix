// Copyright (c) Xalgorix.
// SPDX-License-Identifier: AGPL-3.0-only

package targets

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// newTLSFixture stands up an httptest.NewTLSServer with the supplied
// handler and returns a FileVerifier wired through an http.Client whose
// transport (a) trusts the server's self-signed certificate and (b)
// redirects every dial to the in-memory server regardless of the
// hostname encoded in the request URL.
//
// Steering this dial-rewrite through the transport — instead of, say,
// passing the test server's host:port directly to FileVerifier.Verify —
// keeps the test inputs realistic: callers pass a regular hostname like
// "verify.example.com", so the same-hostname redirect policy and the
// IP-literal rejection branch get exercised against true hostnames. The
// TLS ServerName tracks the hostname in the request URL so the
// certificate that httptest mints (with SAN entries for "example.com"
// and friends) actually validates.
//
// Returns the verifier and the synthetic hostname callers should pass to
// Verify.
func newTLSFixture(t *testing.T, handler http.Handler) (*FileVerifier, string) {
	t.Helper()

	srv := httptest.NewTLSServer(handler)
	t.Cleanup(srv.Close)

	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())

	srvURL, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("parse httptest URL: %v", err)
	}

	// "example.com" is one of the SAN entries baked into httptest's
	// default certificate, which lets the TLS handshake succeed even
	// though the dialer is talking to 127.0.0.1.
	const fakeHost = "example.com"

	transport := &http.Transport{
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			cfg := &tls.Config{
				RootCAs:    pool,
				ServerName: fakeHost,
			}
			d := &tls.Dialer{Config: cfg}
			return d.DialContext(ctx, network, srvURL.Host)
		},
	}

	client := &http.Client{
		Timeout:       DefaultFileVerifierTimeout,
		Transport:     transport,
		CheckRedirect: sameHostnameRedirectPolicy,
	}

	return &FileVerifier{Client: client}, fakeHost
}

// expectedRequestPath is the path every Verify call must hit. Pinning it
// in one place keeps the per-test handlers from drifting away from the
// design-doc's well-known location.
const expectedRequestPath = "/.well-known/xalgorix-verification.txt"

// TestFileVerifier_MatchingToken covers the happy path: a 200 response
// whose body equals expectedToken (with surrounding whitespace) is
// reported as verified.
func TestFileVerifier_MatchingToken(t *testing.T) {
	t.Parallel()

	const token = "xalgorix-site-verification=ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

	cases := []struct {
		name string
		body string
	}{
		{name: "exact match", body: token},
		{name: "trailing newline", body: token + "\n"},
		{name: "leading and trailing whitespace", body: "  \t" + token + "\r\n"},
		{name: "trailing CRLF", body: token + "\r\n"},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var hits atomic.Int32
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				hits.Add(1)
				if r.URL.Path != expectedRequestPath {
					t.Errorf("path = %q, want %q", r.URL.Path, expectedRequestPath)
				}
				if r.Method != http.MethodGet {
					t.Errorf("method = %q, want GET", r.Method)
				}
				w.Header().Set("Content-Type", "text/plain")
				_, _ = w.Write([]byte(tc.body))
			})

			verifier, host := newTLSFixture(t, handler)

			ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
			defer cancel()

			ok, err := verifier.Verify(ctx, host, token)
			if err != nil {
				t.Fatalf("Verify returned error: %v", err)
			}
			if !ok {
				t.Fatalf("Verify returned ok=false; want true")
			}
			if hits.Load() != 1 {
				t.Fatalf("server hit count = %d, want 1", hits.Load())
			}
		})
	}
}

// TestFileVerifier_NonMatchingToken asserts that a 200 with the wrong
// body returns (false, nil). The verifier must distinguish "fetch
// succeeded but contents are wrong" from a transport error.
func TestFileVerifier_NonMatchingToken(t *testing.T) {
	t.Parallel()

	const token = "xalgorix-site-verification=ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

	cases := []struct {
		name string
		body string
	}{
		{name: "different token", body: "xalgorix-site-verification=ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ"},
		{name: "empty body", body: ""},
		{name: "missing prefix", body: "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"},
		{name: "extra characters appended", body: token + "extra"},
		{name: "embedded whitespace breaks token", body: "xalgorix-site-verification= ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte(tc.body))
			})
			verifier, host := newTLSFixture(t, handler)

			ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
			defer cancel()

			ok, err := verifier.Verify(ctx, host, token)
			if err != nil {
				t.Fatalf("Verify returned unexpected error: %v", err)
			}
			if ok {
				t.Fatalf("Verify returned ok=true; want false for body %q", tc.body)
			}
		})
	}
}

// TestFileVerifier_Status404 asserts that a 404 (and any other non-200)
// is reported as a verification failure rather than a transport error.
func TestFileVerifier_Status404(t *testing.T) {
	t.Parallel()

	const token = "xalgorix-site-verification=ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

	cases := []struct {
		name   string
		status int
	}{
		{name: "404 not found", status: http.StatusNotFound},
		{name: "403 forbidden", status: http.StatusForbidden},
		{name: "500 server error", status: http.StatusInternalServerError},
		{name: "204 no content", status: http.StatusNoContent},
		{name: "301 moved permanently with no Location", status: http.StatusMovedPermanently},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.status)
				// Intentionally write the right token in the body to
				// prove that body content does not "rescue" a non-200.
				_, _ = w.Write([]byte(token))
			})
			verifier, host := newTLSFixture(t, handler)

			ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
			defer cancel()

			ok, err := verifier.Verify(ctx, host, token)
			if err != nil {
				t.Fatalf("Verify returned unexpected error: %v", err)
			}
			if ok {
				t.Fatalf("Verify returned ok=true on status %d; want false", tc.status)
			}
		})
	}
}

// TestFileVerifier_BodyCap asserts that a server streaming far more than
// 256 KiB does not cause Verify to over-read or block beyond its
// timeout. The body is a "<token>\n<padding>" pattern: after trimming,
// the token is the first non-whitespace token, but only the first 256
// KiB are read so the comparison is "<token>\n<truncated padding>"
// which must NOT match.
func TestFileVerifier_BodyCap(t *testing.T) {
	t.Parallel()

	const token = "xalgorix-site-verification=ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

	// Generate a body larger than the cap. Use a deterministic
	// non-whitespace pattern so trim() cannot rescue the comparison.
	const oversize = MaxFileVerifierBodyBytes + 4096
	padding := make([]byte, oversize)
	for i := range padding {
		padding[i] = 'A' + byte(i%26)
	}
	body := token + "X" + string(padding) // token immediately followed by junk

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(body)))
		_, _ = w.Write([]byte(body))
	})

	verifier, host := newTLSFixture(t, handler)

	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()

	ok, err := verifier.Verify(ctx, host, token)
	if err != nil {
		t.Fatalf("Verify returned error: %v", err)
	}
	if ok {
		t.Fatalf("Verify returned ok=true on oversized non-matching body; want false")
	}
}

// TestFileVerifier_BodyCap_MatchAtBoundary covers the inverse of the
// previous test: the token sits at the start of the body and the
// remainder is whitespace, then more whitespace beyond the 256 KiB cap.
// Even though only the first 256 KiB are read, the trimmed prefix still
// equals the token, so verification succeeds.
func TestFileVerifier_BodyCap_MatchAtBoundary(t *testing.T) {
	t.Parallel()

	const token = "xalgorix-site-verification=ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

	// token + many bytes of whitespace, total exceeds the cap. After
	// io.LimitReader cuts at 256 KiB, the slice is "<token>\n   ...   "
	// which strings.TrimSpace reduces to the token.
	const oversize = MaxFileVerifierBodyBytes + 1024
	body := make([]byte, oversize)
	copy(body, []byte(token+"\n"))
	for i := len(token) + 1; i < len(body); i++ {
		body[i] = ' '
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(body)
	})

	verifier, host := newTLSFixture(t, handler)

	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()

	ok, err := verifier.Verify(ctx, host, token)
	if err != nil {
		t.Fatalf("Verify returned error: %v", err)
	}
	if !ok {
		t.Fatalf("Verify returned ok=false on whitespace-padded oversize body; want true")
	}
}

// TestFileVerifier_RejectsIPLiteral asserts that the verifier refuses
// bare IP literals up front, with no network attempt. The file method
// requires the customer to control the authoritative origin for a
// hostname.
func TestFileVerifier_RejectsIPLiteral(t *testing.T) {
	t.Parallel()

	cases := []string{
		"127.0.0.1",
		"127.0.0.1:8443",
		"10.0.0.1",
		"::1",
		"[::1]",
		"[::1]:8443",
		"[2001:db8::1]:443",
	}

	verifier := NewFileVerifier()

	for _, host := range cases {
		host := host
		t.Run(host, func(t *testing.T) {
			t.Parallel()
			ok, err := verifier.Verify(context.Background(), host, "xalgorix-site-verification=ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")
			if err == nil {
				t.Fatalf("Verify(%q) returned nil error; want IP-literal rejection", host)
			}
			if ok {
				t.Fatalf("Verify(%q) returned ok=true; want false", host)
			}
			if !strings.Contains(err.Error(), "IP literal") && !strings.Contains(err.Error(), "scheme") {
				t.Fatalf("Verify(%q) error = %v; want IP-literal or hostname-shape rejection", host, err)
			}
		})
	}
}

// TestFileVerifier_RejectsEmptyArgs asserts the early validation
// branches: empty host and empty expected token both yield a non-nil
// error rather than a network attempt.
func TestFileVerifier_RejectsEmptyArgs(t *testing.T) {
	t.Parallel()

	verifier := NewFileVerifier()

	if _, err := verifier.Verify(context.Background(), "", "xalgorix-site-verification=ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"); err == nil {
		t.Fatalf("empty host should error")
	}
	if _, err := verifier.Verify(context.Background(), "example.com", ""); err == nil {
		t.Fatalf("empty token should error")
	}
}
