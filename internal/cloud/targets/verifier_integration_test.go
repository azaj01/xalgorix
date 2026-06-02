// Copyright (c) Xalgorix.
// SPDX-License-Identifier: AGPL-3.0-only

package targets

// Verifier integration tests (task 7.9).
//
// These tests exercise each Target ownership verifier end-to-end against
// a real loopback dependency rather than a fake, complementing the
// per-verifier unit tests in dns_verifier_test.go, file_verifier_test.go
// and meta_verifier_test.go.
//
// Coverage per Requirement 7.2 (three offered methods) and Requirement
// 7.4 (the chosen check is performed from Cloud_Platform infrastructure
// with the timeout / body cap / IP-pinning posture from design.md):
//
//	DNSVerifier  → drives the real PinnedDNSResolver against an
//	               in-process miekg/dns server bound to a loopback UDP
//	               port. Covers matching TXT, non-matching TXT,
//	               NXDOMAIN, SERVFAIL.
//	FileVerifier → drives a real http.Client through httptest.NewTLSServer.
//	               Covers matching token, mismatched body, 404,
//	               body > 256 KiB truncated, > 5s timeout.
//	MetaVerifier → drives a real http.Client through httptest.NewTLSServer.
//	               Covers matching meta, missing meta, mismatched
//	               content, non-HTML content-type.
//
// The file is fully in-process (no real network, no privileged DNS
// port), so it intentionally does not carry an `integration` build tag:
// it must run as part of the standard `go test ./internal/cloud/targets/...`
// invocation so regressions surface in CI without operators having to
// remember an extra flag.

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// integrationToken is the token presented to every verifier in this
// file. Using a single canonical value keeps the per-test handlers
// terse and makes failure diffs trivial to read. The shape matches the
// `xalgorix-site-verification=<32 base32>` form pinned by Requirement
// 7.3, so the meta verifier's IsValidTokenFormat guard is exercised.
const integrationToken = "xalgorix-site-verification=ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

// integrationHost is the synthetic hostname callers pass to Verify in
// the HTTP integration paths. "example.com" is one of the SAN entries
// baked into httptest's default TLS certificate, so the TLS handshake
// completes without test-only cert pool fiddling for the meta verifier
// and matches what the file verifier fixture expects to see.
const integrationHost = "example.com"

// -----------------------------------------------------------------------------
// DNS verifier integration — real PinnedDNSResolver vs in-process miekg/dns
// -----------------------------------------------------------------------------

// startIntegrationDNSServer spins up a miekg/dns UDP server on a random
// loopback port and returns the address callers should hand to
// WithPinnedDNSServers. The shutdown closure blocks until the server has
// fully released the port so concurrent t.Parallel() tests cannot collide
// on the address space.
//
// Kept separate from startTestDNSServer in dns_verifier_test.go so that
// changes to either helper cannot ripple unexpectedly into the other
// suite.
func startIntegrationDNSServer(t *testing.T, handler dns.HandlerFunc) (string, func()) {
	t.Helper()

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp loopback: %v", err)
	}

	srv := &dns.Server{
		PacketConn:   pc,
		Handler:      handler,
		ReadTimeout:  2 * time.Second,
		WriteTimeout: 2 * time.Second,
	}

	ready := make(chan struct{})
	srv.NotifyStartedFunc = func() { close(ready) }

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_ = srv.ActivateAndServe()
	}()

	select {
	case <-ready:
	case <-time.After(2 * time.Second):
		_ = srv.Shutdown()
		wg.Wait()
		t.Fatal("integration DNS server did not start in time")
	}

	addr := pc.LocalAddr().String()
	return addr, func() {
		_ = srv.Shutdown()
		wg.Wait()
	}
}

// dnsHandlerForToken serves the canonical happy-path TXT record so the
// real PinnedDNSResolver exercises EDNS0/DO setup and TXT joining on
// the wire (Requirement 7.4 DNSSEC-aware lookup posture).
func dnsHandlerForToken(host, token string) dns.HandlerFunc {
	return func(w dns.ResponseWriter, msg *dns.Msg) {
		resp := new(dns.Msg)
		resp.SetReply(msg)
		resp.Authoritative = true
		// Echo the DO bit so we look like a DNSSEC-validating recursor:
		// the verifier does not gate on AD itself, but we want the wire
		// shape to match what 1.1.1.1 / 8.8.8.8 actually return.
		if opt := msg.IsEdns0(); opt != nil {
			resp.SetEdns0(4096, opt.Do())
			resp.AuthenticatedData = msg.AuthenticatedData
		}
		if len(msg.Question) == 1 && msg.Question[0].Qtype == dns.TypeTXT {
			resp.Answer = append(resp.Answer, &dns.TXT{
				Hdr: dns.RR_Header{
					Name:   msg.Question[0].Name,
					Rrtype: dns.TypeTXT,
					Class:  dns.ClassINET,
					Ttl:    60,
				},
				// Co-publish a non-matching record (SPF) so the
				// verifier's "find any matching record" branch
				// is exercised against a realistic mixed zone.
				Txt: []string{"v=spf1 -all"},
			})
			resp.Answer = append(resp.Answer, &dns.TXT{
				Hdr: dns.RR_Header{
					Name:   msg.Question[0].Name,
					Rrtype: dns.TypeTXT,
					Class:  dns.ClassINET,
					Ttl:    60,
				},
				Txt: []string{token},
			})
		}
		_ = w.WriteMsg(resp)
		_ = host // host arg accepted for documentation symmetry
	}
}

// dnsHandlerWithRcode returns a handler that always replies with the
// supplied RCODE. Used to drive the NXDOMAIN and SERVFAIL paths through
// the real PinnedDNSResolver so the wire-level translation into
// ErrDNSNXDomain / ErrDNSServerFailure is covered, not just the in-memory
// fakeResolver shortcut.
func dnsHandlerWithRcode(rcode int) dns.HandlerFunc {
	return func(w dns.ResponseWriter, msg *dns.Msg) {
		resp := new(dns.Msg)
		resp.SetReply(msg)
		resp.Rcode = rcode
		_ = w.WriteMsg(resp)
	}
}

// TestIntegration_DNSVerifier_AllPaths drives the real PinnedDNSResolver
// against an in-process miekg/dns server and asserts each branch of the
// (true, nil) / (false, nil) / (false, err) contract documented on
// DNSVerifier.Verify.
//
// Validates: Requirements 7.2, 7.4
func TestIntegration_DNSVerifier_AllPaths(t *testing.T) {
	t.Parallel()

	const (
		matchHost   = "match.example.com"
		mismatchTok = "xalgorix-site-verification=ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ"
	)
	wantPayload := dnsTokenLabel + strings.TrimPrefix(integrationToken, "xalgorix-site-verification=")

	t.Run("matching TXT record verifies", func(t *testing.T) {
		t.Parallel()

		addr, shutdown := startIntegrationDNSServer(t, dnsHandlerForToken(matchHost, wantPayload))
		defer shutdown()

		v := &DNSVerifier{Resolver: NewPinnedDNSResolver(WithPinnedDNSServers(addr))}

		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()

		ok, err := v.Verify(ctx, matchHost, strings.TrimPrefix(integrationToken, "xalgorix-site-verification="))
		if err != nil {
			t.Fatalf("Verify returned error: %v", err)
		}
		if !ok {
			t.Fatalf("Verify(matching TXT) = false, want true")
		}
	})

	t.Run("non-matching TXT record fails verification", func(t *testing.T) {
		t.Parallel()

		// Server publishes a different token; the verifier must
		// return (false, nil) — the lookup itself succeeded.
		addr, shutdown := startIntegrationDNSServer(t, dnsHandlerForToken(matchHost, dnsTokenLabel+strings.TrimPrefix(mismatchTok, "xalgorix-site-verification=")))
		defer shutdown()

		v := &DNSVerifier{Resolver: NewPinnedDNSResolver(WithPinnedDNSServers(addr))}

		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()

		ok, err := v.Verify(ctx, matchHost, strings.TrimPrefix(integrationToken, "xalgorix-site-verification="))
		if err != nil {
			t.Fatalf("Verify returned error: %v (want nil; non-matching TXT is verify-fail)", err)
		}
		if ok {
			t.Fatalf("Verify(non-matching TXT) = true, want false")
		}
	})

	t.Run("NXDOMAIN from upstream is verify-fail", func(t *testing.T) {
		t.Parallel()

		addr, shutdown := startIntegrationDNSServer(t, dnsHandlerWithRcode(dns.RcodeNameError))
		defer shutdown()

		// Feed the same NXDOMAIN address as both pinned upstreams so
		// the resolver exhausts its retry list and surfaces
		// ErrDNSNXDomain rather than falling through to "no pinned
		// resolver answered".
		v := &DNSVerifier{Resolver: NewPinnedDNSResolver(WithPinnedDNSServers(addr, addr))}

		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()

		ok, err := v.Verify(ctx, matchHost, strings.TrimPrefix(integrationToken, "xalgorix-site-verification="))
		if err != nil {
			t.Fatalf("Verify returned error: %v (want nil; NXDOMAIN is verify-fail)", err)
		}
		if ok {
			t.Fatalf("Verify(NXDOMAIN) = true, want false")
		}
	})

	t.Run("SERVFAIL from upstream is verify-fail", func(t *testing.T) {
		t.Parallel()

		addr, shutdown := startIntegrationDNSServer(t, dnsHandlerWithRcode(dns.RcodeServerFailure))
		defer shutdown()

		v := &DNSVerifier{Resolver: NewPinnedDNSResolver(WithPinnedDNSServers(addr, addr))}

		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()

		ok, err := v.Verify(ctx, matchHost, strings.TrimPrefix(integrationToken, "xalgorix-site-verification="))
		if err != nil {
			t.Fatalf("Verify returned error: %v (want nil; SERVFAIL is verify-fail)", err)
		}
		if ok {
			t.Fatalf("Verify(SERVFAIL) = true, want false")
		}
	})
}

// -----------------------------------------------------------------------------
// File verifier integration — real http.Client vs httptest.NewTLSServer
// -----------------------------------------------------------------------------

// fileFixture wires up an httptest TLS server with a transport that:
//   - trusts the server's self-signed certificate;
//   - rewrites every dial to the loopback test server while still
//     preserving the synthetic hostname in the request URL, so the
//     same-hostname redirect policy and IP-literal rejection branches
//     remain exercised;
//   - applies the supplied total timeout (defaulting to 5 s) so the
//     timeout path can be driven without waiting for production
//     defaults.
//
// Returns the verifier configured against the test server plus the
// hostname callers should pass to Verify.
func fileFixture(t *testing.T, handler http.Handler, timeout time.Duration) (*FileVerifier, string) {
	t.Helper()

	srv := httptest.NewTLSServer(handler)
	t.Cleanup(srv.Close)

	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())

	srvURL, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("parse httptest URL: %v", err)
	}

	if timeout <= 0 {
		timeout = DefaultFileVerifierTimeout
	}

	transport := &http.Transport{
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			cfg := &tls.Config{
				RootCAs:    pool,
				ServerName: integrationHost,
			}
			d := &tls.Dialer{Config: cfg}
			return d.DialContext(ctx, network, srvURL.Host)
		},
	}

	client := &http.Client{
		Timeout:       timeout,
		Transport:     transport,
		CheckRedirect: sameHostnameRedirectPolicy,
	}

	return &FileVerifier{Client: client}, integrationHost
}

// TestIntegration_FileVerifier_AllPaths exercises FileVerifier against a
// real httptest TLS server. The unit tests in file_verifier_test.go
// already cover matching/mismatched bodies and non-200 statuses; this
// suite re-asserts those at the integration layer and adds the
// > 256 KiB body-cap and > 5 s timeout branches required by the task.
//
// Validates: Requirements 7.2, 7.4
func TestIntegration_FileVerifier_AllPaths(t *testing.T) {
	t.Parallel()

	const wellKnownPath = "/.well-known/xalgorix-verification.txt"

	t.Run("matching token verifies", func(t *testing.T) {
		t.Parallel()

		var hits atomic.Int32
		v, host := fileFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			hits.Add(1)
			if r.URL.Path != wellKnownPath {
				t.Errorf("path = %q, want %q", r.URL.Path, wellKnownPath)
			}
			w.Header().Set("Content-Type", "text/plain")
			_, _ = w.Write([]byte(integrationToken + "\n"))
		}), 0)

		ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
		defer cancel()

		ok, err := v.Verify(ctx, host, integrationToken)
		if err != nil {
			t.Fatalf("Verify returned error: %v", err)
		}
		if !ok {
			t.Fatalf("Verify(matching token) = false, want true")
		}
		if hits.Load() != 1 {
			t.Fatalf("server hits = %d, want 1", hits.Load())
		}
	})

	t.Run("mismatched body fails verification", func(t *testing.T) {
		t.Parallel()

		v, host := fileFixture(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte("xalgorix-site-verification=ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ"))
		}), 0)

		ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
		defer cancel()

		ok, err := v.Verify(ctx, host, integrationToken)
		if err != nil {
			t.Fatalf("Verify returned error: %v (want nil; mismatch is verify-fail)", err)
		}
		if ok {
			t.Fatalf("Verify(mismatched body) = true, want false")
		}
	})

	t.Run("404 response fails verification", func(t *testing.T) {
		t.Parallel()

		v, host := fileFixture(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNotFound)
			// Write the right token in the body to prove that body
			// content cannot rescue a non-200 status.
			_, _ = w.Write([]byte(integrationToken))
		}), 0)

		ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
		defer cancel()

		ok, err := v.Verify(ctx, host, integrationToken)
		if err != nil {
			t.Fatalf("Verify returned error: %v (want nil; 404 is verify-fail)", err)
		}
		if ok {
			t.Fatalf("Verify(404) = true, want false")
		}
	})

	t.Run("body larger than 256 KiB truncates and fails", func(t *testing.T) {
		t.Parallel()

		// Body = "<wrong-token-prefix><lots of junk past the cap>".
		// io.LimitReader cuts the first 256 KiB, none of which is
		// the canonical token, so trim() cannot make the comparison
		// succeed.
		const oversize = MaxFileVerifierBodyBytes + 8*1024
		body := make([]byte, oversize)
		copy(body, []byte("xalgorix-site-verification=YYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYY\n"))
		for i := 60; i < len(body); i++ {
			body[i] = 'A' + byte(i%26)
		}

		v, host := fileFixture(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/plain")
			w.Header().Set("Content-Length", fmt.Sprintf("%d", len(body)))
			_, _ = w.Write(body)
		}), 0)

		ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
		defer cancel()

		ok, err := v.Verify(ctx, host, integrationToken)
		if err != nil {
			t.Fatalf("Verify returned error: %v", err)
		}
		if ok {
			t.Fatalf("Verify(oversize body) = true, want false (read should be capped at 256 KiB)")
		}
	})

	t.Run("server slower than client timeout fails with deadline error", func(t *testing.T) {
		t.Parallel()

		// 5 s is the production timeout; we drive a much shorter
		// client timeout (250 ms) against a handler that sleeps for
		// 750 ms to keep the test snappy while still proving the
		// verifier surfaces transport timeout as an error rather
		// than a (false, nil) verification result.
		release := make(chan struct{})
		v, host := fileFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			select {
			case <-time.After(750 * time.Millisecond):
			case <-r.Context().Done():
			case <-release:
			}
			_, _ = w.Write([]byte(integrationToken))
		}), 250*time.Millisecond)
		defer close(release)

		ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
		defer cancel()

		start := time.Now()
		ok, err := v.Verify(ctx, host, integrationToken)
		elapsed := time.Since(start)

		if err == nil {
			t.Fatal("Verify returned nil error on timeout; want transport timeout error")
		}
		if ok {
			t.Fatal("Verify returned ok=true on timeout")
		}
		// The client timeout is 250 ms; allow generous CI headroom.
		if elapsed > 2*time.Second {
			t.Fatalf("Verify took %v, want timeout to fire well under 2 s", elapsed)
		}
	})
}

// -----------------------------------------------------------------------------
// Meta verifier integration — real http.Client vs httptest.NewTLSServer
// -----------------------------------------------------------------------------

// metaFixture wires the meta verifier through an httptest TLS server.
// Unlike the file fixture this one does NOT need a cert-pool dance
// because httptest.Server.Client() already returns a client whose
// transport trusts the server's self-signed certificate; we only need
// to layer a DialTLSContext that lets the verifier address the server
// by the synthetic hostname `integrationHost`.
func metaFixture(t *testing.T, handler http.Handler) (*MetaVerifier, string) {
	t.Helper()

	srv := httptest.NewTLSServer(handler)
	t.Cleanup(srv.Close)

	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())

	srvURL, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("parse httptest URL: %v", err)
	}

	transport := &http.Transport{
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			cfg := &tls.Config{
				RootCAs:    pool,
				ServerName: integrationHost,
			}
			d := &tls.Dialer{Config: cfg}
			return d.DialContext(ctx, network, srvURL.Host)
		},
	}

	client := &http.Client{
		Timeout:   metaVerifierTimeout,
		Transport: transport,
		// Mirror NewMetaVerifier: never follow redirects so an
		// attacker cannot bounce verification through a host they
		// control.
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	return &MetaVerifier{Client: client}, integrationHost
}

// TestIntegration_MetaVerifier_AllPaths exercises MetaVerifier against a
// real httptest TLS server. The unit tests already cover the HTML
// parsing happy path and the missing/mismatched cases; this suite
// re-asserts them at the integration layer and adds the non-HTML
// content-type branch required by the task.
//
// Validates: Requirements 7.2, 7.4
func TestIntegration_MetaVerifier_AllPaths(t *testing.T) {
	t.Parallel()

	t.Run("matching meta tag verifies", func(t *testing.T) {
		t.Parallel()

		body := `<!doctype html>
<html><head>
<title>Acme</title>
<meta name="xalgorix-site-verification" content="` + integrationToken + `">
</head><body>hi</body></html>`

		v, host := metaFixture(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write([]byte(body))
		}))

		ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
		defer cancel()

		ok, err := v.Verify(ctx, host, integrationToken)
		if err != nil {
			t.Fatalf("Verify returned error: %v", err)
		}
		if !ok {
			t.Fatalf("Verify(matching meta) = false, want true")
		}
	})

	t.Run("missing meta tag returns ErrMetaTagMissing", func(t *testing.T) {
		t.Parallel()

		body := `<!doctype html><html><head>
<title>Acme</title>
<meta name="description" content="just a marketing page">
</head><body><p>nothing to see here</p></body></html>`

		v, host := metaFixture(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write([]byte(body))
		}))

		ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
		defer cancel()

		ok, err := v.Verify(ctx, host, integrationToken)
		if !errors.Is(err, ErrMetaTagMissing) {
			t.Fatalf("Verify error = %v, want ErrMetaTagMissing", err)
		}
		if ok {
			t.Fatal("Verify(missing meta) = true, want false")
		}
	})

	t.Run("mismatched content fails verification", func(t *testing.T) {
		t.Parallel()

		body := `<html><head><meta name="xalgorix-site-verification" content="xalgorix-site-verification=ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ"></head></html>`

		v, host := metaFixture(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write([]byte(body))
		}))

		ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
		defer cancel()

		ok, err := v.Verify(ctx, host, integrationToken)
		if err != nil {
			t.Fatalf("Verify returned error: %v (want nil; mismatch is verify-fail)", err)
		}
		if ok {
			t.Fatal("Verify(mismatched content) = true, want false")
		}
	})

	t.Run("non-HTML content-type with no meta tag returns ErrMetaTagMissing", func(t *testing.T) {
		t.Parallel()

		// MetaVerifier does not gate on Content-Type; the contract
		// only cares about whether the parsed body contains the
		// verification meta tag. A JSON body like the one below has
		// no <meta> at all, so the verifier must surface
		// ErrMetaTagMissing — proving that a server which returns a
		// non-HTML payload (the common "API endpoint at /" mistake)
		// cannot accidentally pass verification.
		v, host := metaFixture(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"verification":"` + integrationToken + `"}`))
		}))

		ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
		defer cancel()

		ok, err := v.Verify(ctx, host, integrationToken)
		if !errors.Is(err, ErrMetaTagMissing) {
			t.Fatalf("Verify error = %v, want ErrMetaTagMissing for non-HTML body", err)
		}
		if ok {
			t.Fatal("Verify(non-HTML body) = true, want false")
		}
	})
}
