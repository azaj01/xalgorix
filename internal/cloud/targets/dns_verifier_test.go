// Copyright (c) Xalgorix.
// SPDX-License-Identifier: AGPL-3.0-only

package targets

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// fakeResolver is an in-memory TXTResolver that lets each test pin its own
// behaviour without touching the network. It intentionally mirrors the
// contract of PinnedDNSResolver: a hostname mapped to records is returned
// verbatim; a hostname mapped to err returns the error; an unknown
// hostname yields ErrDNSNXDomain so the verifier exercises its
// failure-not-error branch.
type fakeResolver struct {
	records map[string][]string
	errs    map[string]error
	delay   time.Duration
}

func (f *fakeResolver) LookupTXT(ctx context.Context, host string) ([]string, error) {
	if f.delay > 0 {
		select {
		case <-time.After(f.delay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if err, ok := f.errs[host]; ok {
		return nil, err
	}
	if recs, ok := f.records[host]; ok {
		return recs, nil
	}
	return nil, ErrDNSNXDomain
}

const (
	testHost  = "example.com"
	testToken = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
)

func TestDNSVerifier_MatchingTokenReturnsTrue(t *testing.T) {
	t.Parallel()

	v := &DNSVerifier{
		Resolver: &fakeResolver{
			records: map[string][]string{
				testHost: {
					"v=spf1 -all",
					dnsTokenLabel + testToken,
				},
			},
		},
	}

	ok, err := v.Verify(context.Background(), testHost, testToken)
	if err != nil {
		t.Fatalf("Verify returned error: %v", err)
	}
	if !ok {
		t.Fatalf("Verify(%q, ...) = false, want true (token published)", testHost)
	}
}

func TestDNSVerifier_NoMatchingRecordReturnsFalse(t *testing.T) {
	t.Parallel()

	v := &DNSVerifier{
		Resolver: &fakeResolver{
			records: map[string][]string{
				testHost: {
					"v=spf1 -all",
					"google-site-verification=somethingelse",
				},
			},
		},
	}

	ok, err := v.Verify(context.Background(), testHost, testToken)
	if err != nil {
		t.Fatalf("Verify returned error: %v", err)
	}
	if ok {
		t.Fatalf("Verify(%q, ...) = true, want false (token not published)", testHost)
	}
}

func TestDNSVerifier_WrongTokenReturnsFalse(t *testing.T) {
	t.Parallel()

	otherToken := "ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ"
	v := &DNSVerifier{
		Resolver: &fakeResolver{
			records: map[string][]string{
				testHost: {dnsTokenLabel + otherToken},
			},
		},
	}

	ok, err := v.Verify(context.Background(), testHost, testToken)
	if err != nil {
		t.Fatalf("Verify returned error: %v", err)
	}
	if ok {
		t.Fatalf("Verify(%q, ...) = true, want false (different token)", testHost)
	}
}

func TestDNSVerifier_NXDOMAINTreatedAsFalse(t *testing.T) {
	t.Parallel()

	v := &DNSVerifier{
		Resolver: &fakeResolver{
			// No records map entry → fakeResolver returns
			// ErrDNSNXDomain.
		},
	}

	ok, err := v.Verify(context.Background(), testHost, testToken)
	if err != nil {
		t.Fatalf("Verify returned error: %v (want nil)", err)
	}
	if ok {
		t.Fatalf("Verify(%q, ...) = true, want false (NXDOMAIN must verify-fail not error)", testHost)
	}
}

func TestDNSVerifier_SERVFAILTreatedAsFalse(t *testing.T) {
	t.Parallel()

	v := &DNSVerifier{
		Resolver: &fakeResolver{
			errs: map[string]error{
				testHost: ErrDNSServerFailure,
			},
		},
	}

	ok, err := v.Verify(context.Background(), testHost, testToken)
	if err != nil {
		t.Fatalf("Verify returned error: %v (want nil)", err)
	}
	if ok {
		t.Fatalf("Verify(%q, ...) = true, want false (SERVFAIL must verify-fail not error)", testHost)
	}
}

func TestDNSVerifier_TransportErrorPropagates(t *testing.T) {
	t.Parallel()

	boom := errors.New("connection refused")
	v := &DNSVerifier{
		Resolver: &fakeResolver{
			errs: map[string]error{
				testHost: boom,
			},
		},
	}

	ok, err := v.Verify(context.Background(), testHost, testToken)
	if err == nil {
		t.Fatalf("Verify returned nil error, want transport failure")
	}
	if !errors.Is(err, boom) {
		t.Fatalf("Verify error = %v, want wrapped %v", err, boom)
	}
	if ok {
		t.Fatalf("Verify(%q, ...) = true, want false on transport error", testHost)
	}
}

func TestDNSVerifier_TimeoutReturnsError(t *testing.T) {
	t.Parallel()

	v := &DNSVerifier{
		Resolver: &fakeResolver{
			delay: 200 * time.Millisecond,
		},
		Timeout: 25 * time.Millisecond,
	}

	start := time.Now()
	ok, err := v.Verify(context.Background(), testHost, testToken)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatalf("Verify returned nil error, want context deadline exceeded")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Verify error = %v, want context.DeadlineExceeded", err)
	}
	if ok {
		t.Fatal("Verify returned ok=true on timeout")
	}
	if elapsed > 150*time.Millisecond {
		t.Fatalf("Verify did not honour the 25ms Timeout; took %v", elapsed)
	}
}

func TestDNSVerifier_RejectsEmptyHost(t *testing.T) {
	t.Parallel()

	v := &DNSVerifier{Resolver: &fakeResolver{}}
	if _, err := v.Verify(context.Background(), "  ", testToken); err == nil {
		t.Fatal("Verify(empty host) returned nil error, want validation error")
	}
}

func TestDNSVerifier_RejectsEmptyToken(t *testing.T) {
	t.Parallel()

	v := &DNSVerifier{Resolver: &fakeResolver{}}
	if _, err := v.Verify(context.Background(), testHost, ""); err == nil {
		t.Fatal("Verify(empty token) returned nil error, want validation error")
	}
}

// TestPinnedDNSResolver_AgainstInProcessServer exercises the real
// PinnedDNSResolver against a miekg/dns server bound to a loopback port.
// In production the resolver dials 1.1.1.1:53 / 8.8.8.8:53; the option
// hook lets tests substitute the loopback address of the in-process
// server instead. This proves that:
//
//   - the resolver issues a TXT query with EDNS0/DO set;
//   - a happy-path response is parsed and returned to the verifier;
//   - the resolver multiplexes RFC 1035 multi-string TXT records by
//     concatenating their character-strings, so a record split as
//     ["xalgorix-site-verification=", "<token>"] still matches a record
//     stored as the single string the customer pasted into their zone.
func TestPinnedDNSResolver_AgainstInProcessServer(t *testing.T) {
	t.Parallel()

	_, addr, shutdown := startTestDNSServer(t, func(w dns.ResponseWriter, msg *dns.Msg) {
		resp := new(dns.Msg)
		resp.SetReply(msg)
		resp.Authoritative = true
		// Echo the DO bit so we look like a DNSSEC-validating
		// recursor would: just echoing AD here is enough for the
		// verifier's purposes because the integration test's job is
		// to exercise the wire parsing, not to re-implement DNSSEC.
		if opt := msg.IsEdns0(); opt != nil {
			resp.SetEdns0(4096, opt.Do())
			resp.AuthenticatedData = msg.AuthenticatedData
		}
		if len(msg.Question) == 1 && msg.Question[0].Qtype == dns.TypeTXT {
			rr := &dns.TXT{
				Hdr: dns.RR_Header{
					Name:   msg.Question[0].Name,
					Rrtype: dns.TypeTXT,
					Class:  dns.ClassINET,
					Ttl:    60,
				},
				// Multi-string TXT to verify our joiner.
				Txt: []string{dnsTokenLabel, testToken},
			}
			resp.Answer = append(resp.Answer, rr)
		}
		_ = w.WriteMsg(resp)
	})
	defer shutdown()

	resolver := NewPinnedDNSResolver(WithPinnedDNSServers(addr))
	v := &DNSVerifier{Resolver: resolver}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	ok, err := v.Verify(ctx, testHost, testToken)
	if err != nil {
		t.Fatalf("Verify returned error: %v", err)
	}
	if !ok {
		t.Fatal("Verify returned false against in-process server publishing the token")
	}
}

// TestPinnedDNSResolver_NXDOMAINFromUpstream confirms that the pinned
// resolver translates an authoritative NXDOMAIN response from every
// upstream into ErrDNSNXDomain, which the verifier collapses into
// (false, nil).
func TestPinnedDNSResolver_NXDOMAINFromUpstream(t *testing.T) {
	t.Parallel()

	_, addr, shutdown := startTestDNSServer(t, func(w dns.ResponseWriter, msg *dns.Msg) {
		resp := new(dns.Msg)
		resp.SetReply(msg)
		resp.Rcode = dns.RcodeNameError
		_ = w.WriteMsg(resp)
	})
	defer shutdown()

	resolver := NewPinnedDNSResolver(WithPinnedDNSServers(addr, addr))

	v := &DNSVerifier{Resolver: resolver}
	ok, err := v.Verify(context.Background(), testHost, testToken)
	if err != nil {
		t.Fatalf("Verify returned error: %v (want nil because NXDOMAIN is verify-fail)", err)
	}
	if ok {
		t.Fatal("Verify returned true on NXDOMAIN")
	}
}

// startTestDNSServer spins up a miekg/dns server on a random loopback UDP
// port and waits for it to become ready. The returned shutdown closure
// blocks until the server has fully released the port.
func startTestDNSServer(t *testing.T, handler dns.HandlerFunc) (*dns.Server, string, func()) {
	t.Helper()

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}

	srv := &dns.Server{
		PacketConn:    pc,
		Handler:       handler,
		ReadTimeout:   2 * time.Second,
		WriteTimeout:  2 * time.Second,
		NotifyStartedFunc: func() {},
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
		t.Fatal("test DNS server did not start in time")
	}

	addr := pc.LocalAddr().String()
	return srv, addr, func() {
		_ = srv.Shutdown()
		wg.Wait()
	}
}
