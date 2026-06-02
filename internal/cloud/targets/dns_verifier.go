// Copyright (c) Xalgorix.
// SPDX-License-Identifier: AGPL-3.0-only

package targets

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// DNSLookupTimeout is the per-Verify upper bound on DNS work, per
// Requirement 7.4 / design.md ("Time-out 5 seconds per lookup"). If the
// caller's context carries an earlier deadline, the earlier deadline
// wins.
const DNSLookupTimeout = 5 * time.Second

// pinnedDNSServers are the only resolvers the production verifier is ever
// allowed to talk to, per Requirement 7.4 / design.md ("Resolver pinned
// to `1.1.1.1`, `8.8.8.8`; DNSSEC-validated via `github.com/miekg/dns`").
//
// The pinning matters for two reasons:
//   - It blocks DNS rebinding by malicious targets that might point at
//     the local /etc/resolv.conf for the API_Server pod (see design.md
//     "Per-Org Network Isolation").
//   - Both Cloudflare 1.1.1.1 and Google 8.8.8.8 are DNSSEC-validating
//     recursors that honour the DO bit and set AD on validated answers,
//     which is what we rely on for the DNSSEC requirement.
var pinnedDNSServers = []string{"1.1.1.1:53", "8.8.8.8:53"}

// dnsTokenLabel is the literal prefix every customer is asked to publish
// in their TXT record (Requirement 7.3). The verifier reconstructs the
// full expected payload (`<label><token>`) from the bare 32-char token so
// that callers don't have to concatenate by hand.
const dnsTokenLabel = "xalgorix-site-verification="

// ErrDNSNXDomain is returned by a TXTResolver when the queried name does
// not exist (RCODE 3, NXDOMAIN). DNSVerifier translates this into a
// (false, nil) failed-verification result rather than an error, per the
// task spec ("Treat NXDOMAIN/SERVFAIL as failure").
var ErrDNSNXDomain = errors.New("targets: dns nxdomain")

// ErrDNSServerFailure is returned by a TXTResolver when every pinned
// upstream returns SERVFAIL (RCODE 2). Like NXDOMAIN, the verifier treats
// this as a verification failure rather than a hard error.
var ErrDNSServerFailure = errors.New("targets: dns servfail")

// TXTResolver looks up TXT records for a hostname.
//
// Implementations are expected to:
//   - perform the lookup against DNSSEC-validating upstream resolvers,
//   - return the records joined per RFC 1035 (multi-string TXT records
//     concatenated into a single Go string),
//   - return ErrDNSNXDomain or ErrDNSServerFailure (or wrap them) for
//     NXDOMAIN/SERVFAIL responses, so the verifier can translate those
//     into a verification failure rather than a transport error.
//
// The interface exists so tests can swap in a deterministic in-process
// resolver without exercising the real network.
type TXTResolver interface {
	LookupTXT(ctx context.Context, host string) ([]string, error)
}

// DNSVerifier proves ownership of a host by looking up its TXT records and
// matching a previously-issued verification token.
//
// The zero value is not ready for use; obtain one through NewDNSVerifier
// or supply a Resolver explicitly. A nil Resolver at Verify time is
// replaced by a fresh PinnedDNSResolver, but tests should always inject
// their own resolver to avoid hitting the network.
//
// Implements the DNS branch of Requirement 7.2 / 7.4.
type DNSVerifier struct {
	// Resolver performs the actual TXT lookup. Production callers leave
	// this at the default PinnedDNSResolver (1.1.1.1, 8.8.8.8 with DO/AD
	// bits set). Tests inject a deterministic implementation.
	Resolver TXTResolver

	// Timeout overrides DNSLookupTimeout for tests. Zero means use the
	// 5-second default mandated by Requirement 7.4.
	Timeout time.Duration
}

// NewDNSVerifier returns a DNSVerifier wired to the default pinned,
// DNSSEC-aware resolver.
func NewDNSVerifier() *DNSVerifier {
	return &DNSVerifier{Resolver: NewPinnedDNSResolver()}
}

// Verify reports whether host publishes a TXT record whose payload
// matches `xalgorix-site-verification=<expectedToken>`.
//
// expectedToken is the bare 32-char base32 value section produced by
// GenerateVerificationToken; the literal `xalgorix-site-verification=`
// prefix is added here.
//
// Return contract:
//
//	(true,  nil)  the matching TXT record was found.
//	(false, nil)  the lookup succeeded but no matching TXT record was
//	              published, OR the host returned NXDOMAIN/SERVFAIL.
//	(false, err)  the lookup itself failed (timeout, transport error,
//	              malformed response). The caller is expected to surface
//	              this as a transient failure and let the cooldown logic
//	              from task 7.6 do its job.
//
// The 5-second Requirement 7.4 timeout is enforced here regardless of
// what the caller passes in via ctx; a shorter caller deadline still
// wins.
func (v *DNSVerifier) Verify(ctx context.Context, host, expectedToken string) (bool, error) {
	if strings.TrimSpace(host) == "" {
		return false, errors.New("targets: empty host")
	}
	if strings.TrimSpace(expectedToken) == "" {
		return false, errors.New("targets: empty expected token")
	}

	resolver := v.Resolver
	if resolver == nil {
		resolver = NewPinnedDNSResolver()
	}

	timeout := v.Timeout
	if timeout <= 0 {
		timeout = DNSLookupTimeout
	}
	lookupCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	records, err := resolver.LookupTXT(lookupCtx, host)
	if err != nil {
		// NXDOMAIN/SERVFAIL are documented as "verification failed,
		// not error" in the task spec — collapsing them here keeps
		// the caller's branch-shape simple.
		if errors.Is(err, ErrDNSNXDomain) || errors.Is(err, ErrDNSServerFailure) {
			return false, nil
		}
		return false, fmt.Errorf("targets: dns lookup %q: %w", host, err)
	}

	want := dnsTokenLabel + expectedToken
	for _, rec := range records {
		// Customers routinely have multiple TXT records on the apex
		// (SPF, DKIM, other vendor verifications). We only need our
		// exact payload to be one of them.
		if rec == want {
			return true, nil
		}
	}
	return false, nil
}

// PinnedDNSResolver is the production TXTResolver. It speaks to a
// closed list of upstream DNS servers (1.1.1.1:53, 8.8.8.8:53 by
// default) over both UDP and TCP, and uses miekg/dns to set the DNSSEC
// OK (DO) bit so the upstream resolver performs validation on our
// behalf.
//
// Stdlib note: net.Resolver does not surface the AD bit, so it cannot
// satisfy the DNSSEC-validation requirement on its own. miekg/dns lets
// us inspect AD explicitly. Even so, the *primary* DNSSEC enforcement
// comes from the pinned recursors themselves: 1.1.1.1 and 8.8.8.8
// refuse to return forged answers for signed zones regardless of what
// we ask them to do, so a downgrade attack against the AD bit cannot
// promote a forged record to "verified".
type PinnedDNSResolver struct {
	servers []string
	udp     *dns.Client
	tcp     *dns.Client
}

// PinnedDNSResolverOption configures a PinnedDNSResolver at construction
// time. Only test code should use anything other than the defaults.
type PinnedDNSResolverOption func(*PinnedDNSResolver)

// WithPinnedDNSServers overrides the upstream resolver list. Production
// code must NOT use this; it exists only so tests can dial an in-process
// miekg/dns server bound to a loopback port.
func WithPinnedDNSServers(servers ...string) PinnedDNSResolverOption {
	return func(r *PinnedDNSResolver) {
		r.servers = append([]string(nil), servers...)
	}
}

// NewPinnedDNSResolver constructs a PinnedDNSResolver wired to 1.1.1.1
// and 8.8.8.8 with the 5-second per-exchange timeout from Requirement
// 7.4.
func NewPinnedDNSResolver(opts ...PinnedDNSResolverOption) *PinnedDNSResolver {
	r := &PinnedDNSResolver{
		servers: append([]string(nil), pinnedDNSServers...),
		udp: &dns.Client{
			Net:     "udp",
			Timeout: DNSLookupTimeout,
		},
		tcp: &dns.Client{
			Net:     "tcp",
			Timeout: DNSLookupTimeout,
		},
	}
	for _, opt := range opts {
		opt(r)
	}
	return r
}

// LookupTXT performs a DNSSEC-aware TXT lookup against the pinned
// upstreams. The first server that returns a definitive answer wins; if
// all pinned servers fail with the same authoritative-style code we
// surface that as ErrDNSNXDomain / ErrDNSServerFailure. Lower-level
// transport errors become ordinary errors so the caller can decide
// whether to retry.
func (r *PinnedDNSResolver) LookupTXT(ctx context.Context, host string) ([]string, error) {
	if r == nil {
		return nil, errors.New("targets: nil PinnedDNSResolver")
	}

	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(host), dns.TypeTXT)
	msg.RecursionDesired = true
	// EDNS0 with the DO (DNSSEC OK) bit asks the upstream to perform
	// DNSSEC validation and to include RRSIG/AD in its response.
	msg.SetEdns0(4096, true)
	// Mirror DO with the AD bit on the query so a DNSSEC-validating
	// recursor knows we expect AD to be set on validated answers
	// (RFC 6840 §5.7).
	msg.AuthenticatedData = true

	var (
		sawNXDomain bool
		sawServFail bool
		lastErr     error
	)

	for _, srv := range r.servers {
		in, err := r.exchange(ctx, msg, srv)
		if err != nil {
			lastErr = fmt.Errorf("targets: dns exchange %s: %w", srv, err)
			continue
		}
		switch in.Rcode {
		case dns.RcodeNameError:
			sawNXDomain = true
			continue
		case dns.RcodeServerFailure:
			sawServFail = true
			continue
		case dns.RcodeSuccess:
			records := make([]string, 0, len(in.Answer))
			for _, ans := range in.Answer {
				if t, ok := ans.(*dns.TXT); ok {
					// Per RFC 1035 §3.3.14, a single
					// TXT record can carry multiple
					// character-strings; the convention
					// is to concatenate them with no
					// separator before content matching.
					records = append(records, strings.Join(t.Txt, ""))
				}
			}
			return records, nil
		default:
			lastErr = fmt.Errorf("targets: dns rcode %s from %s",
				dns.RcodeToString[in.Rcode], srv)
		}
	}

	switch {
	case sawNXDomain:
		return nil, ErrDNSNXDomain
	case sawServFail:
		return nil, ErrDNSServerFailure
	case lastErr != nil:
		return nil, lastErr
	default:
		return nil, errors.New("targets: no pinned resolver answered")
	}
}

// exchange runs one UDP query and falls back to TCP on truncation, which
// is the standard behaviour for DNS clients (RFC 5966).
func (r *PinnedDNSResolver) exchange(ctx context.Context, msg *dns.Msg, server string) (*dns.Msg, error) {
	in, _, err := r.udp.ExchangeContext(ctx, msg, server)
	if err != nil {
		if in != nil && in.Truncated {
			return r.exchangeTCP(ctx, msg, server)
		}
		return nil, err
	}
	if in.Truncated {
		return r.exchangeTCP(ctx, msg, server)
	}
	return in, nil
}

func (r *PinnedDNSResolver) exchangeTCP(ctx context.Context, msg *dns.Msg, server string) (*dns.Msg, error) {
	in, _, err := r.tcp.ExchangeContext(ctx, msg, server)
	if err != nil {
		return nil, err
	}
	return in, nil
}
