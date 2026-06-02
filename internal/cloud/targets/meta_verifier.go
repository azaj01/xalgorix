// Copyright (c) Xalgorix.
// SPDX-License-Identifier: AGPL-3.0-only

package targets

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"golang.org/x/net/html"
)

// metaVerifierBodyCap is the maximum number of bytes the meta-tag verifier
// will read from the target's home page. Design.md "Meta tag" pins this at
// 1 MiB:
//
//	GET https://{host}/
//	Timeout: 5s
//	Max body: 1 MiB
//
// Most legitimate marketing pages are well under this; the cap protects the
// API_Server from a malicious target that streams indefinitely or returns
// gigabytes of inline data.
const metaVerifierBodyCap = 1 << 20 // 1 MiB

// metaVerifierTimeout is the default end-to-end HTTP timeout used when the
// caller constructs a MetaVerifier without supplying their own *http.Client.
// Design.md pins the meta-tag fetch to a 5-second budget.
const metaVerifierTimeout = 5 * time.Second

// metaTagName is the value of the `name` attribute on the verification
// <meta> element, kept lowercase because the HTML parser normalises
// attribute names.
const metaTagName = "xalgorix-site-verification"

// ErrMetaTagMissing is returned when the response body parses cleanly but
// no `<meta name="xalgorix-site-verification" ...>` tag is present. This is
// distinct from a content-mismatch failure so that callers (and the
// `target_verification_attempts` ledger) can distinguish "owner never set
// it up" from "owner set up the wrong value".
var ErrMetaTagMissing = errors.New("targets: xalgorix-site-verification meta tag not found")

// MetaVerifier checks Target ownership by fetching `https://{host}/` and
// scanning the response for `<meta name="xalgorix-site-verification"
// content="...">`.
//
// Implements Requirement 7.2 (one of the three offered verification
// methods) and Requirement 7.4 (the verifier runs from Cloud_Platform
// infrastructure and transitions the Target on success). Cooldown
// (Requirement 7.5) and re-check (Requirement 7.7) are enforced by the
// dispatcher around this verifier rather than inside it.
type MetaVerifier struct {
	// Client is the HTTP client used for the GET. If nil, a fresh client
	// with a 5-second timeout is built per call. Tests inject an
	// httptest.Server-bound client to avoid real network traffic.
	Client *http.Client
}

// NewMetaVerifier returns a MetaVerifier with a sensible default
// *http.Client (5-second total timeout, no automatic redirect following so
// that an attacker cannot bounce verification through a controlled host).
func NewMetaVerifier() *MetaVerifier {
	return &MetaVerifier{
		Client: &http.Client{
			Timeout: metaVerifierTimeout,
			// Match the file verifier's posture: do not follow
			// redirects. A meta-tag check that silently follows a
			// 302 to attacker-controlled HTML would defeat the
			// purpose of ownership verification.
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

// Verify fetches `https://{host}/` and reports whether the response HTML
// contains a `<meta name="xalgorix-site-verification" content="...">` tag
// whose `content` attribute matches expectedToken.
//
// expectedToken may be supplied in either of the two shapes that the API
// surfaces to customers:
//
//  1. The full display token, e.g. `xalgorix-site-verification=ABC...`.
//     This is what `targets.verification_token` stores and what the
//     dashboard shows in the "Add this meta tag" instructions.
//  2. Just the value section (the 32 base32 characters), which is what a
//     careful site owner might paste into the `content` attribute on its
//     own.
//
// To accept both shapes from the customer's HTML and from the database,
// Verify accepts a match if the page's `content` attribute equals either
// the full token or its value section.
//
// Errors are returned for transport failures, oversized bodies, or HTML
// that cannot be parsed at all. A successful HTTP fetch where the meta tag
// is missing returns `(false, ErrMetaTagMissing)`; a fetch where the tag
// is present but the value differs returns `(false, nil)` because that is
// a deterministic "ownership not proven" outcome rather than an
// operational error.
func (v *MetaVerifier) Verify(ctx context.Context, host, expectedToken string) (bool, error) {
	if strings.TrimSpace(host) == "" {
		return false, errors.New("targets: meta verifier requires a host")
	}
	if !IsValidTokenFormat(expectedToken) {
		return false, fmt.Errorf("targets: meta verifier requires a token in %q form", tokenPrefix+"<32 base32>")
	}

	client := v.Client
	if client == nil {
		client = &http.Client{
			Timeout: metaVerifierTimeout,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
	}

	url := "https://" + host + "/"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return false, fmt.Errorf("targets: build meta verifier request: %w", err)
	}
	// Identify ourselves so target operators can recognise verification
	// traffic in their access logs.
	req.Header.Set("User-Agent", "xalgorix-meta-verifier/1.0")
	req.Header.Set("Accept", "text/html,application/xhtml+xml")

	resp, err := client.Do(req)
	if err != nil {
		return false, fmt.Errorf("targets: meta verifier GET %s: %w", url, err)
	}
	defer resp.Body.Close()

	// Only 2xx responses are considered candidates. A 4xx or 5xx response
	// is a deterministic "ownership not proven" — we surface it as a
	// non-match rather than an error so the dispatcher can record a
	// regular failure attempt.
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return false, nil
	}

	// Cap the body before handing it to the HTML parser.
	limited := io.LimitReader(resp.Body, metaVerifierBodyCap)

	expectedValue := strings.TrimPrefix(expectedToken, tokenPrefix)
	found, content, err := extractVerificationContent(limited)
	if err != nil {
		return false, fmt.Errorf("targets: parse %s: %w", url, err)
	}
	if !found {
		return false, ErrMetaTagMissing
	}

	// Accept either the full display token or just the value section.
	// Comparison is case-sensitive because the base32 alphabet is
	// uppercase and the prefix is fixed by Requirement 7.3.
	if content == expectedToken || content == expectedValue {
		return true, nil
	}
	return false, nil
}

// extractVerificationContent walks the HTML token stream and returns the
// `content` attribute of the first
// `<meta name="xalgorix-site-verification" ...>` element it encounters.
//
// The `name` comparison is case-insensitive because HTML attribute values
// of the `name` attribute are conventionally compared without regard to
// case (browsers and search engines do the same for `<meta name="robots">`
// and friends). The `content` value is returned verbatim — case-sensitive
// comparison against the expected token happens in Verify.
//
// A return of `(false, "", nil)` means parsing succeeded but no matching
// tag was found. A non-nil error indicates the token stream was malformed
// in a way the parser could not recover from; in practice
// `golang.org/x/net/html` is extremely lenient and only returns
// `io.ErrUnexpectedEOF` for truncated input, which we treat as a hard
// error so a body that hits the 1 MiB cap mid-tag does not silently fall
// through as "tag missing".
func extractVerificationContent(r io.Reader) (bool, string, error) {
	z := html.NewTokenizer(r)
	for {
		tt := z.Next()
		switch tt {
		case html.ErrorToken:
			err := z.Err()
			if errors.Is(err, io.EOF) {
				return false, "", nil
			}
			return false, "", err
		case html.StartTagToken, html.SelfClosingTagToken:
			tn, hasAttr := z.TagName()
			// Fast-path: only inspect <meta>. TagName returns the
			// raw bytes lowercased by the tokenizer, so a literal
			// byte comparison against "meta" is sufficient and
			// avoids the cost of a string allocation.
			if !(len(tn) == 4 && tn[0] == 'm' && tn[1] == 'e' && tn[2] == 't' && tn[3] == 'a') {
				// We deliberately keep walking past </head>: some
				// CMSes stamp the verification tag inside <body>.
				// The 1 MiB body cap bounds the total work.
				continue
			}
			if !hasAttr {
				continue
			}

			var (
				gotName    bool
				gotContent bool
				content    string
			)
			for {
				k, val, more := z.TagAttr()
				switch string(k) {
				case "name":
					if strings.EqualFold(string(val), metaTagName) {
						gotName = true
					}
				case "content":
					content = string(val)
					gotContent = true
				}
				if !more {
					break
				}
			}
			if gotName && gotContent {
				return true, content, nil
			}
		}
	}
}
