// Copyright (c) Xalgorix.
// SPDX-License-Identifier: AGPL-3.0-only

package targets

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// metaVerifierToken is a syntactically valid display token used across
// the table tests below. The 32-character value section is uppercase RFC
// 4648 base32, matching the format Requirement 7.3 pins. The constant is
// scoped to this test file (rather than reusing the value-section
// `metaVerifierToken` from recheck_test.go) so that the meta verifier tests can
// stand alone without leaking naming assumptions into a sibling file.
const metaVerifierToken = "xalgorix-site-verification=ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

// hostFromURL strips the scheme from an httptest server URL so the result
// can be passed to MetaVerifier.Verify as the `host` argument.
func hostFromURL(t *testing.T, raw string) string {
	t.Helper()
	const prefix = "https://"
	if !strings.HasPrefix(raw, prefix) {
		t.Fatalf("expected %q to start with %q", raw, prefix)
	}
	return raw[len(prefix):]
}

// newTLSServer wires up an httptest TLS server with the given handler and
// returns a ready-to-use MetaVerifier (its Client trusts the test server's
// self-signed cert) plus the bare host:port string.
func newTLSServer(t *testing.T, h http.HandlerFunc) (*MetaVerifier, string, func()) {
	t.Helper()
	srv := httptest.NewTLSServer(h)
	v := &MetaVerifier{Client: srv.Client()}
	// Disable redirect-following so behaviour matches the production
	// constructor in NewMetaVerifier.
	v.Client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return v, hostFromURL(t, srv.URL), srv.Close
}

func TestMetaVerifier_MatchingTag(t *testing.T) {
	t.Parallel()

	body := `<!doctype html>
<html><head>
<title>Acme</title>
<meta name="xalgorix-site-verification" content="` + metaVerifierToken + `">
</head><body>hello</body></html>`

	v, host, done := newTLSServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(body))
	})
	defer done()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	ok, err := v.Verify(ctx, host, metaVerifierToken)
	if err != nil {
		t.Fatalf("Verify returned unexpected error: %v", err)
	}
	if !ok {
		t.Fatalf("Verify returned ok=false on a matching meta tag")
	}
}

func TestMetaVerifier_MatchingTag_ValueOnlyContent(t *testing.T) {
	t.Parallel()

	// The site owner pasted just the 32-char value section, not the full
	// `xalgorix-site-verification=...` display string. Verify accepts
	// both shapes per its godoc.
	value := strings.TrimPrefix(metaVerifierToken, "xalgorix-site-verification=")
	body := `<html><head><meta name="xalgorix-site-verification" content="` + value + `"></head><body></body></html>`

	v, host, done := newTLSServer(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(body))
	})
	defer done()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	ok, err := v.Verify(ctx, host, metaVerifierToken)
	if err != nil {
		t.Fatalf("Verify returned unexpected error: %v", err)
	}
	if !ok {
		t.Fatalf("Verify returned ok=false on a value-only content match")
	}
}

func TestMetaVerifier_MatchingTag_CaseInsensitiveName(t *testing.T) {
	t.Parallel()

	body := `<html><head><META Name="Xalgorix-Site-Verification" Content="` + metaVerifierToken + `"></head></html>`

	v, host, done := newTLSServer(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(body))
	})
	defer done()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	ok, err := v.Verify(ctx, host, metaVerifierToken)
	if err != nil {
		t.Fatalf("Verify returned unexpected error: %v", err)
	}
	if !ok {
		t.Fatalf("Verify rejected a tag whose name attribute differed only in case")
	}
}

func TestMetaVerifier_MissingTag(t *testing.T) {
	t.Parallel()

	body := `<!doctype html>
<html><head>
<title>Acme</title>
<meta name="description" content="just a marketing page">
<meta name="robots" content="noindex">
</head><body><p>nothing to see here</p></body></html>`

	v, host, done := newTLSServer(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(body))
	})
	defer done()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	ok, err := v.Verify(ctx, host, metaVerifierToken)
	if !errors.Is(err, ErrMetaTagMissing) {
		t.Fatalf("expected ErrMetaTagMissing, got err=%v", err)
	}
	if ok {
		t.Fatalf("Verify returned ok=true when the verification tag was absent")
	}
}

func TestMetaVerifier_MismatchedContent(t *testing.T) {
	t.Parallel()

	const otherToken = "xalgorix-site-verification=ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ"
	body := `<html><head><meta name="xalgorix-site-verification" content="` + otherToken + `"></head></html>`

	v, host, done := newTLSServer(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(body))
	})
	defer done()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	ok, err := v.Verify(ctx, host, metaVerifierToken)
	if err != nil {
		t.Fatalf("Verify returned unexpected error on mismatched content: %v", err)
	}
	if ok {
		t.Fatalf("Verify returned ok=true on mismatched content (page=%q expected=%q)", otherToken, metaVerifierToken)
	}
}

func TestMetaVerifier_MismatchedContent_CaseSensitive(t *testing.T) {
	t.Parallel()

	// Lowercase the value section: the base32 alphabet is uppercase, so
	// the comparison must be case-sensitive. This guards Property 9
	// (token uniqueness) from being silently weakened by a forgiving
	// comparison.
	lower := strings.ToLower(metaVerifierToken)
	body := `<html><head><meta name="xalgorix-site-verification" content="` + lower + `"></head></html>`

	v, host, done := newTLSServer(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(body))
	})
	defer done()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	ok, err := v.Verify(ctx, host, metaVerifierToken)
	if err != nil {
		t.Fatalf("Verify returned unexpected error: %v", err)
	}
	if ok {
		t.Fatalf("Verify accepted lowercase content; comparison must be case-sensitive")
	}
}

func TestMetaVerifier_MalformedHTML(t *testing.T) {
	t.Parallel()

	// Unquoted attribute values, missing closing tag on <meta>,
	// body before </head>: this is the kind of garbage real CMS output
	// produces. golang.org/x/net/html's tokenizer is intentionally
	// lenient, so it should still surface the verification tag.
	body := `<!doctype html><html><head><meta charset=utf-8>
<meta name=xalgorix-site-verification content=` + metaVerifierToken + `>
<body><div><p>oops`

	v, host, done := newTLSServer(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(body))
	})
	defer done()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	ok, err := v.Verify(ctx, host, metaVerifierToken)
	if err != nil {
		t.Fatalf("Verify returned error on malformed-but-recoverable HTML: %v", err)
	}
	if !ok {
		t.Fatalf("Verify rejected a recoverable malformed page that contained the meta tag")
	}
}

func TestMetaVerifier_MalformedHTML_NoTag(t *testing.T) {
	t.Parallel()

	// Malformed HTML that genuinely has no verification tag should
	// resolve to ErrMetaTagMissing, not a parse error. This documents
	// that the verifier separates "couldn't read the page" (error) from
	// "page is fine, owner just hasn't set up the tag" (sentinel).
	body := `<html><head><title>nope</title><meta charset=utf-8><body><p>no verification here`

	v, host, done := newTLSServer(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(body))
	})
	defer done()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	ok, err := v.Verify(ctx, host, metaVerifierToken)
	if !errors.Is(err, ErrMetaTagMissing) {
		t.Fatalf("expected ErrMetaTagMissing on malformed-but-tagless page, got %v", err)
	}
	if ok {
		t.Fatalf("Verify returned ok=true on malformed-but-tagless page")
	}
}

func TestMetaVerifier_RejectsInvalidTokenShape(t *testing.T) {
	t.Parallel()

	v := &MetaVerifier{Client: http.DefaultClient}

	cases := []string{
		"",
		"not-a-token",
		"xalgorix-site-verification=tooshort",
	}
	for _, tok := range cases {
		ok, err := v.Verify(context.Background(), "example.com", tok)
		if err == nil {
			t.Fatalf("Verify with token %q expected error, got nil", tok)
		}
		if ok {
			t.Fatalf("Verify with token %q returned ok=true", tok)
		}
	}
}

func TestMetaVerifier_RejectsEmptyHost(t *testing.T) {
	t.Parallel()

	v := &MetaVerifier{Client: http.DefaultClient}

	ok, err := v.Verify(context.Background(), "   ", metaVerifierToken)
	if err == nil {
		t.Fatalf("expected error on empty host, got nil")
	}
	if ok {
		t.Fatalf("expected ok=false on empty host")
	}
}

func TestMetaVerifier_Non2xxStatus(t *testing.T) {
	t.Parallel()

	v, host, done := newTLSServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	defer done()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	ok, err := v.Verify(ctx, host, metaVerifierToken)
	if err != nil {
		t.Fatalf("Verify returned error on 404; expected (false, nil): %v", err)
	}
	if ok {
		t.Fatalf("Verify returned ok=true on 404")
	}
}
