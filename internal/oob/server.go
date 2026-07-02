// Package oob provides out-of-band (OAST) callback infrastructure so the
// agent can CONFIRM blind vulnerabilities — blind SSRF, blind RCE, blind
// XSS, XXE, blind SQLi via HTTP egress — with concrete evidence: the TARGET'S
// server (or a victim browser) reaching a unique, agent-controlled URL.
//
// This is essential under Xalgorix's "no theoretical findings" policy: a blind
// class that cannot be reproduced by the verifier is dropped, so the agent
// needs a real callback oracle to prove impact.
//
// Design: a single in-process HTTP listener records every inbound request,
// correlated by a unique token embedded in the URL path (/{token}/...). The
// listener binds 0.0.0.0:<XALGORIX_OOB_PORT>; the operator exposes it publicly
// (directly or via reverse proxy) and sets XALGORIX_OOB_PUBLIC_URL to the
// address targets can reach. Without a public URL the feature is disabled and
// the tool tells the agent to fall back to in-band verification.
package oob

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/xalgord/xalgorix/v4/internal/config"
)

// Interaction is a single recorded out-of-band callback.
type Interaction struct {
	Token      string            `json:"token"`
	Protocol   string            `json:"protocol"` // "http" / "https"
	Method     string            `json:"method"`
	Path       string            `json:"path"`
	Query      string            `json:"query"`
	RemoteAddr string            `json:"remote_addr"`
	UserAgent  string            `json:"user_agent"`
	Headers    map[string]string `json:"headers"`
	Body       string            `json:"body"`
	Time       time.Time         `json:"time"`
}

var (
	mu           sync.Mutex
	interactions = map[string][]Interaction{} // token -> ordered interactions
	tokenOrder   []string                     // FIFO of registered tokens for eviction
	startErr     error
	startOnce    sync.Once
)

const (
	maxOOBBody      = 8 * 1024
	maxHitsPerToken = 100  // cap interactions kept per token
	maxTokens       = 4096 // cap registered tokens; oldest evicted beyond this
)

// selfHosted reports whether the operator configured a self-hosted callback
// listener (XALGORIX_OOB_PUBLIC_URL). When set it takes precedence over the
// zero-config interactsh backend.
func selfHosted() bool {
	return strings.TrimSpace(config.Get().OOBPublicURL) != ""
}

// Enabled reports whether OOB is usable: either a self-hosted listener is
// configured, or the interactsh backend is available (the default).
func Enabled() bool {
	return selfHosted() || interactshEnabled()
}

// Generate mints a callback URL + polling token using whichever backend is
// active: the self-hosted listener when configured, otherwise interactsh.
func Generate() (callbackURL, token string, err error) {
	if selfHosted() {
		return selfHostedGenerate()
	}
	if !interactshEnabled() {
		return "", "", fmt.Errorf("OOB is disabled (XALGORIX_OOB_DISABLE=true)")
	}
	return interactshGenerate()
}

// Poll returns interactions for a token from whichever backend is active.
func Poll(token string) []Interaction {
	if selfHosted() {
		return selfHostedPoll(token)
	}
	return interactshPoll(token)
}

// PublicBaseURL returns the operator-configured public callback base, trimmed
// of any trailing slash. Empty when OOB is disabled.
func PublicBaseURL() string {
	return strings.TrimRight(strings.TrimSpace(config.Get().OOBPublicURL), "/")
}

// ensureStarted lazily starts the listener the first time OOB is used.
func ensureStarted() error {
	startOnce.Do(func() {
		port := config.Get().OOBPort
		if port <= 0 {
			startErr = fmt.Errorf("XALGORIX_OOB_PORT not set")
			return
		}
		mux := http.NewServeMux()
		mux.HandleFunc("/", handle)
		srv := &http.Server{
			Addr:              fmt.Sprintf("0.0.0.0:%d", port),
			Handler:           mux,
			ReadHeaderTimeout: 10 * time.Second,
		}
		ln, err := net.Listen("tcp", srv.Addr)
		if err != nil {
			startErr = fmt.Errorf("oob listen %s: %w", srv.Addr, err)
			return
		}
		go func() { _ = srv.Serve(ln) }()
	})
	return startErr
}

// selfHostedGenerate registers a fresh correlation token and returns the full
// callback URL the agent should plant in payloads, plus the bare token for
// polling. Returns an error when the self-hosted listener is not reachable.
func selfHostedGenerate() (callbackURL, token string, err error) {
	if !selfHosted() {
		return "", "", fmt.Errorf("OOB is not configured (set XALGORIX_OOB_PUBLIC_URL and XALGORIX_OOB_PORT)")
	}
	if err := ensureStarted(); err != nil {
		return "", "", err
	}
	token = randToken()
	mu.Lock()
	// Register the token so the handler only records callbacks for tokens we
	// actually minted (internet scan noise hitting random paths is ignored).
	interactions[token] = []Interaction{}
	tokenOrder = append(tokenOrder, token)
	// Evict the oldest tokens if we exceed the cap (long-lived server).
	for len(tokenOrder) > maxTokens {
		old := tokenOrder[0]
		tokenOrder = tokenOrder[1:]
		delete(interactions, old)
	}
	mu.Unlock()
	return PublicBaseURL() + "/" + token, token, nil
}

// selfHostedPoll returns interactions recorded by the self-hosted listener
// for a token since the beginning.
func selfHostedPoll(token string) []Interaction {
	token = strings.TrimSpace(token)
	mu.Lock()
	defer mu.Unlock()
	out := make([]Interaction, len(interactions[token]))
	copy(out, interactions[token])
	return out
}

func handle(w http.ResponseWriter, r *http.Request) {
	token := firstPathSegment(r.URL.Path)
	proto := "http"
	if r.TLS != nil {
		proto = "https"
	}
	body := ""
	if r.Body != nil {
		b, _ := io.ReadAll(io.LimitReader(r.Body, maxOOBBody))
		body = string(b)
	}
	hdrs := map[string]string{}
	for k, v := range r.Header {
		hdrs[k] = strings.Join(v, ", ")
	}
	it := Interaction{
		Token:      token,
		Protocol:   proto,
		Method:     r.Method,
		Path:       r.URL.Path,
		Query:      r.URL.RawQuery,
		RemoteAddr: r.RemoteAddr,
		UserAgent:  r.UserAgent(),
		Headers:    hdrs,
		Body:       body,
		Time:       time.Now(),
	}
	if token != "" {
		mu.Lock()
		// Only record callbacks for tokens we minted via Generate — ignore
		// unregistered paths (bots, scanners, favicon probes) so the store
		// can't be polluted or grown without bound by internet noise.
		if hits, ok := interactions[token]; ok && len(hits) < maxHitsPerToken {
			interactions[token] = append(hits, it)
		}
		mu.Unlock()
	}
	// Respond with a tiny, benign, unique marker so the agent can also detect
	// the callback in-band (e.g. an SSRF that reflects the response body).
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("xalgorix-oob-ok:" + token + "\n"))
}

func firstPathSegment(p string) string {
	p = strings.TrimLeft(p, "/")
	if i := strings.IndexByte(p, '/'); i >= 0 {
		p = p[:i]
	}
	if i := strings.IndexByte(p, '?'); i >= 0 {
		p = p[:i]
	}
	return p
}

func randToken() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("t%d", time.Now().UnixNano())
	}
	return "x" + hex.EncodeToString(b) // 17 chars, url/dns safe
}
