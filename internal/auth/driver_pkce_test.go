// Package auth — driver_pkce_test verifies the PKCE driver against
// the contract documented in driver_pkce.go and Requirements 6.1
// through 6.6 + 13.1, 13.2.
//
// The suite uses httptest.NewServer to stub the upstream
// authorization-code → token endpoint so the exchange is exercised
// end-to-end without network access. Catalog_Entry values handed to
// pkceDriver.Start carry AuthorizationEndpoint / TokenEndpoint
// pointing at the test server; ClientID / Scopes / Audience are
// fixtures.
//
// Properties covered (cross-referenced from design.md):
//
//   - Property 12 (verifier-challenge round-trip): R6.2 →
//     TestPKCE_VerifierToChallenge_S256RoundTrip iterates 128
//     random verifiers and asserts pkceChallenge equals a manual
//     base64url-no-pad(sha256(v)) reference.
//   - Property 13 (state binding): R6.3 →
//     TestPKCE_RejectsStateMismatch.
//   - Property 14 (flow timeout): R6.5 →
//     TestPKCE_TimeoutReturns408 (PKCE leg).
//   - Property 15 (loopback ↔ paste-fallback equivalence): R6.4,
//     R6.6 → TestPKCE_HappyPath_PersistsProfile and
//     TestPKCE_PasteFallback_EquivalentResult assert the persisted
//     OAuth_Profile shape is identical across the two paths.
//   - Property 26 (non-loopback bind refuses listener): R13.2 →
//     TestPKCE_RefuseNonLoopbackBind_PromptsPaste.
//
// Validates: Requirements 6.1, 6.2, 6.3, 6.4, 6.5, 6.6, 13.1, 13.2.
package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xalgord/xalgorix/v4/internal/providers"
)

// pkceStubCatalog is a minimal CatalogResolver used to construct a
// Profile_Store from a PKCE driver test. The PKCE driver does not
// consult the catalog itself — only Store.Put does, to enforce
// Requirement 4.8 (unknown provider rejection) — so the stub
// returns the configured Entry for matching ids and (false, nil)
// otherwise.
//
// Named pkceStubCatalog (rather than stubCatalog) because
// sink_test.go and store_test.go already declare a package-scoped
// stubCatalog with a different field shape; reusing the type name
// would collide at compile time.
type pkceStubCatalog struct {
	id    string
	entry providers.Entry
}

func (s *pkceStubCatalog) IsEmpty() bool { return false }

func (s *pkceStubCatalog) Get(_ context.Context, id string) (providers.Entry, bool, error) {
	if id != s.id {
		return providers.Entry{}, false, nil
	}
	return s.entry, true, nil
}

// pkceTestFixture bundles every plumbing dependency a PKCE-driver
// test needs: the token-endpoint stub server (with knobs for the
// next response), the constructed driver, the on-disk Profile_Store,
// and the Catalog_Entry whose URLs already point at the stub.
type pkceTestFixture struct {
	t            *testing.T
	server       *httptest.Server
	driver       *pkceDriver
	store        *Store
	entry        providers.Entry
	tokenCalls   atomic.Int64
	lastTokenReq atomic.Pointer[recordedTokenRequest]

	// Knobs the test sets before triggering an exchange. The
	// stub handler reads these atomically so a goroutine writing
	// the next response shape never races with the handler
	// reading it.
	nextStatus     atomic.Int64
	nextBody       atomic.Pointer[[]byte]
	expectedCode   atomic.Pointer[string]
	requireCodeVer atomic.Bool
}

// recordedTokenRequest captures the parsed form values of the most
// recent POST to the stub token endpoint so happy-path tests can
// assert that code, code_verifier, redirect_uri, and grant_type all
// arrived as expected.
type recordedTokenRequest struct {
	GrantType    string
	Code         string
	CodeVerifier string
	RedirectURI  string
	ClientID     string
}

// newPKCETestFixture wires up the stub upstream, an empty
// Profile_Store rooted in t.TempDir(), and a fresh pkceDriver
// pointed at both. The returned fixture exposes setNextOK /
// setNextError so individual tests can configure the upstream
// response without rebuilding the harness.
func newPKCETestFixture(t *testing.T) *pkceTestFixture {
	t.Helper()
	f := &pkceTestFixture{t: t}

	mux := http.NewServeMux()
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		f.tokenCalls.Add(1)
		_ = r.ParseForm()
		rec := &recordedTokenRequest{
			GrantType:    r.Form.Get("grant_type"),
			Code:         r.Form.Get("code"),
			CodeVerifier: r.Form.Get("code_verifier"),
			RedirectURI:  r.Form.Get("redirect_uri"),
			ClientID:     r.Form.Get("client_id"),
		}
		f.lastTokenReq.Store(rec)

		// When a test pinned an expected code, mismatch returns
		// 400 invalid_grant so the driver path can branch.
		if expPtr := f.expectedCode.Load(); expPtr != nil && *expPtr != rec.Code {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"invalid_grant","error_description":"unexpected code"}`))
			return
		}
		if f.requireCodeVer.Load() && rec.CodeVerifier == "" {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"invalid_request","error_description":"missing code_verifier"}`))
			return
		}

		status := int(f.nextStatus.Load())
		if status == 0 {
			status = http.StatusOK
		}
		bodyPtr := f.nextBody.Load()
		var body []byte
		if bodyPtr != nil {
			body = *bodyPtr
		} else {
			body = []byte(`{"access_token":"at-default","refresh_token":"rt-default","token_type":"bearer","expires_in":3600,"scope":"read write"}`)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write(body)
	})
	mux.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		// The PKCE driver never POSTs here directly; this exists
		// only so the AuthorizationEndpoint URL is a real,
		// reachable HTTP target if a test ever wants to GET it.
		w.WriteHeader(http.StatusOK)
	})
	f.server = httptest.NewServer(mux)
	t.Cleanup(f.server.Close)

	f.entry = providers.Entry{
		ID:                    "stub-provider",
		DisplayName:           "Stub",
		BaseURL:               f.server.URL,
		HeaderStyle:           "openai",
		Flow:                  "pkce",
		ClientID:              "client-xyz",
		AuthorizationEndpoint: f.server.URL + "/authorize",
		TokenEndpoint:         f.server.URL + "/token",
		Scopes:                []string{"read", "write"},
	}
	cat := &pkceStubCatalog{id: f.entry.ID, entry: f.entry}

	storePath := filepath.Join(t.TempDir(), "auth-profiles.json")
	store, err := NewStore(storePath, cat)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	f.store = store
	f.driver = newPKCEDriver(store, f.server.Client())

	return f
}

// setNextOK pins the next /token response to a 200 with the supplied
// body. The handler still validates code_verifier presence when
// requireCodeVer is set.
func (f *pkceTestFixture) setNextOK(body string) {
	b := []byte(body)
	f.nextBody.Store(&b)
	f.nextStatus.Store(int64(http.StatusOK))
}

// setExpectedCode forces the stub to return invalid_grant unless the
// posted code matches code. Used to verify the driver round-trips
// the operator-supplied code through to the upstream exchange.
func (f *pkceTestFixture) setExpectedCode(code string) {
	c := code
	f.expectedCode.Store(&c)
}

// authURLValues parses the authorization URL the driver returned in
// StartResult and surfaces the query values for assertion. Callers
// MUST pass the URL exactly as it came back from Start; this helper
// does not normalize or re-encode.
func authURLValues(t *testing.T, raw string) url.Values {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse auth URL %q: %v", raw, err)
	}
	return u.Query()
}

// referenceChallenge derives the S256 PKCE challenge using the
// std-lib primitives — the suite asserts pkceChallenge produces an
// identical value across 128 random verifiers (Property 12).
func referenceChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// =============================================================
// Tests
// =============================================================

// TestPKCE_BindsLoopbackEphemeral asserts Start with a loopback
// BindAddr binds an ephemeral 127.0.0.1 listener and embeds that
// host:port pair in the redirect_uri carried by the authorization
// URL.
//
// Validates: Requirements 6.1, 13.1.
func TestPKCE_BindsLoopbackEphemeral(t *testing.T) {
	f := newPKCETestFixture(t)
	res, err := f.driver.Start(context.Background(), f.entry, StartOptions{BindAddr: "127.0.0.1"})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer f.driver.expireFlow(res.FlowID, nil)

	if res.Mode != "loopback" {
		t.Fatalf("Mode = %q; want loopback", res.Mode)
	}
	q := authURLValues(t, res.AuthURL)
	redirect := q.Get("redirect_uri")
	if !strings.HasPrefix(redirect, "http://127.0.0.1:") {
		t.Fatalf("redirect_uri %q does not start with http://127.0.0.1:", redirect)
	}
	// Strip the scheme prefix so we can split host:port/path.
	rest := strings.TrimPrefix(redirect, "http://127.0.0.1:")
	slash := strings.Index(rest, "/")
	if slash < 0 {
		t.Fatalf("redirect_uri %q missing path separator", redirect)
	}
	port := rest[:slash]
	if port == "" || port == "0" {
		t.Fatalf("redirect_uri %q has zero/empty port", redirect)
	}
	if got := rest[slash:]; got != pkceCallbackPath {
		t.Fatalf("redirect_uri path = %q; want %q", got, pkceCallbackPath)
	}
}

// TestPKCE_VerifierToChallenge_S256RoundTrip exercises the
// pkceChallenge derivation across 128 random verifier byte strings.
// Each iteration draws crypto-random bytes, encodes as base64url-no-
// pad (the same shape pkceRandomBase64URL produces), and asserts the
// driver's derivation matches a manual reference computation.
//
// Validates: Requirement 6.2 (Property 12).
func TestPKCE_VerifierToChallenge_S256RoundTrip(t *testing.T) {
	const iterations = 128
	for i := 0; i < iterations; i++ {
		// Verifier length is varied across the RFC 7636 §4.1
		// allowed range (43–128 chars after base64url encoding)
		// so the property is exercised across the full input
		// space rather than only at the 32-byte minimum used by
		// the production code.
		nBytes := 32 + (i % 65) // 32..96 raw bytes → 43..128 b64url chars
		buf := make([]byte, nBytes)
		if _, err := rand.Read(buf); err != nil {
			t.Fatalf("rand.Read: %v", err)
		}
		verifier := base64.RawURLEncoding.EncodeToString(buf)

		got := pkceChallenge(verifier)
		want := referenceChallenge(verifier)
		if got != want {
			t.Fatalf("iteration %d: pkceChallenge(%q) = %q; want %q", i, verifier, got, want)
		}
		// Sanity: challenge is base64url-no-pad of a 32-byte
		// digest — always 43 chars.
		if len(got) != 43 {
			t.Fatalf("iteration %d: challenge length = %d; want 43", i, len(got))
		}
		if strings.ContainsAny(got, "=+/") {
			t.Fatalf("iteration %d: challenge %q contains non-base64url-no-pad chars", i, got)
		}
	}
}

// TestPKCE_RejectsStateMismatch verifies Complete refuses to call the
// upstream token endpoint when the supplied state does not match the
// flow's stored state.
//
// Validates: Requirement 6.3 (Property 13).
func TestPKCE_RejectsStateMismatch(t *testing.T) {
	f := newPKCETestFixture(t)
	res, err := f.driver.Start(context.Background(), f.entry, StartOptions{PreferPaste: true})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	if res.Mode != "paste" {
		t.Fatalf("expected paste mode; got %q", res.Mode)
	}

	startCalls := f.tokenCalls.Load()
	_, err = f.driver.Complete(context.Background(), f.entry, CompleteInput{
		FlowID:            res.FlowID,
		AuthorizationCode: "some-code",
		State:             "definitely-not-the-state",
	})
	if err == nil {
		t.Fatalf("Complete with mismatched state returned nil error")
	}
	if !strings.Contains(err.Error(), "state mismatch") {
		t.Fatalf("error = %v; want state mismatch", err)
	}
	if got := f.tokenCalls.Load(); got != startCalls {
		t.Fatalf("token endpoint called %d times during state-mismatch path; want 0 new calls", got-startCalls)
	}
}

// TestPKCE_HappyPath_PersistsProfile drives a full loopback flow:
// Start → derive redirect_uri+state → GET the redirect to trigger
// the callback handler → assert the resulting OAuth_Profile is
// persisted with the upstream-issued tokens.
//
// Validates: Requirements 6.1, 6.4 (Property 15 loopback leg).
func TestPKCE_HappyPath_PersistsProfile(t *testing.T) {
	f := newPKCETestFixture(t)
	f.setExpectedCode("auth-code-happy")
	f.requireCodeVer.Store(true)
	f.setNextOK(`{"access_token":"at-happy","refresh_token":"rt-happy","token_type":"bearer","expires_in":7200,"scope":"read write"}`)

	res, err := f.driver.Start(context.Background(), f.entry, StartOptions{BindAddr: "127.0.0.1"})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	q := authURLValues(t, res.AuthURL)
	redirect := q.Get("redirect_uri")
	state := q.Get("state")
	if redirect == "" || state == "" {
		t.Fatalf("missing redirect_uri/state in auth URL; q=%v", q)
	}

	// Fire the callback. The loopback listener is already serving
	// pkceCallbackPath, so a GET to redirect_uri?code=...&state=...
	// is exactly what an upstream provider would send the operator's
	// browser through to.
	cbURL := redirect + "?code=auth-code-happy&state=" + url.QueryEscape(state)
	resp, err := http.Get(cbURL)
	if err != nil {
		t.Fatalf("GET %s: %v", cbURL, err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("callback status = %d body=%s", resp.StatusCode, string(body))
	}

	// The cleanup goroutine fires expireFlow after the response is
	// flushed; wait for the flow's done channel so the assertions
	// below race-free on the in-memory store snapshot.
	gone, pending := waitForFlowGoneOrFinalize(f, res.FlowID, 2*time.Second)
	if !gone && pending != nil {
		// Flow still pending after the polling deadline — wait
		// briefly on its done channel before declaring failure.
		select {
		case <-pending.done:
		case <-time.After(2 * time.Second):
			t.Fatalf("flow %q did not finalize within 4s", res.FlowID)
		}
	}

	// Re-read the persisted profile.
	key := f.entry.ID + ":" + pkceDefaultProfileID
	got, found, err := f.store.Get(context.Background(), key)
	if err != nil {
		t.Fatalf("store.Get(%q): %v", key, err)
	}
	if !found {
		t.Fatalf("profile %q not persisted", key)
	}
	if got.AccessToken != "at-happy" || got.RefreshToken != "rt-happy" {
		t.Fatalf("profile tokens = (%q,%q); want (at-happy,rt-happy)", got.AccessToken, got.RefreshToken)
	}
	if got.TokenType != "bearer" {
		t.Fatalf("profile token type = %q; want bearer", got.TokenType)
	}
	if got.Type != OAuth {
		t.Fatalf("profile type = %q; want %q", got.Type, OAuth)
	}
	if got.ExpiresAt.IsZero() || got.ExpiresAt.Before(time.Now()) {
		t.Fatalf("profile expiresAt = %v; want non-zero future", got.ExpiresAt)
	}
	wantScopes := []string{"read", "write"}
	if len(got.Scopes) != len(wantScopes) {
		t.Fatalf("profile scopes = %v; want %v", got.Scopes, wantScopes)
	}
	for i, s := range wantScopes {
		if got.Scopes[i] != s {
			t.Fatalf("profile scopes[%d] = %q; want %q", i, got.Scopes[i], s)
		}
	}

	// And the recorded token request reflects the operator-supplied
	// code + the driver-generated verifier + the loopback redirect.
	rec := f.lastTokenReq.Load()
	if rec == nil {
		t.Fatalf("no token request recorded")
	}
	if rec.GrantType != "authorization_code" {
		t.Fatalf("grant_type = %q; want authorization_code", rec.GrantType)
	}
	if rec.Code != "auth-code-happy" {
		t.Fatalf("code = %q", rec.Code)
	}
	if rec.RedirectURI != redirect {
		t.Fatalf("redirect_uri at token endpoint = %q; want %q", rec.RedirectURI, redirect)
	}
	if rec.ClientID != f.entry.ClientID {
		t.Fatalf("client_id = %q; want %q", rec.ClientID, f.entry.ClientID)
	}
	if rec.CodeVerifier == "" {
		t.Fatalf("code_verifier was empty at token endpoint")
	}
}

// waitForFlowGoneOrFinalize polls d.flows for flowID. Returns once
// either (a) the flow entry is no longer present (cleanup already
// ran) or (b) deadline elapses with the flow still pending. Used
// after a callback handler GET to wait for the goroutine-spawned
// signalFlow → expireFlow chain to settle so subsequent Store
// reads see the persisted profile.
func waitForFlowGoneOrFinalize(f *pkceTestFixture, flowID string, deadline time.Duration) (gone bool, flow *pkceFlow) {
	end := time.Now().Add(deadline)
	for time.Now().Before(end) {
		raw, ok := f.driver.flows.Load(flowID)
		if !ok {
			return true, nil
		}
		flow = raw.(*pkceFlow)
		// Briefly back off to give the signalFlow goroutine a
		// chance to win the race with cleanup. 1ms is enough
		// in practice — the cleanup chain is purely in-memory
		// once the listener Shutdown returns.
		time.Sleep(1 * time.Millisecond)
	}
	return false, flow
}

// TestPKCE_TimeoutReturns408 shrinks pkceFlowDeadline to a few tens
// of milliseconds, starts a flow without ever completing it, and
// then asserts:
//
//  1. After the deadline elapses, Complete returns ErrFlowTimeout.
//  2. The flow entry has been removed from d.flows.
//  3. The loopback listener is closed (a TCP dial to its port fails).
//
// Validates: Requirement 6.5 (Property 14 PKCE leg).
func TestPKCE_TimeoutReturns408(t *testing.T) {
	original := pkceFlowDeadline
	pkceFlowDeadline = 50 * time.Millisecond
	t.Cleanup(func() { pkceFlowDeadline = original })

	f := newPKCETestFixture(t)
	res, err := f.driver.Start(context.Background(), f.entry, StartOptions{BindAddr: "127.0.0.1"})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	q := authURLValues(t, res.AuthURL)
	redirect := q.Get("redirect_uri")

	// Wait for the AfterFunc to fire. We poll for the flow to be
	// gone instead of sleeping for a fixed duration so this test is
	// not flaky on a slow CI runner — the deadline is 50ms but a
	// laggy scheduler can take longer.
	end := time.Now().Add(2 * time.Second)
	for time.Now().Before(end) {
		if _, ok := f.driver.flows.Load(res.FlowID); !ok {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if _, stillThere := f.driver.flows.Load(res.FlowID); stillThere {
		t.Fatalf("flow %q still present after deadline", res.FlowID)
	}

	// (1) Complete now returns ErrFlowTimeout.
	_, err = f.driver.Complete(context.Background(), f.entry, CompleteInput{
		FlowID:            res.FlowID,
		AuthorizationCode: "code",
		State:             "state",
	})
	if !errors.Is(err, ErrFlowTimeout) {
		t.Fatalf("Complete after timeout = %v; want errors.Is ErrFlowTimeout", err)
	}

	// (3) The loopback listener is closed — an HTTP GET against
	// the redirect_uri now fails (connection refused / EOF). We
	// allow either a network error or a non-2xx (some platforms
	// return RST and Go surfaces it as a 0-status response error).
	resp, gerr := http.Get(redirect + "?code=ignored&state=ignored")
	if gerr == nil {
		// If the dial somehow still succeeds (shouldn't, but
		// defensive), the response must not be 200.
		resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			t.Fatalf("loopback listener still serving 200 after deadline")
		}
	}
}

// TestPKCE_PasteFallback_EquivalentResult drives the paste-fallback
// path to the same upstream stub as TestPKCE_HappyPath_PersistsProfile
// and asserts the persisted Profile carries the same identifying
// fields (Provider, ProfileID, Type, AccessToken, RefreshToken,
// TokenType, Scopes). UpdatedAt is permitted to differ — it is wall-
// clock-stamped per Put — but every other field forms the
// equivalence class the property asserts.
//
// Validates: Requirement 6.6 (Property 15 paste leg).
func TestPKCE_PasteFallback_EquivalentResult(t *testing.T) {
	f := newPKCETestFixture(t)
	f.setExpectedCode("auth-code-paste")
	f.requireCodeVer.Store(true)
	f.setNextOK(`{"access_token":"at-paste","refresh_token":"rt-paste","token_type":"bearer","expires_in":7200,"scope":"read write"}`)

	res, err := f.driver.Start(context.Background(), f.entry, StartOptions{PreferPaste: true})
	if err != nil {
		t.Fatalf("Start(paste): %v", err)
	}
	if res.Mode != "paste" {
		t.Fatalf("Mode = %q; want paste", res.Mode)
	}
	q := authURLValues(t, res.AuthURL)
	if got := q.Get("redirect_uri"); got != pkceOOBRedirect {
		t.Fatalf("paste redirect_uri = %q; want %q", got, pkceOOBRedirect)
	}
	state := q.Get("state")

	prof, err := f.driver.Complete(context.Background(), f.entry, CompleteInput{
		FlowID:            res.FlowID,
		AuthorizationCode: "auth-code-paste",
		State:             state,
	})
	if err != nil {
		t.Fatalf("Complete(paste): %v", err)
	}

	// Profile shape equivalence — the design's Property 15 says the
	// persisted record is byte-identical across loopback and paste
	// paths for identical upstream responses; we assert on each
	// field rather than a JSON byte-compare so a future schema
	// addition (e.g., a new metadata field) does not silently break
	// the test without a clear signal.
	if prof.Provider != f.entry.ID {
		t.Fatalf("Provider = %q; want %q", prof.Provider, f.entry.ID)
	}
	if prof.ProfileID != pkceDefaultProfileID {
		t.Fatalf("ProfileID = %q; want %q", prof.ProfileID, pkceDefaultProfileID)
	}
	if prof.Type != OAuth {
		t.Fatalf("Type = %q; want %q", prof.Type, OAuth)
	}
	if prof.AccessToken != "at-paste" || prof.RefreshToken != "rt-paste" {
		t.Fatalf("tokens = (%q,%q); want (at-paste,rt-paste)", prof.AccessToken, prof.RefreshToken)
	}
	if prof.TokenType != "bearer" {
		t.Fatalf("TokenType = %q; want bearer", prof.TokenType)
	}
	wantScopes := []string{"read", "write"}
	if !equalSlice(prof.Scopes, wantScopes) {
		t.Fatalf("Scopes = %v; want %v", prof.Scopes, wantScopes)
	}

	// Verify the upstream saw redirect_uri = OOB literal — the paste
	// flow MUST send the same redirect_uri it advertised.
	rec := f.lastTokenReq.Load()
	if rec == nil {
		t.Fatalf("no token request recorded")
	}
	if rec.RedirectURI != pkceOOBRedirect {
		t.Fatalf("token-endpoint redirect_uri = %q; want %q", rec.RedirectURI, pkceOOBRedirect)
	}
}

// equalSlice reports whether a == b element-wise. Inlined helper so
// the suite does not depend on a slices.Equal go-version floor.
func equalSlice(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestPKCE_LoopbackBindWhenBindLoopback asserts that a loopback
// BindAddr produces Mode="loopback".
//
// Validates: Requirement 13.1.
func TestPKCE_LoopbackBindWhenBindLoopback(t *testing.T) {
	cases := []struct {
		name string
		bind string
	}{
		{"empty", ""},
		{"loopback-ipv4", "127.0.0.1"},
		{"loopback-ipv4-with-port", "127.0.0.1:8080"},
		{"loopback-ipv6", "::1"},
		{"localhost", "localhost"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newPKCETestFixture(t)
			res, err := f.driver.Start(context.Background(), f.entry, StartOptions{BindAddr: tc.bind})
			if err != nil {
				t.Fatalf("Start: %v", err)
			}
			defer f.driver.expireFlow(res.FlowID, nil)
			if res.Mode != "loopback" {
				t.Fatalf("BindAddr=%q Mode = %q; want loopback", tc.bind, res.Mode)
			}
			q := authURLValues(t, res.AuthURL)
			if got := q.Get("redirect_uri"); !strings.HasPrefix(got, "http://127.0.0.1:") {
				t.Fatalf("BindAddr=%q redirect_uri = %q; want http://127.0.0.1:<port>", tc.bind, got)
			}
		})
	}
}

// TestPKCE_RefuseNonLoopbackBind_PromptsPaste asserts a non-loopback
// BindAddr produces Mode="paste" with the OOB redirect_uri and binds
// no listener.
//
// Validates: Requirement 13.2 (Property 26).
func TestPKCE_RefuseNonLoopbackBind_PromptsPaste(t *testing.T) {
	cases := []struct {
		name string
		bind string
	}{
		{"wildcard-ipv4", "0.0.0.0"},
		{"wildcard-ipv4-with-port", "0.0.0.0:8080"},
		{"wildcard-ipv6", "::"},
		{"public-ipv4", "10.0.0.5"},
		{"non-localhost-host", "example.internal"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newPKCETestFixture(t)
			res, err := f.driver.Start(context.Background(), f.entry, StartOptions{BindAddr: tc.bind})
			if err != nil {
				t.Fatalf("Start: %v", err)
			}
			defer f.driver.expireFlow(res.FlowID, nil)
			if res.Mode != "paste" {
				t.Fatalf("BindAddr=%q Mode = %q; want paste", tc.bind, res.Mode)
			}
			q := authURLValues(t, res.AuthURL)
			if got := q.Get("redirect_uri"); got != pkceOOBRedirect {
				t.Fatalf("BindAddr=%q redirect_uri = %q; want %q", tc.bind, got, pkceOOBRedirect)
			}
			// And the flow object has no listener attached — the
			// driver refused to bind one.
			raw, ok := f.driver.flows.Load(res.FlowID)
			if !ok {
				t.Fatalf("flow %q not stored", res.FlowID)
			}
			flow := raw.(*pkceFlow)
			if flow.listener != nil {
				t.Fatalf("BindAddr=%q paste-mode flow has non-nil listener", tc.bind)
			}
			if flow.server != nil {
				t.Fatalf("BindAddr=%q paste-mode flow has non-nil http.Server", tc.bind)
			}
		})
	}
}

// =============================================================
// Compile-time guards
// =============================================================
