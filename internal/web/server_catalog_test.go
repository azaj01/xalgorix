// Package web — Wave H task 9.8 web-server tests for the
// provider-catalog-and-oauth spec.
//
// These tests live in a sibling file to server_test.go so the new
// catalog/profile/OAuth surface coverage stays readable. They cover
// the design's correctness properties as scoped by tasks.md:
//
//   • Property 11   — credential masking on /api/auth/profiles
//   • Property 22   — per-scan precedence rule (resolveScanCredentials)
//   • Property 23   — unknown provider_profile rejected at /api/scan
//   • Property 24   — every new route returns 401 without a session
//   • Property 25   — every mutating new route is CSRF-gated (in csrf_test.go)
//   • Property 27   — env file is not polluted by catalog/profile writes
//
// Plus the surrounding requirement assertions (R3.3, R5.x, R11.x,
// R12.x, R13.3, R15.x).
package web

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xalgord/xalgorix/v4/internal/auth"
	"github.com/xalgord/xalgorix/v4/internal/config"
	"github.com/xalgord/xalgorix/v4/internal/llm"
	"github.com/xalgord/xalgorix/v4/internal/providers"
)

// seedCatalogEntry installs a single catalog entry on s.catalog and
// returns the canonical Entry shape so tests can use it as the
// resolver's "provider_X" reference. The HeaderStyle is fixed to
// "openai" (the simplest of the three allowlist values) unless the
// caller wants something else; pass headerStyle == "" to default.
func seedCatalogEntry(t *testing.T, s *Server, id, baseURL, headerStyle string) providers.Entry {
	t.Helper()
	if headerStyle == "" {
		headerStyle = "openai"
	}
	entry := providers.Entry{
		ID:          id,
		DisplayName: id + " display",
		BaseURL:     baseURL,
		HeaderStyle: headerStyle,
		Models:      []string{id + "-model"},
	}
	if err := s.catalog.Create(context.Background(), entry); err != nil {
		t.Fatalf("seed catalog entry %q: %v", id, err)
	}
	return entry
}

// seedAPIKeyProfile installs an API-key profile under the given
// catalog provider id. The credential string is opaque — callers
// pick the value they want to assert against the masking output.
func seedAPIKeyProfile(t *testing.T, s *Server, provider, profileID, apiKey, apiBaseOverride string) auth.Profile {
	t.Helper()
	p := auth.Profile{
		Provider:        provider,
		ProfileID:       profileID,
		Type:            auth.APIKey,
		APIKey:          apiKey,
		APIBaseOverride: apiBaseOverride,
	}
	if err := s.profiles.Put(context.Background(), p); err != nil {
		t.Fatalf("seed api key profile %q: %v", p.Key(), err)
	}
	stored, ok, err := s.profiles.Get(context.Background(), p.Key())
	if err != nil || !ok {
		t.Fatalf("seed api key profile readback failed: ok=%v err=%v", ok, err)
	}
	return stored
}

// seedOAuthProfile installs an OAuth profile under the given catalog
// provider id with all four optional metadata fields populated.
func seedOAuthProfile(t *testing.T, s *Server, p auth.Profile) auth.Profile {
	t.Helper()
	p.Type = auth.OAuth
	if err := s.profiles.Put(context.Background(), p); err != nil {
		t.Fatalf("seed oauth profile %q: %v", p.Key(), err)
	}
	stored, ok, err := s.profiles.Get(context.Background(), p.Key())
	if err != nil || !ok {
		t.Fatalf("seed oauth profile readback failed: ok=%v err=%v", ok, err)
	}
	return stored
}

// randomToken returns a deterministic-ish printable token of the
// requested byte length. We deliberately avoid pulling in a
// cryptorand dependency: the masking properties only care about
// length and the trailing 8 characters, so a math/rand-driven
// alphabet is sufficient and keeps the tests reproducible from a
// caller-supplied seed.
func randomToken(rng *rand.Rand, n int) string {
	const alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	if n <= 0 {
		return ""
	}
	b := make([]byte, n)
	for i := range b {
		b[i] = alphabet[rng.Intn(len(alphabet))]
	}
	return string(b)
}

// ---------- Property 11: Credential masking ----------

// TestProfilesEndpoint_MasksCredentials confirms the canonical
// happy-path mask shape on /api/auth/profiles: the trailing-8-char
// "****" prefix mirrors maskAgentMailKey so the dashboard's
// existing mask-detection logic keeps working unchanged.
//
// Validates: Requirements 5.1, 5.2, 5.4 (Property 11).
func TestProfilesEndpoint_MasksCredentials(t *testing.T) {
	s := newTestServer(t, nil)
	if s.profiles == nil || s.catalog == nil {
		t.Fatal("test server profile/catalog stores were not initialized")
	}

	seedCatalogEntry(t, s, "openai", "https://api.openai.com", "openai")
	apiKey := "0123456789abcdef" // 16 chars; tail is "89abcdef"
	seedAPIKeyProfile(t, s, "openai", "default", apiKey, "")

	rr := httptest.NewRecorder()
	s.handleListProfiles(rr, httptest.NewRequest(http.MethodGet, "/api/auth/profiles", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("list profiles status = %d body=%s", rr.Code, rr.Body.String())
	}

	var got []auth.Profile
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode profiles response: %v body=%s", err, rr.Body.String())
	}
	if len(got) != 1 {
		t.Fatalf("profiles count = %d, want 1: %#v", len(got), got)
	}
	wantMask := "****" + apiKey[len(apiKey)-8:]
	if got[0].APIKey != wantMask {
		t.Fatalf("masked apiKey = %q, want %q", got[0].APIKey, wantMask)
	}
	// Body must never carry the unmasked credential as a
	// substring — even when the field happens to be shorter than
	// the trailing-8 window (defensive coverage).
	if strings.Contains(rr.Body.String(), apiKey) {
		t.Fatalf("response body leaked the unmasked apiKey: %s", rr.Body.String())
	}
}

// TestProfilesEndpoint_PreservesUnmaskedMetadata is the property
// half of Property 11: across 100 randomized profiles (mixed APIKey
// + OAuth shapes), every non-credential field must round-trip
// exactly, and the three credential fields must equal
// maskAuthCredential(<stored value>).
//
// Validates: Requirements 5.1, 5.2, 5.3, 5.4 (Property 11).
func TestProfilesEndpoint_PreservesUnmaskedMetadata(t *testing.T) {
	s := newTestServer(t, nil)
	if s.profiles == nil || s.catalog == nil {
		t.Fatal("test server profile/catalog stores were not initialized")
	}

	// Seed two catalog entries — provider key alternates so we
	// exercise both Profile rows in the masked response.
	seedCatalogEntry(t, s, "alpha", "https://alpha.example", "openai")
	seedCatalogEntry(t, s, "beta", "https://beta.example", "anthropic")

	rng := rand.New(rand.NewSource(int64(0xC471D)))

	type want struct {
		key       string
		stored    auth.Profile
		wantAPI   string
		wantAcc   string
		wantRef   string
		hadAPI    bool // whether we expect a non-empty mask vs. ""
		hadAcc    bool
		hadRef    bool
	}
	const N = 100
	wants := make(map[string]want, N)

	for i := 0; i < N; i++ {
		provider := "alpha"
		if i%2 == 1 {
			provider = "beta"
		}
		profID := fmt.Sprintf("p%03d", i)
		var p auth.Profile
		if rng.Intn(2) == 0 {
			// API_Key_Profile branch — random key length in
			// [4, 64] so we cover the short / medium / long
			// masking cells and the empty-override cell.
			klen := 4 + rng.Intn(61)
			apiKey := randomToken(rng, klen)
			override := ""
			if rng.Intn(3) == 0 {
				override = "https://override-" + profID + ".example"
			}
			p = auth.Profile{
				Provider:        provider,
				ProfileID:       profID,
				Type:            auth.APIKey,
				APIKey:          apiKey,
				APIBaseOverride: override,
			}
		} else {
			// OAuth_Profile branch — populate every metadata
			// field so the round-trip assertion is exhaustive.
			tlen := 8 + rng.Intn(40)
			rtl := 8 + rng.Intn(40)
			scopes := []string{"scope" + profID}
			if rng.Intn(2) == 0 {
				scopes = append(scopes, "scope-extra")
			}
			p = auth.Profile{
				Provider:       provider,
				ProfileID:      profID,
				Type:           auth.OAuth,
				AccessToken:    randomToken(rng, tlen),
				RefreshToken:   randomToken(rng, rtl),
				ExpiresAt:      time.Now().UTC().Add(time.Duration(rng.Intn(7200)) * time.Second),
				Scopes:         scopes,
				TokenType:      "Bearer",
				RequiresReauth: rng.Intn(5) == 0,
			}
		}
		stored := seedOAuthOrAPIKeyHelper(t, s, p)
		wants[stored.Key()] = want{
			key:     stored.Key(),
			stored:  stored,
			wantAPI: maskAuthCredential(stored.APIKey),
			wantAcc: maskAuthCredential(stored.AccessToken),
			wantRef: maskAuthCredential(stored.RefreshToken),
			hadAPI:  stored.APIKey != "",
			hadAcc:  stored.AccessToken != "",
			hadRef:  stored.RefreshToken != "",
		}
	}

	rr := httptest.NewRecorder()
	s.handleListProfiles(rr, httptest.NewRequest(http.MethodGet, "/api/auth/profiles", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("list profiles status = %d body=%s", rr.Code, rr.Body.String())
	}
	var got []auth.Profile
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode profiles response: %v", err)
	}
	if len(got) != N {
		t.Fatalf("profile count = %d, want %d", len(got), N)
	}

	for _, p := range got {
		w, ok := wants[p.Key()]
		if !ok {
			t.Fatalf("unexpected profile in response: %#v", p)
		}
		// Credential fields must equal mask of the stored value.
		if p.APIKey != w.wantAPI {
			t.Fatalf("profile %s: APIKey mask = %q, want %q (stored %q)", p.Key(), p.APIKey, w.wantAPI, w.stored.APIKey)
		}
		if p.AccessToken != w.wantAcc {
			t.Fatalf("profile %s: AccessToken mask = %q, want %q", p.Key(), p.AccessToken, w.wantAcc)
		}
		if p.RefreshToken != w.wantRef {
			t.Fatalf("profile %s: RefreshToken mask = %q, want %q", p.Key(), p.RefreshToken, w.wantRef)
		}
		// Non-credential fields must be unchanged from the stored value.
		if p.Provider != w.stored.Provider || p.ProfileID != w.stored.ProfileID {
			t.Fatalf("profile %s: identity changed: got (%s,%s) want (%s,%s)", p.Key(), p.Provider, p.ProfileID, w.stored.Provider, w.stored.ProfileID)
		}
		if p.Type != w.stored.Type {
			t.Fatalf("profile %s: Type = %q, want %q", p.Key(), p.Type, w.stored.Type)
		}
		if p.APIBaseOverride != w.stored.APIBaseOverride {
			t.Fatalf("profile %s: APIBaseOverride = %q, want %q", p.Key(), p.APIBaseOverride, w.stored.APIBaseOverride)
		}
		if !p.ExpiresAt.Equal(w.stored.ExpiresAt) {
			t.Fatalf("profile %s: ExpiresAt = %v, want %v", p.Key(), p.ExpiresAt, w.stored.ExpiresAt)
		}
		if !stringSlicesEqual(p.Scopes, w.stored.Scopes) {
			t.Fatalf("profile %s: Scopes = %v, want %v", p.Key(), p.Scopes, w.stored.Scopes)
		}
		if p.TokenType != w.stored.TokenType {
			t.Fatalf("profile %s: TokenType = %q, want %q", p.Key(), p.TokenType, w.stored.TokenType)
		}
		if p.RequiresReauth != w.stored.RequiresReauth {
			t.Fatalf("profile %s: RequiresReauth = %v, want %v", p.Key(), p.RequiresReauth, w.stored.RequiresReauth)
		}
		// UpdatedAt is stamped by the Store; just assert it
		// round-trips equal to the stored value (the store
		// returns the same Profile we read back via Get).
		if !p.UpdatedAt.Equal(w.stored.UpdatedAt) {
			t.Fatalf("profile %s: UpdatedAt = %v, want %v", p.Key(), p.UpdatedAt, w.stored.UpdatedAt)
		}
		// And the response body must never leak the raw secret as a substring.
		if w.hadAPI && strings.Contains(rr.Body.String(), w.stored.APIKey) {
			t.Fatalf("profile %s: body leaked APIKey", p.Key())
		}
		if w.hadAcc && strings.Contains(rr.Body.String(), w.stored.AccessToken) {
			t.Fatalf("profile %s: body leaked AccessToken", p.Key())
		}
		if w.hadRef && strings.Contains(rr.Body.String(), w.stored.RefreshToken) {
			t.Fatalf("profile %s: body leaked RefreshToken", p.Key())
		}
	}
}

// seedOAuthOrAPIKeyHelper persists either profile shape and returns
// the readback so tests can compare against the Store-stamped
// UpdatedAt without re-doing the lookup at every assertion site.
func seedOAuthOrAPIKeyHelper(t *testing.T, s *Server, p auth.Profile) auth.Profile {
	t.Helper()
	if err := s.profiles.Put(context.Background(), p); err != nil {
		t.Fatalf("seed profile %q: %v", p.Key(), err)
	}
	stored, ok, err := s.profiles.Get(context.Background(), p.Key())
	if err != nil || !ok {
		t.Fatalf("seed profile readback failed: ok=%v err=%v", ok, err)
	}
	return stored
}

func stringSlicesEqual(a, b []string) bool {
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

// ---------- Property 22: Per-scan precedence ----------

// TestResolveScanCredentials_PrecedenceMatrix runs ≥ 100 random
// (ScanRequest, Profile) combinations and asserts the design's
// precedence rule (Property 22):
//
//   effective.Model  = R.Model   if R.Model   != ""  else T.Model
//   effective.APIKey = R.APIKey  if R.APIKey  != ""  else T.APIKey
//   effective.URL    = R.APIBase if R.APIBase != ""  else T.URL
//
// AND when R.APIKey != "" the effective Auth method is forced to
// AuthAPIKey regardless of the underlying profile shape.
//
// Validates: Requirements 11.2, 11.3, 11.4 (Property 22).
func TestResolveScanCredentials_PrecedenceMatrix(t *testing.T) {
	s := newTestServer(t, nil)
	if s.profiles == nil || s.catalog == nil {
		t.Fatal("test server profile/catalog stores were not initialized")
	}

	entry := seedCatalogEntry(t, s, "openai", "https://api.openai.com", "openai")
	apiKeyProf := seedAPIKeyProfile(t, s, "openai", "default", "stored-api-key-1", "")
	oauthProf := seedOAuthOrAPIKeyHelper(t, s, auth.Profile{
		Provider:    "openai",
		ProfileID:   "oauth1",
		Type:        auth.OAuth,
		AccessToken: "stored-access-token-2",
		TokenType:   "Bearer",
	})

	// Pre-compute the base URL/model the resolver would produce
	// for each profile so we can predict the unmodified branch.
	urlAPIKey, modelAPIKey, _ := buildEndpoint(entry, apiKeyProf)
	urlOAuth, modelOAuth, _ := buildEndpoint(entry, oauthProf)

	rng := rand.New(rand.NewSource(int64(0xBADF00D)))
	const N = 100
	for i := 0; i < N; i++ {
		// Pick which profile we're routing through.
		useOAuth := rng.Intn(2) == 0
		req := ScanRequest{}
		if useOAuth {
			req.ProviderProfile = oauthProf.Key()
		} else {
			req.ProviderProfile = apiKeyProf.Key()
		}
		// Optionally apply each ad-hoc override independently.
		if rng.Intn(2) == 0 {
			req.Model = fmt.Sprintf("override-model-%03d", i)
		}
		if rng.Intn(2) == 0 {
			req.APIKey = fmt.Sprintf("override-api-key-%03d", i)
		}
		if rng.Intn(2) == 0 {
			req.APIBase = fmt.Sprintf("https://override-%03d.example/v1", i)
		}

		ep, err := s.resolveScanCredentials(context.Background(), req, &config.Config{})
		if err != nil {
			t.Fatalf("iter %d: resolveScanCredentials: %v", i, err)
		}

		// Predict each field's expected value per Property 22.
		var wantURL, wantModel string
		if useOAuth {
			wantURL, wantModel = urlOAuth, modelOAuth
		} else {
			wantURL, wantModel = urlAPIKey, modelAPIKey
		}
		if req.Model != "" {
			wantModel = req.Model
		}
		if req.APIBase != "" {
			wantURL = strings.TrimRight(req.APIBase, "/")
		}
		if ep.Model != wantModel {
			t.Fatalf("iter %d: Model = %q, want %q (req=%#v)", i, ep.Model, wantModel, req)
		}
		if ep.URL != wantURL {
			t.Fatalf("iter %d: URL = %q, want %q (req=%#v)", i, ep.URL, wantURL, req)
		}

		// APIKey precedence + Auth flip when override is set.
		if req.APIKey != "" {
			if ep.APIKey != req.APIKey {
				t.Fatalf("iter %d: APIKey = %q, want override %q", i, ep.APIKey, req.APIKey)
			}
			if ep.Auth != llm.AuthAPIKey {
				t.Fatalf("iter %d: Auth = %q with override APIKey, want %q", i, ep.Auth, llm.AuthAPIKey)
			}
			if ep.AccessToken != "" {
				t.Fatalf("iter %d: AccessToken not cleared on APIKey override: %q", i, ep.AccessToken)
			}
		} else if useOAuth {
			// No APIKey override AND OAuth profile: Auth must
			// be OAuthBearer, AccessToken from the profile.
			if ep.Auth != llm.AuthOAuthBearer {
				t.Fatalf("iter %d: Auth = %q with OAuth profile and no override, want %q", i, ep.Auth, llm.AuthOAuthBearer)
			}
			if ep.AccessToken != oauthProf.AccessToken {
				t.Fatalf("iter %d: AccessToken = %q, want %q", i, ep.AccessToken, oauthProf.AccessToken)
			}
		} else {
			if ep.Auth != llm.AuthAPIKey {
				t.Fatalf("iter %d: Auth = %q with API-key profile, want %q", i, ep.Auth, llm.AuthAPIKey)
			}
			if ep.APIKey != apiKeyProf.APIKey {
				t.Fatalf("iter %d: APIKey = %q, want stored %q", i, ep.APIKey, apiKeyProf.APIKey)
			}
		}
	}
}

// TestResolveScanCredentials_UnknownProfile400 confirms Property 23:
// a /api/scan body whose ProviderProfile is non-empty but absent
// from Profile_Store returns HTTP 400 ("unknown provider profile")
// AND no scan goroutine is spawned. We verify the latter by
// snapshotting s.instances before/after.
//
// Validates: Requirements 3.3 (no auto-fetch on rejected scan),
// 11.6 (Property 23).
func TestResolveScanCredentials_UnknownProfile400(t *testing.T) {
	s := newTestServer(t, nil)
	if s.profiles == nil || s.catalog == nil {
		t.Fatal("test server profile/catalog stores were not initialized")
	}
	seedCatalogEntry(t, s, "openai", "https://api.openai.com", "openai")

	// Direct resolveScanCredentials call must surface the sentinel.
	_, err := s.resolveScanCredentials(context.Background(), ScanRequest{ProviderProfile: "bogus:nope"}, s.cfg)
	if err == nil || err.Error() != "unknown provider profile" {
		t.Fatalf("resolveScanCredentials err = %v, want errUnknownProviderProfile", err)
	}

	// /api/scan handler path — the 400 must arrive BEFORE any
	// instance is created. Snapshot the instances map to assert
	// it is unchanged.
	s.instancesMu.RLock()
	beforeCount := len(s.instances)
	s.instancesMu.RUnlock()

	body := strings.NewReader(`{"targets":["https://example.test"],"provider_profile":"bogus:nope","scan_mode":"single"}`)
	rr := httptest.NewRecorder()
	s.handleScan(rr, httptest.NewRequest(http.MethodPost, "/api/scan", body))
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("scan status = %d body=%s, want 400", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "unknown provider profile") {
		t.Fatalf("scan body = %q, want canonical message", rr.Body.String())
	}

	s.instancesMu.RLock()
	afterCount := len(s.instances)
	s.instancesMu.RUnlock()
	if afterCount != beforeCount {
		t.Fatalf("instances count changed despite 400: before=%d after=%d", beforeCount, afterCount)
	}
}

// ---------- Property 24: Auth gate ----------

// newRoutesGated is the canonical list of new routes (catalog +
// profile + OAuth). Each entry maps a (method, path) tuple to the
// handler the dashboard mux dispatches to. We test against the
// real handler functions (rather than building a mux) so the test
// remains stable even if Server.Start changes how it wires the
// dispatcher subtree.
type newRouteCase struct {
	method  string
	path    string
	handler http.HandlerFunc
}

func newRoutesUnderAuth(s *Server) []newRouteCase {
	return []newRouteCase{
		{http.MethodGet, "/api/providers", s.handleListProviders},
		{http.MethodPost, "/api/providers", s.handleCreateProvider},
		{http.MethodPut, "/api/providers/openai", s.handleUpdateProvider},
		{http.MethodDelete, "/api/providers/openai", s.handleDeleteProvider},
		{http.MethodPost, "/api/providers/import-openclaw", s.handleImportOpenclaw},
		{http.MethodPost, "/api/providers/migrate-legacy", s.handleLegacyMigrate},
		{http.MethodGet, "/api/providers/migrate-legacy/status", s.handleLegacyMigrateStatus},
		{http.MethodGet, "/api/auth/profiles", s.handleListProfiles},
		{http.MethodPost, "/api/auth/profiles/api-key", s.handleCreateAPIKeyProfile},
		{http.MethodPost, "/api/auth/profiles/oauth/start", s.handleOAuthStart},
		{http.MethodPost, "/api/auth/profiles/oauth/complete", s.handleOAuthComplete},
		{http.MethodPost, "/api/auth/profiles/openai:default/refresh", s.handleProfileRefresh},
		{http.MethodDelete, "/api/auth/profiles/openai:default", s.handleDeleteProfile},
	}
}

// TestNewRoutes_AllReturn401WithoutSession asserts Property 24:
// every new route, when wrapped by authMiddleware on a server with
// auth configured but no valid session cookie, returns 401. The
// CSRF leg is exercised separately in csrf_test.go (Property 25);
// here we set a valid same-origin Origin header so CSRF passes and
// the only failing gate is the session check.
//
// Validates: Requirements 12.4 (Property 24), 15.1, 15.2.
func TestNewRoutes_AllReturn401WithoutSession(t *testing.T) {
	resetAuthSessionsForTest()
	cfg := &config.Config{Username: "admin", Password: "secret"}
	s := newTestServer(t, cfg)
	mw := authMiddleware(s.cfg)

	cases := newRoutesUnderAuth(s)
	for _, c := range cases {
		t.Run(c.method+" "+c.path, func(t *testing.T) {
			req := httptest.NewRequest(c.method, c.path, strings.NewReader("{}"))
			req.Host = "x.local"
			// Same-origin: makes CSRF pass so the session
			// gate is the only remaining failure mode.
			req.Header.Set("Origin", "http://x.local")

			handler := mw(c.handler)
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)

			if rr.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d body=%q, want 401", rr.Code, rr.Body.String())
			}
		})
	}
}

// ---------- Property 23/12.5 surrounding tests ----------

// TestScanRoute_ProviderProfileGatedOnAuth confirms the /api/scan
// route's combined gate behavior:
//
//   - Without a session cookie, the request is rejected at the
//     auth layer (401) before any provider_profile lookup runs.
//   - With a session cookie but a bogus provider_profile, the
//     request is rejected at the resolver (400 "unknown provider
//     profile") before any scan goroutine is spawned.
//
// The session-gated path exercises both R11.5 (auth requirement)
// and R11.6 (early 400) on the same request flow.
//
// Validates: Requirements 11.5, 11.6, 12.4.
func TestScanRoute_ProviderProfileGatedOnAuth(t *testing.T) {
	resetAuthSessionsForTest()
	cfg := &config.Config{Username: "admin", Password: "secret"}
	s := newTestServer(t, cfg)
	if s.profiles == nil || s.catalog == nil {
		t.Fatal("test server profile/catalog stores were not initialized")
	}
	mw := authMiddleware(s.cfg)
	handler := mw(http.HandlerFunc(s.handleScan))

	// Step 1 — no session: expect 401.
	body := strings.NewReader(`{"targets":["https://example.test"],"provider_profile":"openai:bogus","scan_mode":"single"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/scan", body)
	req.Host = "x.local"
	req.Header.Set("Origin", "http://x.local")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated scan status = %d body=%q, want 401", rr.Code, rr.Body.String())
	}

	// Step 2 — register a session and retry with the cookie.
	authSessionsMu.Lock()
	authSessions["sess-1"] = time.Now().Add(time.Hour)
	authSessionsMu.Unlock()

	body = strings.NewReader(`{"targets":["https://example.test"],"provider_profile":"openai:bogus","scan_mode":"single"}`)
	req = httptest.NewRequest(http.MethodPost, "/api/scan", body)
	req.Host = "x.local"
	req.Header.Set("Origin", "http://x.local")
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "sess-1"})
	rr = httptest.NewRecorder()

	s.instancesMu.RLock()
	beforeCount := len(s.instances)
	s.instancesMu.RUnlock()

	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("authenticated bogus profile status = %d body=%q, want 400", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "unknown provider profile") {
		t.Fatalf("scan body = %q, want canonical R11.6 message", rr.Body.String())
	}

	s.instancesMu.RLock()
	afterCount := len(s.instances)
	s.instancesMu.RUnlock()
	if afterCount != beforeCount {
		t.Fatalf("instances count changed despite 400: before=%d after=%d", beforeCount, afterCount)
	}
}

// ---------- Dashboard mux + backwards compatibility ----------

// TestDashboardMux_DoesNotRegisterOAuthCallback asserts Requirement
// 13.3: `/oauth/callback` MUST NOT appear in the dashboardRoutes
// slice. The PKCE driver allocates its own ephemeral 127.0.0.1
// listener per flow start; mounting the callback on the dashboard
// mux would expose it to long-lived network exposure and to CSRF.
//
// Validates: Requirement 13.3.
func TestDashboardMux_DoesNotRegisterOAuthCallback(t *testing.T) {
	for _, route := range dashboardRoutes {
		if route == "/oauth/callback" || strings.HasSuffix(route, "/oauth/callback") {
			t.Fatalf("dashboardRoutes registered %q — PKCE callback must not be on the dashboard mux", route)
		}
	}
}

// TestExistingAuthRoutesUnchanged asserts Requirement 15.1 / 15.2:
// the existing /api/auth/login, /api/auth/logout, /api/auth/status
// routes still work exactly as documented before this spec landed.
//
// Validates: Requirements 15.1, 15.2.
func TestExistingAuthRoutesUnchanged(t *testing.T) {
	resetAuthSessionsForTest()
	cfg := &config.Config{
		Username:          "admin",
		Password:          "secret",
		RateLimitRequests: 60,
		RateLimitWindow:   60,
	}
	s := newTestServer(t, cfg)

	// /api/auth/status (unauthenticated) — auth_enabled=true, authenticated=false.
	rr := httptest.NewRecorder()
	s.handleAuthStatus(rr, httptest.NewRequest(http.MethodGet, "/api/auth/status", nil))
	if !strings.Contains(rr.Body.String(), `"auth_enabled":true`) ||
		!strings.Contains(rr.Body.String(), `"authenticated":false`) {
		t.Fatalf("unauthenticated status body changed: %s", rr.Body.String())
	}

	// /api/auth/login — POST returns a session cookie.
	rr = httptest.NewRecorder()
	loginBody := strings.NewReader(`{"username":"admin","password":"secret"}`)
	s.handleLogin(rr, httptest.NewRequest(http.MethodPost, "/api/auth/login", loginBody))
	if rr.Code != http.StatusOK {
		t.Fatalf("login status = %d body=%q", rr.Code, rr.Body.String())
	}
	cookies := rr.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != sessionCookieName {
		t.Fatalf("login cookie shape changed: %#v", cookies)
	}
	cookie := cookies[0]

	// /api/auth/status (authenticated) — flips to authenticated=true.
	req := httptest.NewRequest(http.MethodGet, "/api/auth/status", nil)
	req.AddCookie(cookie)
	rr = httptest.NewRecorder()
	s.handleAuthStatus(rr, req)
	if !strings.Contains(rr.Body.String(), `"authenticated":true`) {
		t.Fatalf("authenticated status body changed: %s", rr.Body.String())
	}

	// /api/auth/logout — POST clears the session.
	req = httptest.NewRequest(http.MethodPost, "/api/auth/logout", nil)
	req.AddCookie(cookie)
	rr = httptest.NewRecorder()
	s.handleLogout(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("logout status = %d body=%q", rr.Code, rr.Body.String())
	}
	if isValidSession(cookie.Value) {
		t.Fatal("session remained valid after logout")
	}
}

// ---------- Property 27: env file purity ----------

// TestEnvFile_NotPollutedByCatalogOrProfileWrites asserts Property
// 27: arbitrary catalog Create/Update/Delete + profile Put/Delete
// operations leave ~/.xalgorix.env byte-identical. The env file is
// the single canonical store for the legacy free-text Settings
// path; the new catalog/profile surface persists exclusively under
// ~/.xalgorix/data/, never via env-var writes.
//
// Validates: Requirements 15.3, 15.4, 15.5 (Property 27).
func TestEnvFile_NotPollutedByCatalogOrProfileWrites(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	envPath := filepath.Join(home, ".xalgorix.env")
	// Seed an env file with realistic legacy content. The
	// importer, catalog handlers, and profile handlers must
	// never touch any of these lines.
	original := []byte("XALGORIX_LLM=openai/gpt-5\nXALGORIX_API_KEY=legacy-key-1234567890\nXALGORIX_API_BASE=https://api.openai.com/v1\nAGENTMAIL_API_KEY=agentmail-key-1234567890\n")
	if err := os.WriteFile(envPath, original, 0o600); err != nil {
		t.Fatalf("seed env file: %v", err)
	}
	originalHash := fileSHA256(t, envPath)

	s := newTestServer(t, nil)
	if s.profiles == nil || s.catalog == nil {
		t.Fatal("test server profile/catalog stores were not initialized")
	}

	// Pre-seed two catalog entries so profile Puts can land on
	// known providers without exhausting the available cells.
	seedCatalogEntry(t, s, "alpha", "https://alpha.example", "openai")
	seedCatalogEntry(t, s, "beta", "https://beta.example", "anthropic")

	rng := rand.New(rand.NewSource(int64(0xE1F11E)))
	const N = 100
	knownEntries := map[string]bool{"alpha": true, "beta": true}
	knownProfiles := map[string]bool{}

	for i := 0; i < N; i++ {
		switch rng.Intn(5) {
		case 0:
			// Catalog Create — pick a fresh id.
			id := fmt.Sprintf("c%03d", i)
			err := s.catalog.Create(context.Background(), providers.Entry{
				ID:          id,
				DisplayName: id + " disp",
				BaseURL:     "https://" + id + ".example",
				HeaderStyle: "openai",
			})
			if err == nil {
				knownEntries[id] = true
			}
		case 1:
			// Catalog Update — pick a known id.
			id := pickRandomKey(rng, knownEntries)
			if id == "" {
				continue
			}
			_ = s.catalog.Update(context.Background(), id, providers.Entry{
				ID:          id,
				DisplayName: id + " disp v2",
				BaseURL:     "https://" + id + "-v2.example",
				HeaderStyle: "openai",
			})
		case 2:
			// Catalog Delete — pick a known id (but never alpha/beta so we
			// keep a known provider available for profile writes).
			candidates := map[string]bool{}
			for id := range knownEntries {
				if id != "alpha" && id != "beta" {
					candidates[id] = true
				}
			}
			id := pickRandomKey(rng, candidates)
			if id == "" {
				continue
			}
			if err := s.catalog.Delete(context.Background(), id); err == nil {
				delete(knownEntries, id)
			}
		case 3:
			// Profile Put — alternate provider + fresh id.
			provider := "alpha"
			if rng.Intn(2) == 1 {
				provider = "beta"
			}
			profID := fmt.Sprintf("p%03d", i)
			p := auth.Profile{
				Provider:  provider,
				ProfileID: profID,
				Type:      auth.APIKey,
				APIKey:    randomToken(rng, 16),
			}
			if err := s.profiles.Put(context.Background(), p); err == nil {
				knownProfiles[p.Key()] = true
			}
		case 4:
			// Profile Delete — known key.
			key := pickRandomKey(rng, knownProfiles)
			if key == "" {
				continue
			}
			if _, err := s.profiles.Delete(context.Background(), key); err == nil {
				delete(knownProfiles, key)
			}
		}

		// Re-check the env file hash after every op so a single
		// rogue write is caught at the iteration that introduced
		// it instead of being smeared across the whole run.
		if h := fileSHA256(t, envPath); h != originalHash {
			t.Fatalf("iter %d: env file changed (hash %s, want %s)", i, h, originalHash)
		}
	}

	// Final mode check — env file mode must remain 0600 after
	// the workload (no handler should have rewritten with looser
	// permissions).
	info, err := os.Stat(envPath)
	if err != nil {
		t.Fatalf("stat env file: %v", err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Fatalf("env file mode = %o, want 0600", mode)
	}
}

// pickRandomKey returns a uniformly-random key from m, or "" when
// m is empty. Used by the env-purity test to drive Update/Delete
// operations against the running set of known entries.
func pickRandomKey(rng *rand.Rand, m map[string]bool) string {
	if len(m) == 0 {
		return ""
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys[rng.Intn(len(keys))]
}

// fileSHA256 returns the lowercase hex SHA-256 of path. Used as a
// stable byte-identical-ness probe for the env file and any other
// "this file should not change" assertions.
func fileSHA256(t *testing.T, path string) string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		t.Fatalf("hash %s: %v", path, err)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// ---------- Openclaw is never auto-fetched ----------

// TestOpenclaw_NeverFetchedAutomatically asserts Requirement 3.3:
// the openclaw catalog is fetched only on explicit operator action
// (POST /api/providers/import-openclaw). No background goroutine,
// startup hook, or polling loop in the production code path may
// dial the openclaw URL on its own.
//
// We exercise this by:
//
//  1. Standing up an httptest.NewTLSServer whose handler increments
//     an atomic counter on every request (the openclaw client
//     requires HTTPS per ImportOpenclaw's scheme check).
//  2. Replacing s.catalog with a Service that holds a TLS-skipping
//     http.Client so the import handler can reach the stub.
//  3. Letting the server settle for a generous wait window with
//     XALGORIX_OPENCLAW_URL set to the stub.
//  4. Asserting the counter is still zero after the wait.
//  5. Sanity check: an explicit POST /api/providers/import-openclaw
//     against the stub URL must hit the counter — proves the test
//     instrumentation can detect a fetch when one occurs.
//
// Validates: Requirement 3.3.
func TestOpenclaw_NeverFetchedAutomatically(t *testing.T) {
	var hits int64
	stub := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&hits, 1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("[]"))
	}))
	defer stub.Close()
	t.Setenv("XALGORIX_OPENCLAW_URL", stub.URL)

	// newTestServer runs NewServer which is the only path that
	// could plausibly trip an auto-import. Construct it and let
	// any background goroutines run for a beat.
	s := newTestServer(t, nil)
	if s.catalog == nil {
		t.Fatal("catalog store not initialized")
	}

	// Re-wire the catalog with an http.Client whose Transport
	// trusts the test server's self-signed cert so the explicit
	// import sanity check at the bottom can reach the stub. The
	// catalog file shape doesn't change — we just swap the in-
	// process Service.
	catalogPath := filepath.Join(s.dataDir, "providers.json")
	cat, err := providers.NewService(catalogPath, providers.WithHTTPClient(stub.Client()))
	if err != nil {
		t.Fatalf("rewire catalog: %v", err)
	}
	s.catalog = cat

	// Generous settle window — the auto-resume goroutine in
	// Server.Start sleeps 5 seconds before doing work, but we
	// never call Start() here; this delay covers any hypothetical
	// constructor-side goroutine.
	time.Sleep(500 * time.Millisecond)

	if got := atomic.LoadInt64(&hits); got != 0 {
		t.Fatalf("openclaw stub was hit %d times without operator action", got)
	}

	// Sanity check: an explicit POST /api/providers/import-openclaw
	// to the stub URL must hit the counter — proves the test
	// infrastructure can detect a fetch when one actually occurs.
	body := strings.NewReader(fmt.Sprintf(`{"url":%q}`, stub.URL))
	rr := httptest.NewRecorder()
	s.handleImportOpenclaw(rr, httptest.NewRequest(http.MethodPost, "/api/providers/import-openclaw", body))
	if rr.Code != http.StatusOK {
		t.Fatalf("explicit import status = %d body=%q", rr.Code, rr.Body.String())
	}
	if got := atomic.LoadInt64(&hits); got == 0 {
		t.Fatal("explicit import did not hit the stub server — test instrumentation broken")
	}
}
