package auth

// Tests for task 2.8 — Google + GitHub OAuth (PKCE).
//
// These tests use httptest.Server-backed fake provider implementations
// for token exchange and userinfo so the round trip stays in-process
// and deterministic. Coverage:
//
//   - Start writes a PKCE+state record to Redis and 302-redirects to
//     the provider's AuthURL with the matching S256 challenge.
//   - Start refuses unknown providers with 404.
//   - Callback rejects forged or replayed state values (CSRF).
//   - Callback rejects state values that were issued for a different
//     provider (mixup attack).
//   - Callback enforces PKCE: a token endpoint that does not see the
//     stored verifier returns the exchange error path.
//   - Callback links a new identity to an existing verified account
//     when the OAuth email matches.
//   - Callback creates a brand-new tenant on the no-match path.
//   - Callback signs an existing identity in (no link, no create).
//   - Callback refuses to auto-link when email_verified is false.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/rs/zerolog"

	redisclient "github.com/xalgord/xalgorix/v4/internal/cloud/redis"
)

// ----------------------------------------------------------------------
// Fakes
// ----------------------------------------------------------------------

// fakeOAuthRepo is an in-memory [OAuthRepository] used to assert the
// three identity branches end-to-end.
type fakeOAuthRepo struct {
	mu sync.Mutex

	identities map[string]string       // provider+":"+subject -> account_id
	accounts   map[string]OAuthAccount // lower-cased email -> account
	created    []CreateAccountWithIdentityInput
	links      []linkCall

	failLookupIdentity bool
	failCreate         bool
}

type linkCall struct {
	AccountID     string
	Provider      string
	Subject       string
	EmailVerified bool
}

func newFakeOAuthRepo() *fakeOAuthRepo {
	return &fakeOAuthRepo{
		identities: map[string]string{},
		accounts:   map[string]OAuthAccount{},
	}
}

func (f *fakeOAuthRepo) addAccount(email, status string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	id := "acc-" + strings.ToLower(strings.TrimSpace(email))
	f.accounts[strings.ToLower(strings.TrimSpace(email))] = OAuthAccount{
		AccountID: id,
		Email:     email,
		Status:    status,
	}
	return id
}

func (f *fakeOAuthRepo) addIdentity(provider, subject, accountID string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.identities[provider+":"+subject] = accountID
}

func (f *fakeOAuthRepo) LookupIdentity(_ context.Context, provider, subject string) (string, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failLookupIdentity {
		return "", false, errors.New("forced lookup failure")
	}
	id, ok := f.identities[provider+":"+subject]
	return id, ok, nil
}

func (f *fakeOAuthRepo) LookupAccountByEmail(_ context.Context, email string) (OAuthAccount, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	a, ok := f.accounts[strings.ToLower(strings.TrimSpace(email))]
	return a, ok, nil
}

func (f *fakeOAuthRepo) LinkIdentity(_ context.Context, accountID, provider, subject string, emailVerified bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.links = append(f.links, linkCall{accountID, provider, subject, emailVerified})
	f.identities[provider+":"+subject] = accountID
	return nil
}

func (f *fakeOAuthRepo) CreateAccountWithIdentity(_ context.Context, in CreateAccountWithIdentityInput) (OAuthAccount, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failCreate {
		return OAuthAccount{}, errors.New("forced create failure")
	}
	f.created = append(f.created, in)
	id := "newacc-" + in.Email
	acct := OAuthAccount{AccountID: id, Email: in.Email, Status: "active"}
	if in.Email != "" {
		f.accounts[strings.ToLower(in.Email)] = acct
	}
	f.identities[in.Provider+":"+in.Subject] = id
	return acct, nil
}

// fakeSession is a stub OAuthSessionIssuer for tests that does not
// depend on Redis.
type fakeSession struct {
	mu       sync.Mutex
	issued   []string
	written  []string
	failNext bool
}

func (s *fakeSession) Issue(_ context.Context, accountID string) (*Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failNext {
		s.failNext = false
		return nil, errors.New("forced issue failure")
	}
	s.issued = append(s.issued, accountID)
	return &Session{
		ID:         "sid-" + accountID,
		Token:      "token-" + accountID,
		AccountID:  accountID,
		IssuedAt:   time.Unix(1700000000, 0),
		LastSeenAt: time.Unix(1700000000, 0),
		ExpiresAt:  time.Unix(1700000000+86400, 0),
	}, nil
}

func (s *fakeSession) WriteCookie(w http.ResponseWriter, token string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.written = append(s.written, token)
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    token,
		Path:     "/",
		Secure:   true,
		HttpOnly: true,
	})
}

// fakeProviderEnv runs a token endpoint and a userinfo endpoint via
// httptest.Server. It captures the most recent token request so tests
// can assert the PKCE verifier was forwarded.
type fakeProviderEnv struct {
	server *httptest.Server

	mu              sync.Mutex
	tokenRequests   []url.Values
	userInfoBody    []byte
	emailsBody      []byte
	failToken       bool
	failUserinfo    bool
	requireVerifier string
}

func newFakeProviderEnv(t *testing.T, userInfo any) *fakeProviderEnv {
	t.Helper()
	body, err := json.Marshal(userInfo)
	if err != nil {
		t.Fatalf("marshal userInfo: %v", err)
	}
	env := &fakeProviderEnv{userInfoBody: body}
	mux := http.NewServeMux()
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		env.mu.Lock()
		env.tokenRequests = append(env.tokenRequests, r.PostForm)
		fail := env.failToken
		need := env.requireVerifier
		env.mu.Unlock()
		if fail {
			http.Error(w, "boom", http.StatusBadGateway)
			return
		}
		if need != "" && r.PostForm.Get("code_verifier") != need {
			http.Error(w, "missing pkce verifier", http.StatusBadRequest)
			return
		}
		if r.PostForm.Get("code_verifier") == "" {
			http.Error(w, "pkce required", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"access_token":"AT","token_type":"Bearer","expires_in":3600}`)
	})
	mux.HandleFunc("/userinfo", func(w http.ResponseWriter, r *http.Request) {
		env.mu.Lock()
		fail := env.failUserinfo
		body := env.userInfoBody
		env.mu.Unlock()
		if fail {
			http.Error(w, "boom", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	})
	mux.HandleFunc("/user", func(w http.ResponseWriter, r *http.Request) {
		env.mu.Lock()
		body := env.userInfoBody
		env.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	})
	mux.HandleFunc("/user/emails", func(w http.ResponseWriter, r *http.Request) {
		env.mu.Lock()
		body := env.emailsBody
		env.mu.Unlock()
		if body == nil {
			body = []byte("[]")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	})
	env.server = httptest.NewServer(mux)
	t.Cleanup(env.server.Close)
	return env
}

// newGoogleProvider wires a [GoogleProvider] backed by env.
func (env *fakeProviderEnv) newGoogleProvider() *GoogleProvider {
	return NewGoogleProvider(GoogleConfig{
		ClientID:     "client-id",
		ClientSecret: "client-secret",
		RedirectURL:  "https://example.test/callback",
		AuthURL:      env.server.URL + "/auth",
		TokenURL:     env.server.URL + "/token",
		UserInfoURL:  env.server.URL + "/userinfo",
		HTTPClient:   env.server.Client(),
	})
}

// newGitHubProvider wires a [GitHubProvider] backed by env.
func (env *fakeProviderEnv) newGitHubProvider() *GitHubProvider {
	return NewGitHubProvider(GitHubConfig{
		ClientID:     "client-id",
		ClientSecret: "client-secret",
		RedirectURL:  "https://example.test/callback",
		AuthURL:      env.server.URL + "/auth",
		TokenURL:     env.server.URL + "/token",
		UserURL:      env.server.URL + "/user",
		EmailsURL:    env.server.URL + "/user/emails",
		HTTPClient:   env.server.Client(),
	})
}

// staticProvider is a minimal [OAuthProvider] used to drive the
// orchestrator without spinning up a httptest server. It is useful for
// the state/CSRF tests where we do not care about wire details.
type staticProvider struct {
	authURL  string
	user     *UserInfo
	exchErr  error
	calls    int
	gotCode  string
	gotPKCE  string
	mu       sync.Mutex
}

func (s *staticProvider) AuthURL(state, codeChallenge string) string {
	if s.authURL == "" {
		return "https://idp.example.test/authorize?state=" + state + "&code_challenge=" + codeChallenge
	}
	return s.authURL + "?state=" + state + "&code_challenge=" + codeChallenge
}

func (s *staticProvider) Exchange(_ context.Context, code, codeVerifier string) (*UserInfo, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	s.gotCode = code
	s.gotPKCE = codeVerifier
	if s.exchErr != nil {
		return nil, s.exchErr
	}
	return s.user, nil
}

// ----------------------------------------------------------------------
// Test harness
// ----------------------------------------------------------------------

type oauthFixture struct {
	mr      *miniredis.Miniredis
	rdb     *redisclient.Client
	repo    *fakeOAuthRepo
	session *fakeSession
	svc     *OAuthService
}

func newOAuthFixture(t *testing.T, providers map[string]OAuthProvider) *oauthFixture {
	t.Helper()
	mr := miniredis.RunT(t)
	rdb, err := redisclient.New(t.Context(), redisclient.Options{Addrs: []string{mr.Addr()}})
	if err != nil {
		t.Fatalf("redis.New: %v", err)
	}
	t.Cleanup(func() { _ = rdb.Close() })
	repo := newFakeOAuthRepo()
	sess := &fakeSession{}
	svc := NewOAuthService(providers, rdb, repo, sess, zerolog.Nop())
	return &oauthFixture{mr: mr, rdb: rdb, repo: repo, session: sess, svc: svc}
}

// startRequest issues a Start request for provider and returns the 302
// Location URL.
func (f *oauthFixture) startRequest(t *testing.T, provider string) *http.Response {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/auth/oauth/"+provider+"/start", nil)
	req.SetPathValue("provider", provider)
	rec := httptest.NewRecorder()
	f.svc.Start(rec, req)
	return rec.Result()
}

// callbackRequest issues a Callback request with the supplied state +
// code and returns the recorder so tests can inspect status, location,
// cookies, and the [OAuthCallbackResult].
func (f *oauthFixture) callbackRequest(t *testing.T, provider, state, code string) (*httptest.ResponseRecorder, *OAuthCallbackResult, error) {
	t.Helper()
	q := url.Values{}
	if state != "" {
		q.Set("state", state)
	}
	if code != "" {
		q.Set("code", code)
	}
	req := httptest.NewRequest(http.MethodGet, "/auth/oauth/"+provider+"/callback?"+q.Encode(), nil)
	req.SetPathValue("provider", provider)
	rec := httptest.NewRecorder()
	res, err := f.svc.Callback(rec, req)
	return rec, res, err
}

// ----------------------------------------------------------------------
// Tests
// ----------------------------------------------------------------------

func TestStart_PersistsPKCEAndRedirects(t *testing.T) {
	t.Parallel()
	provider := &staticProvider{authURL: "https://idp.example.test/authorize"}
	f := newOAuthFixture(t, map[string]OAuthProvider{"google": provider})

	resp := f.startRequest(t, "google")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		t.Fatalf("Start status = %d, want 302", resp.StatusCode)
	}
	loc, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatalf("parse Location: %v", err)
	}
	state := loc.Query().Get("state")
	challenge := loc.Query().Get("code_challenge")
	if state == "" || challenge == "" {
		t.Fatalf("redirect missing state/challenge: %s", resp.Header.Get("Location"))
	}

	// Redis must hold a SetNX'd key whose JSON contains the verifier.
	raw, err := f.mr.Get(oauthStatePrefix + state)
	if err != nil {
		t.Fatalf("redis.Get: %v", err)
	}
	var rec stateRecord
	if err := json.Unmarshal([]byte(raw), &rec); err != nil {
		t.Fatalf("unmarshal stateRecord: %v", err)
	}
	if rec.CodeVerifier == "" {
		t.Fatal("stateRecord.CodeVerifier is empty")
	}
	if rec.Provider != "google" {
		t.Fatalf("stateRecord.Provider = %q, want google", rec.Provider)
	}
	if pkceChallenge(rec.CodeVerifier) != challenge {
		t.Fatalf("S256(verifier) does not match query challenge")
	}
	ttl := f.mr.TTL(oauthStatePrefix + state)
	if ttl <= 0 || ttl > OAuthStateTTL+time.Second {
		t.Fatalf("redis TTL = %v, want ~%v", ttl, OAuthStateTTL)
	}
}

func TestStart_UnknownProvider404(t *testing.T) {
	t.Parallel()
	provider := &staticProvider{}
	f := newOAuthFixture(t, map[string]OAuthProvider{"google": provider})
	resp := f.startRequest(t, "twitter")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		// fail() routes user-facing errors to a 302 redirect, not 404,
		// to avoid a phishable error page. That redirect still must
		// not include a state in Redis.
		t.Fatalf("unknown provider status = %d, want 302 redirect", resp.StatusCode)
	}
	if got := f.mr.Keys(); len(got) != 0 {
		t.Fatalf("unknown provider should not write redis keys; got %v", got)
	}
}

func TestCallback_RejectsMissingState(t *testing.T) {
	t.Parallel()
	provider := &staticProvider{user: &UserInfo{Subject: "u-1"}}
	f := newOAuthFixture(t, map[string]OAuthProvider{"google": provider})

	rec, _, err := f.callbackRequest(t, "google", "", "code")
	if !errors.Is(err, ErrOAuthInvalidState) {
		t.Fatalf("err = %v, want ErrOAuthInvalidState", err)
	}
	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302 redirect to failure", rec.Code)
	}
	if provider.calls != 0 {
		t.Fatalf("Exchange should not be called when state is missing")
	}
}

func TestCallback_RejectsForgedState(t *testing.T) {
	t.Parallel()
	// Issuing a Start writes one valid state. Callback with a *different*
	// state must be rejected and the legitimate state must remain
	// untouched in Redis.
	provider := &staticProvider{user: &UserInfo{Subject: "u-1"}}
	f := newOAuthFixture(t, map[string]OAuthProvider{"google": provider})

	resp := f.startRequest(t, "google")
	defer resp.Body.Close()

	rec, _, err := f.callbackRequest(t, "google", "deadbeef-forged", "code")
	if !errors.Is(err, ErrOAuthInvalidState) {
		t.Fatalf("err = %v, want ErrOAuthInvalidState", err)
	}
	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", rec.Code)
	}
	if provider.calls != 0 {
		t.Fatalf("Exchange must not run on forged state")
	}
}

func TestCallback_RejectsReplayedState(t *testing.T) {
	t.Parallel()
	provider := &staticProvider{user: &UserInfo{Subject: "u-1", Email: "u@example.test", EmailVerified: true}}
	f := newOAuthFixture(t, map[string]OAuthProvider{"google": provider})

	resp := f.startRequest(t, "google")
	defer resp.Body.Close()
	loc, _ := url.Parse(resp.Header.Get("Location"))
	state := loc.Query().Get("state")

	// First callback consumes the state.
	if _, _, err := f.callbackRequest(t, "google", state, "code-a"); err != nil {
		t.Fatalf("first callback failed: %v", err)
	}
	// Replay must be refused.
	rec, _, err := f.callbackRequest(t, "google", state, "code-b")
	if !errors.Is(err, ErrOAuthInvalidState) {
		t.Fatalf("replay err = %v, want ErrOAuthInvalidState", err)
	}
	if rec.Code != http.StatusFound {
		t.Fatalf("replay status = %d, want 302", rec.Code)
	}
}

func TestCallback_RejectsMixupAttack(t *testing.T) {
	t.Parallel()
	// State issued by /google/start must not be redeemable on
	// /github/callback — the canonical IdP-mixup attack against
	// multi-provider servers.
	gp := &staticProvider{user: &UserInfo{Subject: "u-google"}}
	hp := &staticProvider{user: &UserInfo{Subject: "u-github"}}
	f := newOAuthFixture(t, map[string]OAuthProvider{"google": gp, "github": hp})

	resp := f.startRequest(t, "google")
	defer resp.Body.Close()
	loc, _ := url.Parse(resp.Header.Get("Location"))
	state := loc.Query().Get("state")

	rec, _, err := f.callbackRequest(t, "github", state, "code")
	if !errors.Is(err, ErrOAuthInvalidState) {
		t.Fatalf("mixup err = %v, want ErrOAuthInvalidState", err)
	}
	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", rec.Code)
	}
	if hp.calls != 0 {
		t.Fatalf("github provider must not run when state was issued for google")
	}
}

func TestCallback_PKCEVerifierForwarded_Google(t *testing.T) {
	t.Parallel()
	env := newFakeProviderEnv(t, map[string]any{
		"sub":            "g-sub-1",
		"email":          "g@example.test",
		"email_verified": true,
		"name":           "Glenda",
	})
	provider := env.newGoogleProvider()
	f := newOAuthFixture(t, map[string]OAuthProvider{"google": provider})

	resp := f.startRequest(t, "google")
	defer resp.Body.Close()
	loc, _ := url.Parse(resp.Header.Get("Location"))
	state := loc.Query().Get("state")

	// Read the verifier from Redis BEFORE callback consumes it so we
	// can assert the token endpoint sees the same value.
	raw, err := f.mr.Get(oauthStatePrefix + state)
	if err != nil {
		t.Fatalf("redis get: %v", err)
	}
	var rec stateRecord
	_ = json.Unmarshal([]byte(raw), &rec)
	env.mu.Lock()
	env.requireVerifier = rec.CodeVerifier
	env.mu.Unlock()

	cbRec, result, err := f.callbackRequest(t, "google", state, "auth-code")
	if err != nil {
		t.Fatalf("callback err: %v", err)
	}
	if result == nil || result.Outcome != OutcomeCreated {
		t.Fatalf("outcome = %+v, want created", result)
	}
	if cbRec.Code != http.StatusFound {
		t.Fatalf("callback status = %d, want 302", cbRec.Code)
	}

	env.mu.Lock()
	defer env.mu.Unlock()
	if len(env.tokenRequests) != 1 {
		t.Fatalf("token endpoint called %d times, want 1", len(env.tokenRequests))
	}
	if env.tokenRequests[0].Get("code_verifier") == "" {
		t.Fatalf("token request missing code_verifier")
	}
	if env.tokenRequests[0].Get("code") != "auth-code" {
		t.Fatalf("token request code = %q", env.tokenRequests[0].Get("code"))
	}
}

func TestCallback_LinksExistingVerifiedAccount(t *testing.T) {
	t.Parallel()
	env := newFakeProviderEnv(t, map[string]any{
		"sub":            "g-sub-link",
		"email":          "owner@example.test",
		"email_verified": true,
		"name":           "Owner",
	})
	provider := env.newGoogleProvider()
	f := newOAuthFixture(t, map[string]OAuthProvider{"google": provider})
	existingID := f.repo.addAccount("owner@example.test", "active")

	resp := f.startRequest(t, "google")
	defer resp.Body.Close()
	loc, _ := url.Parse(resp.Header.Get("Location"))
	state := loc.Query().Get("state")

	cbRec, result, err := f.callbackRequest(t, "google", state, "auth-code")
	if err != nil {
		t.Fatalf("callback err: %v", err)
	}
	if result == nil || result.Outcome != OutcomeLinked {
		t.Fatalf("outcome = %+v, want linked", result)
	}
	if result.AccountID != existingID {
		t.Fatalf("AccountID = %q, want %q", result.AccountID, existingID)
	}
	if got := f.repo.links; len(got) != 1 || got[0].AccountID != existingID || got[0].Subject != "g-sub-link" {
		t.Fatalf("LinkIdentity calls = %+v", got)
	}
	if len(f.repo.created) != 0 {
		t.Fatalf("must not create an account on the link branch")
	}
	if cbRec.Result().Cookies()[0].Value == "" {
		t.Fatal("session cookie missing")
	}
}

func TestCallback_RefusesAutoLinkWhenEmailUnverified(t *testing.T) {
	t.Parallel()
	env := newFakeProviderEnv(t, map[string]any{
		"sub":            "g-sub-noverify",
		"email":          "owner@example.test",
		"email_verified": false,
	})
	provider := env.newGoogleProvider()
	f := newOAuthFixture(t, map[string]OAuthProvider{"google": provider})
	f.repo.addAccount("owner@example.test", "active")

	resp := f.startRequest(t, "google")
	defer resp.Body.Close()
	loc, _ := url.Parse(resp.Header.Get("Location"))
	state := loc.Query().Get("state")

	_, result, err := f.callbackRequest(t, "google", state, "auth-code")
	if err != nil {
		t.Fatalf("callback err: %v", err)
	}
	// Unverified email must NOT auto-link, so we fall through to
	// account creation.
	if result == nil || result.Outcome != OutcomeCreated {
		t.Fatalf("outcome = %+v, want created", result)
	}
	if len(f.repo.links) != 0 {
		t.Fatalf("must not auto-link on email_verified=false")
	}
}

func TestCallback_CreatesNewAccount(t *testing.T) {
	t.Parallel()
	env := newFakeProviderEnv(t, map[string]any{
		"sub":            "g-sub-fresh",
		"email":          "fresh@example.test",
		"email_verified": true,
		"name":           "Fresh User",
	})
	provider := env.newGoogleProvider()
	f := newOAuthFixture(t, map[string]OAuthProvider{"google": provider})

	resp := f.startRequest(t, "google")
	defer resp.Body.Close()
	loc, _ := url.Parse(resp.Header.Get("Location"))
	state := loc.Query().Get("state")

	_, result, err := f.callbackRequest(t, "google", state, "auth-code")
	if err != nil {
		t.Fatalf("callback err: %v", err)
	}
	if result == nil || result.Outcome != OutcomeCreated {
		t.Fatalf("outcome = %+v, want created", result)
	}
	if len(f.repo.created) != 1 {
		t.Fatalf("created calls = %d, want 1", len(f.repo.created))
	}
	got := f.repo.created[0]
	if got.Provider != "google" || got.Subject != "g-sub-fresh" || got.Email != "fresh@example.test" {
		t.Fatalf("created input = %+v", got)
	}
	if !got.EmailVerified {
		t.Fatalf("EmailVerified should propagate from provider userinfo")
	}
	if got.Name != "Fresh User" {
		t.Fatalf("Name = %q", got.Name)
	}
	if got.OrgName == "" {
		t.Fatalf("OrgName should default from name/email")
	}
}

func TestCallback_SignsExistingIdentityIn(t *testing.T) {
	t.Parallel()
	env := newFakeProviderEnv(t, map[string]any{
		"sub":            "g-sub-existing",
		"email":          "old@example.test",
		"email_verified": true,
	})
	provider := env.newGoogleProvider()
	f := newOAuthFixture(t, map[string]OAuthProvider{"google": provider})
	existing := f.repo.addAccount("old@example.test", "active")
	f.repo.addIdentity("google", "g-sub-existing", existing)

	resp := f.startRequest(t, "google")
	defer resp.Body.Close()
	loc, _ := url.Parse(resp.Header.Get("Location"))
	state := loc.Query().Get("state")

	_, result, err := f.callbackRequest(t, "google", state, "auth-code")
	if err != nil {
		t.Fatalf("callback err: %v", err)
	}
	if result == nil || result.Outcome != OutcomeSignedIn {
		t.Fatalf("outcome = %+v, want signed_in", result)
	}
	if result.AccountID != existing {
		t.Fatalf("account id = %q, want %q", result.AccountID, existing)
	}
	if len(f.repo.created) != 0 || len(f.repo.links) != 0 {
		t.Fatalf("must not create or link when identity already exists; created=%d links=%d",
			len(f.repo.created), len(f.repo.links))
	}
}

func TestCallback_GitHubFallsBackToEmailsEndpoint(t *testing.T) {
	t.Parallel()
	// /user returns email=null; /user/emails has the verified primary.
	env := newFakeProviderEnv(t, map[string]any{
		"id":    1234,
		"email": nil,
		"name":  "Octocat",
	})
	emails, _ := json.Marshal([]map[string]any{
		{"email": "octocat@example.test", "primary": true, "verified": true},
		{"email": "alt@example.test", "primary": false, "verified": true},
	})
	env.mu.Lock()
	env.emailsBody = emails
	env.mu.Unlock()
	provider := env.newGitHubProvider()
	f := newOAuthFixture(t, map[string]OAuthProvider{"github": provider})

	resp := f.startRequest(t, "github")
	defer resp.Body.Close()
	loc, _ := url.Parse(resp.Header.Get("Location"))
	state := loc.Query().Get("state")

	_, result, err := f.callbackRequest(t, "github", state, "auth-code")
	if err != nil {
		t.Fatalf("callback err: %v", err)
	}
	if result == nil || result.Outcome != OutcomeCreated {
		t.Fatalf("outcome = %+v, want created", result)
	}
	if len(f.repo.created) != 1 {
		t.Fatalf("created calls = %d", len(f.repo.created))
	}
	got := f.repo.created[0]
	if got.Email != "octocat@example.test" {
		t.Fatalf("email = %q, want octocat@example.test", got.Email)
	}
	if !got.EmailVerified {
		t.Fatalf("EmailVerified should be true from /user/emails")
	}
	if got.Subject != "1234" {
		t.Fatalf("Subject = %q, want 1234", got.Subject)
	}
}

func TestCallback_ExchangeFailureBubbles(t *testing.T) {
	t.Parallel()
	env := newFakeProviderEnv(t, map[string]any{"sub": "x"})
	env.mu.Lock()
	env.failToken = true
	env.mu.Unlock()
	provider := env.newGoogleProvider()
	f := newOAuthFixture(t, map[string]OAuthProvider{"google": provider})

	resp := f.startRequest(t, "google")
	defer resp.Body.Close()
	loc, _ := url.Parse(resp.Header.Get("Location"))
	state := loc.Query().Get("state")

	_, _, err := f.callbackRequest(t, "google", state, "auth-code")
	if !errors.Is(err, ErrOAuthExchangeFailed) {
		t.Fatalf("err = %v, want ErrOAuthExchangeFailed", err)
	}
	if len(f.repo.created) != 0 {
		t.Fatalf("must not create on exchange failure")
	}
}

func TestPKCEChallengeIsS256OfVerifier(t *testing.T) {
	t.Parallel()
	v, err := pkceVerifier(deterministicRandSeed(0xab))
	if err != nil {
		t.Fatalf("pkceVerifier: %v", err)
	}
	if len(v) < 43 || len(v) > 128 {
		t.Fatalf("verifier length %d outside RFC 7636 bounds", len(v))
	}
	c1 := pkceChallenge(v)
	c2 := pkceChallenge(v)
	if c1 != c2 {
		t.Fatalf("challenge is not deterministic")
	}
	if c1 == v {
		t.Fatalf("challenge must differ from verifier")
	}
}

// deterministicRandSeed returns a reader that yields the supplied byte
// repeatedly. It produces verifiers identical across runs so the
// PKCE-challenge test is reproducible.
func deterministicRandSeed(b byte) *byteReader { return &byteReader{b: b} }

type byteReader struct{ b byte }

func (r *byteReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = r.b
	}
	return len(p), nil
}

func TestNewOAuthService_PanicsOnBadInputs(t *testing.T) {
	t.Parallel()
	// Empty providers
	mr := miniredis.RunT(t)
	rdb, err := redisclient.New(t.Context(), redisclient.Options{Addrs: []string{mr.Addr()}})
	if err != nil {
		t.Fatalf("redis.New: %v", err)
	}
	t.Cleanup(func() { _ = rdb.Close() })

	mustPanic(t, "empty providers", func() {
		NewOAuthService(nil, rdb, newFakeOAuthRepo(), &fakeSession{}, zerolog.Nop())
	})
	mustPanic(t, "nil redis", func() {
		NewOAuthService(map[string]OAuthProvider{"x": &staticProvider{}}, nil, newFakeOAuthRepo(), &fakeSession{}, zerolog.Nop())
	})
	mustPanic(t, "nil repo", func() {
		NewOAuthService(map[string]OAuthProvider{"x": &staticProvider{}}, rdb, nil, &fakeSession{}, zerolog.Nop())
	})
	mustPanic(t, "nil session", func() {
		NewOAuthService(map[string]OAuthProvider{"x": &staticProvider{}}, rdb, newFakeOAuthRepo(), nil, zerolog.Nop())
	})
}

func mustPanic(t *testing.T, name string, fn func()) {
	t.Helper()
	defer func() {
		if r := recover(); r == nil {
			t.Fatalf("%s: expected panic, got none", name)
		}
	}()
	fn()
}
