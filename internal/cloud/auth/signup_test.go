package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/rs/zerolog"

	redisclient "github.com/xalgord/xalgorix/v4/internal/cloud/redis"
)

// ----------------------------------------------------------------------
// Fakes
// ----------------------------------------------------------------------

// fakeSignupRepo is an in-memory [SignupRepository]. It records every
// call so tests can assert that the persist step executed (or did not)
// and exposes a knob for forcing a duplicate-email failure on demand.
type fakeSignupRepo struct {
	mu        sync.Mutex
	emails    map[string]string // canonical email → account_id
	calls     []CreateAccountWithOrgInput
	forceErr  error
	nextOrgID string
}

func newFakeSignupRepo() *fakeSignupRepo {
	return &fakeSignupRepo{emails: make(map[string]string)}
}

func (r *fakeSignupRepo) CreateAccountWithOrg(_ context.Context, in CreateAccountWithOrgInput) (SignupAccount, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, in)
	if r.forceErr != nil {
		return SignupAccount{}, r.forceErr
	}
	canonical := strings.ToLower(strings.TrimSpace(in.Email))
	if _, exists := r.emails[canonical]; exists {
		return SignupAccount{}, ErrDuplicateEmail
	}
	accountID := "acc-" + canonical
	orgID := r.nextOrgID
	if orgID == "" {
		orgID = "org-" + canonical
	}
	r.emails[canonical] = accountID
	return SignupAccount{
		AccountID:   accountID,
		OrgID:       orgID,
		WorkspaceID: "ws-default-" + canonical,
		Email:       in.Email,
	}, nil
}

// fakePwner is a stub [Pwner] that returns whatever the test programs.
// It also records every (ctx, plain) call so tests can assert whether
// the handler invoked the probe.
type fakePwner struct {
	mu    sync.Mutex
	calls []string
	pwned bool
	err   error
}

func (p *fakePwner) Pwned(_ context.Context, plain string) (bool, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.calls = append(p.calls, plain)
	return p.pwned, p.err
}

// fakeEmailSender records the verification messages dispatched by the
// handler so tests can confirm both the recipient and the URL shape.
type fakeEmailSender struct {
	mu       sync.Mutex
	messages []VerificationEmail
	err      error
}

func (e *fakeEmailSender) SendVerificationEmail(_ context.Context, msg VerificationEmail) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.messages = append(e.messages, msg)
	return e.err
}

// ----------------------------------------------------------------------
// Test harness
// ----------------------------------------------------------------------

// signupFixture aggregates every dependency the handler under test
// touches so each table entry can mutate one field without rebuilding
// the whole graph.
type signupFixture struct {
	mr      *miniredis.Miniredis
	redis   *redisclient.Client
	repo    *fakeSignupRepo
	pwner   *fakePwner
	email   *fakeEmailSender
	handler *SignupHandler
	hasher  func(string) (string, error)
	logBuf  *bytes.Buffer
}

// newSignupFixture wires a SignupHandler against an in-memory Redis,
// in-memory repository, in-memory email sender, and the real Argon2id
// hasher from password.go (Hash). Tests can swap any field on the
// returned fixture before calling [signupFixture.do].
func newSignupFixture(t *testing.T) *signupFixture {
	t.Helper()
	mr := miniredis.RunT(t)
	rdb, err := redisclient.New(t.Context(), redisclient.Options{Addrs: []string{mr.Addr()}})
	if err != nil {
		t.Fatalf("redis.New: %v", err)
	}
	t.Cleanup(func() { _ = rdb.Close() })

	repo := newFakeSignupRepo()
	pwner := &fakePwner{}
	email := &fakeEmailSender{}

	logBuf := &bytes.Buffer{}
	logger := zerolog.New(logBuf).Level(zerolog.WarnLevel).With().Timestamp().Logger()

	handler := NewSignupHandler(rdb, Hash, pwner, email, repo, "https://app.xalgorix.com", logger)

	return &signupFixture{
		mr:      mr,
		redis:   rdb,
		repo:    repo,
		pwner:   pwner,
		email:   email,
		handler: handler,
		hasher:  Hash,
		logBuf:  logBuf,
	}
}

// do issues a JSON-encoded POST to the handler and returns the
// recorded response. A nil body becomes an empty body so tests can
// assert how the handler reacts to malformed input.
func (f *signupFixture) do(t *testing.T, body any) *httptest.ResponseRecorder {
	t.Helper()
	var raw []byte
	switch v := body.(type) {
	case nil:
	case []byte:
		raw = v
	case string:
		raw = []byte(v)
	default:
		var err error
		raw, err = json.Marshal(v)
		if err != nil {
			t.Fatalf("marshal body: %v", err)
		}
	}
	req := httptest.NewRequest(http.MethodPost, "/auth/signup", bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	f.handler.Handle(rec, req)
	return rec
}

// decodeJSON parses the response body into v and fails the test on
// any unmarshal error. We accept any v so tests can decode either
// SignupResponse or SignupErrorResponse without repeating boilerplate.
func decodeJSON(t *testing.T, rec *httptest.ResponseRecorder, v any) {
	t.Helper()
	if err := json.Unmarshal(rec.Body.Bytes(), v); err != nil {
		t.Fatalf("decode body %q: %v", rec.Body.String(), err)
	}
}

// ----------------------------------------------------------------------
// Constructor guards
// ----------------------------------------------------------------------

func TestNewSignupHandler_RejectsNilDeps(t *testing.T) {
	t.Parallel()

	mr := miniredis.RunT(t)
	rdb, err := redisclient.New(t.Context(), redisclient.Options{Addrs: []string{mr.Addr()}})
	if err != nil {
		t.Fatalf("redis.New: %v", err)
	}
	t.Cleanup(func() { _ = rdb.Close() })

	repo := newFakeSignupRepo()
	email := &fakeEmailSender{}
	logger := zerolog.Nop()

	cases := []struct {
		name string
		fn   func()
	}{
		{"nil redis", func() { NewSignupHandler(nil, Hash, nil, email, repo, "https://x", logger) }},
		{"nil hasher", func() { NewSignupHandler(rdb, nil, nil, email, repo, "https://x", logger) }},
		{"nil email", func() { NewSignupHandler(rdb, Hash, nil, nil, repo, "https://x", logger) }},
		{"nil repo", func() { NewSignupHandler(rdb, Hash, nil, email, nil, "https://x", logger) }},
		{"empty base url", func() { NewSignupHandler(rdb, Hash, nil, email, repo, "   ", logger) }},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Fatalf("expected NewSignupHandler to panic for %s", tc.name)
				}
			}()
			tc.fn()
		})
	}
}

// ----------------------------------------------------------------------
// Table-driven Handle() tests
// ----------------------------------------------------------------------

// TestSignupHandle covers the full matrix called out by task 2.4:
// happy path, weak password, pwned password, duplicate email, and
// missing fields.
func TestSignupHandle(t *testing.T) {
	t.Parallel()

	type expectations struct {
		status          int
		errCode         string
		errRule         string
		repoCall        bool
		emailDispatched bool
	}
	type setup func(*signupFixture)

	cases := []struct {
		name   string
		setup  setup
		body   any
		expect expectations
	}{
		{
			name: "happy_path",
			body: SignupRequest{
				Email:    "owner@example.com",
				Password: "Correct-Horse-Battery-9",
				OrgName:  "Example Co",
			},
			expect: expectations{
				status:          http.StatusCreated,
				repoCall:        true,
				emailDispatched: true,
			},
		},
		{
			name: "weak_password_too_short",
			body: SignupRequest{
				Email:    "short@example.com",
				Password: "abc12",
				OrgName:  "Tiny",
			},
			expect: expectations{
				status:  http.StatusUnprocessableEntity,
				errCode: "weak_password",
				errRule: "password_too_short",
			},
		},
		{
			name: "weak_password_missing_digit",
			body: SignupRequest{
				Email:    "nodigit@example.com",
				Password: "abcdefghijkl",
				OrgName:  "NoDigit",
			},
			expect: expectations{
				status:  http.StatusUnprocessableEntity,
				errCode: "weak_password",
				errRule: "password_missing_digit",
			},
		},
		{
			name: "weak_password_missing_letter",
			body: SignupRequest{
				Email:    "noletter@example.com",
				Password: "123456789012",
				OrgName:  "NoLetter",
			},
			expect: expectations{
				status:  http.StatusUnprocessableEntity,
				errCode: "weak_password",
				errRule: "password_missing_letter",
			},
		},
		{
			name: "pwned_password_rejected",
			setup: func(f *signupFixture) {
				f.pwner.pwned = true
			},
			body: SignupRequest{
				Email:    "pwned@example.com",
				Password: "Correct-Horse-Battery-9",
				OrgName:  "Pwned",
			},
			expect: expectations{
				status:  http.StatusUnprocessableEntity,
				errCode: "weak_password",
				errRule: "password_pwned",
			},
		},
		{
			name: "duplicate_email_conflict",
			setup: func(f *signupFixture) {
				// Pre-populate the repo with the same email so the
				// second insert maps to ErrDuplicateEmail.
				_, err := f.repo.CreateAccountWithOrg(context.Background(), CreateAccountWithOrgInput{
					Email:        "owner@example.com",
					PasswordHash: "preloaded",
					OrgName:      "Existing",
				})
				if err != nil {
					t.Fatalf("preload: %v", err)
				}
			},
			body: SignupRequest{
				Email:    "owner@example.com",
				Password: "Correct-Horse-Battery-9",
				OrgName:  "Example Co",
			},
			expect: expectations{
				status:  http.StatusConflict,
				errCode: "email_already_registered",
				// Repo IS called — the duplicate is discovered
				// by the persist step. See assertion below.
				repoCall: true,
			},
		},
		{
			name: "missing_email",
			body: SignupRequest{
				Password: "Correct-Horse-Battery-9",
				OrgName:  "MissingEmail",
			},
			expect: expectations{
				status:  http.StatusUnprocessableEntity,
				errCode: "missing_field",
				errRule: "email",
			},
		},
		{
			name: "missing_password",
			body: SignupRequest{
				Email:   "owner@example.com",
				OrgName: "MissingPassword",
			},
			expect: expectations{
				status:  http.StatusUnprocessableEntity,
				errCode: "missing_field",
				errRule: "password",
			},
		},
		{
			name: "missing_org_name",
			body: SignupRequest{
				Email:    "owner@example.com",
				Password: "Correct-Horse-Battery-9",
			},
			expect: expectations{
				status:  http.StatusUnprocessableEntity,
				errCode: "missing_field",
				errRule: "org_name",
			},
		},
		{
			name: "invalid_email_format",
			body: SignupRequest{
				Email:    "not-an-email",
				Password: "Correct-Horse-Battery-9",
				OrgName:  "Bad Email",
			},
			expect: expectations{
				status:  http.StatusUnprocessableEntity,
				errCode: "invalid_email",
				errRule: "email",
			},
		},
		{
			name: "malformed_json",
			body: "{not-json",
			expect: expectations{
				status:  http.StatusBadRequest,
				errCode: "invalid_json",
			},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := newSignupFixture(t)
			if tc.setup != nil {
				tc.setup(f)
			}
			// Track baseline call counts to recognise the
			// "repo called once during this request" expectation
			// even when the test pre-seeded the repo.
			baselineCalls := len(f.repo.calls)
			rec := f.do(t, tc.body)

			if rec.Code != tc.expect.status {
				t.Fatalf("status: got %d, want %d (body=%s)", rec.Code, tc.expect.status, rec.Body.String())
			}

			if tc.expect.status == http.StatusCreated {
				var resp SignupResponse
				decodeJSON(t, rec, &resp)
				if resp.AccountID == "" {
					t.Fatalf("account_id missing in response: %s", rec.Body.String())
				}
				if resp.OrgID == "" {
					t.Fatalf("org_id missing in response: %s", rec.Body.String())
				}
			} else {
				var errResp SignupErrorResponse
				decodeJSON(t, rec, &errResp)
				if errResp.Error != tc.expect.errCode {
					t.Fatalf("error code: got %q, want %q", errResp.Error, tc.expect.errCode)
				}
				if tc.expect.errRule != "" && errResp.Rule != tc.expect.errRule {
					t.Fatalf("error rule: got %q, want %q", errResp.Rule, tc.expect.errRule)
				}
			}

			// Repo should be invoked iff the test expected it.
			if tc.expect.repoCall {
				if len(f.repo.calls) <= baselineCalls {
					t.Fatalf("expected repo CreateAccountWithOrg call; saw none beyond baseline %d", baselineCalls)
				}
			} else if len(f.repo.calls) > baselineCalls {
				t.Fatalf("did not expect repo call but saw %d new", len(f.repo.calls)-baselineCalls)
			}

			// Email should only be dispatched on the happy path.
			if tc.expect.emailDispatched {
				if len(f.email.messages) != 1 {
					t.Fatalf("expected 1 verification email; got %d", len(f.email.messages))
				}
				msg := f.email.messages[0]
				if msg.Token == "" {
					t.Fatal("verification email missing token")
				}
				if !strings.Contains(msg.VerifyURL, "/auth/verify?token="+msg.Token) {
					t.Fatalf("verify url shape: got %q", msg.VerifyURL)
				}
				// Token must be persisted under the documented
				// key with the documented TTL.
				key := verifyKeyPrefix + msg.Token
				stored, err := f.redis.Underlying().Get(t.Context(), key).Result()
				if err != nil {
					t.Fatalf("redis Get(%s): %v", key, err)
				}
				if stored != msg.AccountID {
					t.Fatalf("redis token value: got %q, want %q", stored, msg.AccountID)
				}
				ttl, err := f.redis.Underlying().TTL(t.Context(), key).Result()
				if err != nil {
					t.Fatalf("redis TTL: %v", err)
				}
				if ttl <= 0 || ttl > VerifyTokenTTL {
					t.Fatalf("verify TTL out of bounds: got %v, want (0, %v]", ttl, VerifyTokenTTL)
				}
			} else if len(f.email.messages) != 0 {
				t.Fatalf("expected no email; got %d", len(f.email.messages))
			}
		})
	}
}

// TestSignupHandle_HIBPSkippedWhenPwnerNil ensures the handler is
// happy with a nil Pwner — the HIBP probe is optional per the task
// description.
func TestSignupHandle_HIBPSkippedWhenPwnerNil(t *testing.T) {
	t.Parallel()
	f := newSignupFixture(t)
	f.handler.Pwner = nil

	rec := f.do(t, SignupRequest{
		Email:    "no-pwner@example.com",
		Password: "Correct-Horse-Battery-9",
		OrgName:  "NoPwner Co",
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("status: got %d, want 201; body=%s", rec.Code, rec.Body.String())
	}
}

// TestSignupHandle_HIBPErrorIsFailOpen documents that a Pwner returning
// an error must not block the signup. The handler logs and proceeds.
func TestSignupHandle_HIBPErrorIsFailOpen(t *testing.T) {
	t.Parallel()
	f := newSignupFixture(t)
	f.pwner.err = errors.New("boom")

	rec := f.do(t, SignupRequest{
		Email:    "fail-open@example.com",
		Password: "Correct-Horse-Battery-9",
		OrgName:  "FailOpen",
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("status: got %d, want 201; body=%s", rec.Code, rec.Body.String())
	}
}

// TestSignupHandle_EmailFailureIsNonFatal proves that a transient
// email outage leaves the freshly-created account in place: the
// response is still 201 and the verification token is still in Redis,
// so a manual resend can recover.
func TestSignupHandle_EmailFailureIsNonFatal(t *testing.T) {
	t.Parallel()
	f := newSignupFixture(t)
	f.email.err = errors.New("resend down")

	rec := f.do(t, SignupRequest{
		Email:    "email-down@example.com",
		Password: "Correct-Horse-Battery-9",
		OrgName:  "EmailDown",
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("status: got %d, want 201; body=%s", rec.Code, rec.Body.String())
	}
	if len(f.email.messages) != 1 {
		t.Fatalf("expected 1 attempted email; got %d", len(f.email.messages))
	}
	keys := f.mr.Keys()
	var foundVerify bool
	for _, k := range keys {
		if strings.HasPrefix(k, verifyKeyPrefix) {
			foundVerify = true
			break
		}
	}
	if !foundVerify {
		t.Fatalf("verification token not stored despite 201 response: keys=%v", keys)
	}
}

// TestSignupHandle_MethodNotAllowed pins the HTTP method gate so the
// router is free to mount the handler without an extra wrapper.
func TestSignupHandle_MethodNotAllowed(t *testing.T) {
	t.Parallel()
	f := newSignupFixture(t)

	req := httptest.NewRequest(http.MethodGet, "/auth/signup", nil)
	rec := httptest.NewRecorder()
	f.handler.Handle(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status: got %d, want 405", rec.Code)
	}
}
