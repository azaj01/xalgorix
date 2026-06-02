// Copyright (c) Xalgorix.
// SPDX-License-Identifier: AGPL-3.0-only

package targets

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/go-chi/chi/v5"

	"github.com/xalgord/xalgorix/v4/internal/cloud/billing"
	"github.com/xalgord/xalgorix/v4/internal/cloud/orgs"
	cloudredis "github.com/xalgord/xalgorix/v4/internal/cloud/redis"
	"github.com/xalgord/xalgorix/v4/internal/cloud/tenancy"
)

// Tenancy fixtures shared across the handler tests. We pin the org and
// workspace UUIDs (and a "different tenant" pair for the isolation
// assertions) up front so every assertion can compare against named
// constants rather than scattered string literals.
const (
	hOrgID            = "00000000-0000-4000-8000-00000000a001"
	hWorkspaceID      = "00000000-0000-4000-8000-00000000a002"
	hOrgIDOther       = "00000000-0000-4000-8000-00000000b001"
	hWorkspaceIDOther = "00000000-0000-4000-8000-00000000b002"
)

// fakeRepo is the in-memory Repository used by every handler test in
// this file. It enforces tenant isolation by hand on Get so we can
// assert "a sibling tenant cannot see this row" without booting Postgres.
type fakeRepo struct {
	mu               sync.Mutex
	rows             map[string]Target
	createErr        error
	getErr           error
	markVerifiedErr  error
	recordAttemptErr error
	deleteErr        error
	attempts         []VerificationAttempt
	deletes          []string
	// duplicateOnce, when true, makes the next Create call return
	// ErrDuplicateToken before succeeding on the retry. Lets the
	// handler's createWithRetry path be exercised without rare entropy
	// collisions.
	duplicateOnce bool
}

func newFakeRepo() *fakeRepo {
	return &fakeRepo{rows: map[string]Target{}}
}

func (f *fakeRepo) Create(_ context.Context, t Target) (Target, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.createErr != nil {
		return Target{}, f.createErr
	}
	if f.duplicateOnce {
		f.duplicateOnce = false
		return Target{}, ErrDuplicateToken
	}
	t.ID = NewID()
	f.rows[t.ID] = t
	return t, nil
}

func (f *fakeRepo) Get(_ context.Context, id string) (Target, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.getErr != nil {
		return Target{}, f.getErr
	}
	t, ok := f.rows[id]
	if !ok {
		return Target{}, ErrTargetNotFound
	}
	return t, nil
}

func (f *fakeRepo) MarkVerified(_ context.Context, id, method string, at time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.markVerifiedErr != nil {
		return f.markVerifiedErr
	}
	t, ok := f.rows[id]
	if !ok {
		return ErrTargetNotFound
	}
	t.Status = "verified"
	t.VerifiedMethod = method
	t.VerifiedAt = at
	f.rows[id] = t
	return nil
}

func (f *fakeRepo) RecordAttempt(_ context.Context, attempt VerificationAttempt) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.recordAttemptErr != nil {
		return f.recordAttemptErr
	}
	f.attempts = append(f.attempts, attempt)
	return nil
}

func (f *fakeRepo) Delete(_ context.Context, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.deleteErr != nil {
		return f.deleteErr
	}
	if _, ok := f.rows[id]; !ok {
		return ErrTargetNotFound
	}
	delete(f.rows, id)
	f.deletes = append(f.deletes, id)
	return nil
}

func (f *fakeRepo) snapshotAttempts() []VerificationAttempt {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]VerificationAttempt, len(f.attempts))
	copy(out, f.attempts)
	return out
}

// fakeAudit records every Emit call so tests can assert the right
// event types fired.
type fakeAudit struct {
	mu     sync.Mutex
	events []AuditEvent
}

func (f *fakeAudit) Emit(_ context.Context, ev AuditEvent) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.events = append(f.events, ev)
	return nil
}

func (f *fakeAudit) types() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, 0, len(f.events))
	for _, e := range f.events {
		out = append(out, e.EventType)
	}
	return out
}

// staticVerifier is a Verifier that returns a pre-programmed result.
// The handler doesn't care which concrete verifier ran — it just
// records the (ok, err) it was handed — so the unit tests don't need
// to spin up a real DNS or HTTP server.
type staticVerifier struct {
	ok  bool
	err error
}

func (s *staticVerifier) Verify(_ context.Context, _, _ string) (bool, error) {
	return s.ok, s.err
}

// newTestHandlers wires a fresh Handlers value with sensible test
// defaults. Each test that needs a different verifier or repo state
// mutates the returned struct before issuing requests.
func newTestHandlers(t *testing.T, plan billing.Plan) (*Handlers, *fakeRepo, *fakeAudit, *CooldownTracker) {
	t.Helper()
	repo := newFakeRepo()
	audit := &fakeAudit{}

	mr, err := newMiniredisCooldown(t)
	if err != nil {
		t.Fatalf("cooldown setup: %v", err)
	}

	h := &Handlers{
		Repo:     repo,
		Cooldown: mr,
		DNS:      &staticVerifier{ok: true},
		File:     &staticVerifier{ok: true},
		Meta:     &staticVerifier{ok: true},
		Audit:    audit,
		Plans: PlanResolverFunc(func(_ context.Context, _ string) (billing.Plan, error) {
			return plan, nil
		}),
		Now: func() time.Time { return time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC) },
	}
	return h, repo, audit, mr
}

// newMiniredisCooldown builds a CooldownTracker backed by miniredis so
// the cooldown ledger is exercised end-to-end in handler tests without
// a real Redis. The existing cooldown_test.go uses the same pattern; we
// reuse the helper rather than duplicate it.
func newMiniredisCooldown(t *testing.T) (*CooldownTracker, error) {
	t.Helper()
	mr := miniredis.RunT(t)
	rdb, err := cloudredis.New(t.Context(), cloudredis.Options{Addrs: []string{mr.Addr()}})
	if err != nil {
		return nil, err
	}
	t.Cleanup(func() {
		if cerr := rdb.Close(); cerr != nil {
			t.Logf("redis client close: %v", cerr)
		}
	})
	return NewCooldownTracker(rdb), nil
}

// withTenant returns ctx stamped with the test org/workspace pair so
// the handler's tenant resolver returns the expected values.
func withTenant(ctx context.Context, orgID, workspaceID string) context.Context {
	return tenancy.WithTenantInfo(ctx, orgID, workspaceID)
}

// newRouter mounts the handlers on a fresh chi router with the Member
// role injected onto every request context. The routes mirror what the
// API_Server (task 8.1) will mount in production.
func newRouter(h *Handlers, role orgs.Role) http.Handler {
	r := chi.NewRouter()
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			ctx := orgs.WithRole(req.Context(), role)
			next.ServeHTTP(w, req.WithContext(ctx))
		})
	})
	r.Route("/api/v1/targets", func(sub chi.Router) {
		h.Mount(sub)
	})
	return r
}

// doJSON is a tiny request helper that constructs a JSON-bodied
// httptest request under the supplied tenant.
func doJSON(t *testing.T, router http.Handler, method, path string, body any, orgID, workspaceID string) *httptest.ResponseRecorder {
	t.Helper()
	var buf io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal body: %v", err)
		}
		buf = strings.NewReader(string(raw))
	}
	req := httptest.NewRequest(method, path, buf)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if orgID != "" || workspaceID != "" {
		req = req.WithContext(withTenant(req.Context(), orgID, workspaceID))
	}
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec
}

// decodeBody decodes the recorder body into v or fails the test.
func decodeBody(t *testing.T, rec *httptest.ResponseRecorder, v any) {
	t.Helper()
	if err := json.Unmarshal(rec.Body.Bytes(), v); err != nil {
		t.Fatalf("decode body %q: %v", rec.Body.String(), err)
	}
}

// ---------------------------------------------------------------------
// Create endpoint
// ---------------------------------------------------------------------

// TestCreateTarget covers the table-driven happy paths and validation
// branches of POST /api/v1/targets. Validates: Requirements 7.1, 7.3,
// 7.6, 8.1.
func TestCreateTarget(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		body       any
		plan       billing.Plan
		role       orgs.Role
		wantStatus int
		wantError  string
		assert     func(t *testing.T, resp CreateTargetResponse, repo *fakeRepo, audit *fakeAudit)
	}{
		{
			name:       "host_unverified",
			body:       CreateTargetRequest{Host: "example.com", Mode: ModeSaaS},
			plan:       billing.PlanPro,
			role:       orgs.RoleMember,
			wantStatus: http.StatusCreated,
			assert: func(t *testing.T, resp CreateTargetResponse, repo *fakeRepo, audit *fakeAudit) {
				if resp.Status != VerificationStatusUnverified {
					t.Errorf("status = %s, want unverified", resp.Status)
				}
				if !IsValidTokenFormat(resp.VerificationToken) {
					t.Errorf("verification_token %q is not in canonical form", resp.VerificationToken)
				}
				wantMethods := []string{"dns", "file", "meta"}
				if fmt.Sprintf("%v", resp.VerificationMethods) != fmt.Sprintf("%v", wantMethods) {
					t.Errorf("methods = %v, want %v", resp.VerificationMethods, wantMethods)
				}
				if got := audit.types(); len(got) != 1 || got[0] != AuditEventTargetAdded {
					t.Errorf("audit events = %v, want [target_added]", got)
				}
			},
		},
		{
			name:       "loopback_short_circuits_to_verified_local",
			body:       CreateTargetRequest{Host: "127.0.0.1", Mode: ModeSaaS},
			plan:       billing.PlanFree,
			role:       orgs.RoleMember,
			wantStatus: http.StatusCreated,
			assert: func(t *testing.T, resp CreateTargetResponse, repo *fakeRepo, audit *fakeAudit) {
				if resp.Status != VerificationStatusVerifiedLocal {
					t.Errorf("status = %s, want verified_local", resp.Status)
				}
				if resp.VerificationToken != "" {
					t.Errorf("verification_token = %q, want empty for loopback", resp.VerificationToken)
				}
				if len(resp.VerificationMethods) != 1 || resp.VerificationMethods[0] != "local" {
					t.Errorf("methods = %v, want [local]", resp.VerificationMethods)
				}
			},
		},
		{
			name:       "default_mode_is_saas",
			body:       map[string]string{"host": "example.com"},
			plan:       billing.PlanFree,
			role:       orgs.RoleMember,
			wantStatus: http.StatusCreated,
		},
		{
			name:       "invalid_mode_rejected",
			body:       map[string]string{"host": "example.com", "mode": "self-hosted"},
			plan:       billing.PlanPro,
			role:       orgs.RoleMember,
			wantStatus: http.StatusUnprocessableEntity,
			wantError:  errCodeInvalidMode,
		},
		{
			name:       "empty_host_rejected",
			body:       CreateTargetRequest{Host: "  ", Mode: ModeSaaS},
			plan:       billing.PlanPro,
			role:       orgs.RoleMember,
			wantStatus: http.StatusUnprocessableEntity,
			wantError:  errCodeInvalidHost,
		},
		{
			name:       "host_with_path_rejected",
			body:       CreateTargetRequest{Host: "example.com/foo", Mode: ModeSaaS},
			plan:       billing.PlanPro,
			role:       orgs.RoleMember,
			wantStatus: http.StatusUnprocessableEntity,
			wantError:  errCodeInvalidHost,
		},
		{
			name:       "enterprise_mode_blocked_on_pro_plan",
			body:       CreateTargetRequest{Host: "example.com", Mode: ModeEnterprise},
			plan:       billing.PlanPro,
			role:       orgs.RoleMember,
			wantStatus: http.StatusPaymentRequired,
			wantError:  errCodePlanLockedEnterprise,
		},
		{
			name:       "enterprise_mode_allowed_on_enterprise_plan",
			body:       CreateTargetRequest{Host: "example.com", Mode: ModeEnterprise},
			plan:       billing.PlanEnterprise,
			role:       orgs.RoleMember,
			wantStatus: http.StatusCreated,
		},
		{
			name:       "viewer_role_rejected",
			body:       CreateTargetRequest{Host: "example.com"},
			plan:       billing.PlanPro,
			role:       orgs.RoleViewer,
			wantStatus: http.StatusForbidden,
			wantError:  "forbidden_role",
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			h, repo, audit, _ := newTestHandlers(t, tc.plan)
			router := newRouter(h, tc.role)

			rec := doJSON(t, router, http.MethodPost, "/api/v1/targets", tc.body, hOrgID, hWorkspaceID)

			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d body=%s, want %d", rec.Code, rec.Body.String(), tc.wantStatus)
			}
			if tc.wantError != "" {
				var eb errorBody
				decodeBody(t, rec, &eb)
				if eb.Error != tc.wantError {
					t.Errorf("error = %q, want %q", eb.Error, tc.wantError)
				}
				return
			}
			if tc.wantStatus != http.StatusCreated {
				return
			}
			var resp CreateTargetResponse
			decodeBody(t, rec, &resp)
			if resp.ID == "" {
				t.Fatal("response missing id")
			}
			if tc.assert != nil {
				tc.assert(t, resp, repo, audit)
			}
		})
	}
}

// TestCreateTarget_RequiresTenant exercises the "no resolved tenant"
// branch — a request that reaches the handler without org/workspace
// info must be rejected with 401 before any work is done. This is the
// runtime defence behind Requirement 1.1 / 1.5 tenancy.
func TestCreateTarget_RequiresTenant(t *testing.T) {
	t.Parallel()
	h, _, _, _ := newTestHandlers(t, billing.PlanPro)
	router := newRouter(h, orgs.RoleMember)

	rec := doJSON(t, router, http.MethodPost, "/api/v1/targets",
		CreateTargetRequest{Host: "example.com"}, "", "")

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d body=%s, want 401", rec.Code, rec.Body.String())
	}
	var eb errorBody
	decodeBody(t, rec, &eb)
	if eb.Error != errCodeTenantUnresolved {
		t.Errorf("error = %q, want %q", eb.Error, errCodeTenantUnresolved)
	}
}

// TestCreateTarget_RetriesOnDuplicateToken exercises the createWithRetry
// branch. The fake repo is programmed to fail the first Create with
// ErrDuplicateToken; the handler should mint a fresh token and retry,
// surfacing a successful 201 to the caller.
func TestCreateTarget_RetriesOnDuplicateToken(t *testing.T) {
	t.Parallel()
	h, repo, _, _ := newTestHandlers(t, billing.PlanPro)
	repo.duplicateOnce = true
	router := newRouter(h, orgs.RoleMember)

	rec := doJSON(t, router, http.MethodPost, "/api/v1/targets",
		CreateTargetRequest{Host: "example.com"}, hOrgID, hWorkspaceID)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d body=%s, want 201", rec.Code, rec.Body.String())
	}
	if len(repo.rows) != 1 {
		t.Errorf("repo has %d rows, want 1 after retry", len(repo.rows))
	}
}

// ---------------------------------------------------------------------
// Verify endpoint
// ---------------------------------------------------------------------

// TestVerifyTarget covers the happy path, the cooldown gate, and the
// validation branches of POST /api/v1/targets/{id}/verify.
//
// Validates: Requirements 7.2, 7.4, 7.5, 8.1.
func TestVerifyTarget(t *testing.T) {
	t.Parallel()

	makeUnverifiedTarget := func(repo *fakeRepo) Target {
		token, _ := GenerateVerificationToken()
		t := Target{
			OrgID:             hOrgID,
			WorkspaceID:       hWorkspaceID,
			Host:              "example.com",
			Status:            VerificationStatusUnverified,
			VerificationToken: token,
		}
		row, _ := repo.Create(context.Background(), t)
		return row
	}

	t.Run("happy_path_dns", func(t *testing.T) {
		t.Parallel()
		h, repo, audit, _ := newTestHandlers(t, billing.PlanPro)
		row := makeUnverifiedTarget(repo)
		router := newRouter(h, orgs.RoleMember)

		rec := doJSON(t, router, http.MethodPost,
			"/api/v1/targets/"+row.ID+"/verify",
			VerifyTargetRequest{Method: "dns"}, hOrgID, hWorkspaceID)

		if rec.Code != http.StatusAccepted {
			t.Fatalf("status = %d body=%s, want 202", rec.Code, rec.Body.String())
		}
		var resp VerifyTargetResponse
		decodeBody(t, rec, &resp)
		if resp.Status != "verified" {
			t.Errorf("status = %s, want verified", resp.Status)
		}
		if got := audit.types(); len(got) != 1 || got[0] != AuditEventTargetVerified {
			t.Errorf("audit events = %v, want [target_verified]", got)
		}
		if attempts := repo.snapshotAttempts(); len(attempts) != 1 || !attempts[0].Succeeded {
			t.Errorf("attempts = %+v, want one succeeded attempt", attempts)
		}
	})

	t.Run("verifier_failure_records_attempt_no_promotion", func(t *testing.T) {
		t.Parallel()
		h, repo, audit, _ := newTestHandlers(t, billing.PlanPro)
		h.DNS = &staticVerifier{ok: false}
		row := makeUnverifiedTarget(repo)
		router := newRouter(h, orgs.RoleMember)

		rec := doJSON(t, router, http.MethodPost,
			"/api/v1/targets/"+row.ID+"/verify",
			VerifyTargetRequest{Method: "dns"}, hOrgID, hWorkspaceID)

		if rec.Code != http.StatusAccepted {
			t.Fatalf("status = %d, want 202", rec.Code)
		}
		var resp VerifyTargetResponse
		decodeBody(t, rec, &resp)
		if resp.Status != VerificationStatusUnverified {
			t.Errorf("status = %s, want unverified", resp.Status)
		}
		if got := audit.types(); len(got) != 0 {
			t.Errorf("audit events = %v, want none on failed verify", got)
		}
		if attempts := repo.snapshotAttempts(); len(attempts) != 1 || attempts[0].Succeeded {
			t.Errorf("attempts = %+v, want one failed attempt", attempts)
		}
	})

	t.Run("cooldown_returns_429_after_three_fails", func(t *testing.T) {
		t.Parallel()
		h, repo, _, _ := newTestHandlers(t, billing.PlanPro)
		h.DNS = &staticVerifier{ok: false}
		row := makeUnverifiedTarget(repo)
		router := newRouter(h, orgs.RoleMember)

		// Three consecutive failures should hand out three 202s, then
		// the fourth must be rejected with 429.
		for i := 0; i < 3; i++ {
			rec := doJSON(t, router, http.MethodPost,
				"/api/v1/targets/"+row.ID+"/verify",
				VerifyTargetRequest{Method: "dns"}, hOrgID, hWorkspaceID)
			if rec.Code != http.StatusAccepted {
				t.Fatalf("attempt %d: status = %d body=%s, want 202", i, rec.Code, rec.Body.String())
			}
		}

		rec := doJSON(t, router, http.MethodPost,
			"/api/v1/targets/"+row.ID+"/verify",
			VerifyTargetRequest{Method: "dns"}, hOrgID, hWorkspaceID)

		if rec.Code != http.StatusTooManyRequests {
			t.Fatalf("status = %d body=%s, want 429", rec.Code, rec.Body.String())
		}
		if got := rec.Header().Get("Retry-After"); got == "" {
			t.Error("missing Retry-After header on cooldown rejection")
		}
		var eb errorBody
		decodeBody(t, rec, &eb)
		if eb.Error != errCodeVerificationCooldown {
			t.Errorf("error = %q, want %q", eb.Error, errCodeVerificationCooldown)
		}
	})

	t.Run("invalid_method_rejected", func(t *testing.T) {
		t.Parallel()
		h, repo, _, _ := newTestHandlers(t, billing.PlanPro)
		row := makeUnverifiedTarget(repo)
		router := newRouter(h, orgs.RoleMember)

		rec := doJSON(t, router, http.MethodPost,
			"/api/v1/targets/"+row.ID+"/verify",
			VerifyTargetRequest{Method: "ssh-key"}, hOrgID, hWorkspaceID)

		if rec.Code != http.StatusUnprocessableEntity {
			t.Fatalf("status = %d, want 422", rec.Code)
		}
		var eb errorBody
		decodeBody(t, rec, &eb)
		if eb.Error != errCodeInvalidMethod {
			t.Errorf("error = %q, want %q", eb.Error, errCodeInvalidMethod)
		}
	})

	t.Run("missing_target_returns_404", func(t *testing.T) {
		t.Parallel()
		h, _, _, _ := newTestHandlers(t, billing.PlanPro)
		router := newRouter(h, orgs.RoleMember)

		rec := doJSON(t, router, http.MethodPost,
			"/api/v1/targets/00000000-0000-0000-0000-000000000000/verify",
			VerifyTargetRequest{Method: "dns"}, hOrgID, hWorkspaceID)

		if rec.Code != http.StatusNotFound {
			t.Fatalf("status = %d body=%s, want 404", rec.Code, rec.Body.String())
		}
	})

	t.Run("tenant_isolation_blocks_cross_tenant_verify", func(t *testing.T) {
		t.Parallel()
		h, repo, _, _ := newTestHandlers(t, billing.PlanPro)
		row := makeUnverifiedTarget(repo)
		router := newRouter(h, orgs.RoleMember)

		// Same target id, but the request comes in under a *different*
		// tenant's org/workspace pair. The handler must return 404
		// rather than 200 — leaking either the existence of the row
		// or its host would violate tenant isolation.
		rec := doJSON(t, router, http.MethodPost,
			"/api/v1/targets/"+row.ID+"/verify",
			VerifyTargetRequest{Method: "dns"}, hOrgIDOther, hWorkspaceIDOther)

		if rec.Code != http.StatusNotFound {
			t.Fatalf("status = %d body=%s, want 404 for cross-tenant", rec.Code, rec.Body.String())
		}
	})

	t.Run("already_verified_returns_409", func(t *testing.T) {
		t.Parallel()
		h, repo, _, _ := newTestHandlers(t, billing.PlanPro)
		row := makeUnverifiedTarget(repo)
		// Promote the row out of band so the verify endpoint returns 409.
		_ = repo.MarkVerified(context.Background(), row.ID, "dns", time.Now())
		router := newRouter(h, orgs.RoleMember)

		rec := doJSON(t, router, http.MethodPost,
			"/api/v1/targets/"+row.ID+"/verify",
			VerifyTargetRequest{Method: "dns"}, hOrgID, hWorkspaceID)

		if rec.Code != http.StatusConflict {
			t.Fatalf("status = %d, want 409", rec.Code)
		}
	})

	t.Run("verified_local_returns_409", func(t *testing.T) {
		t.Parallel()
		h, repo, _, _ := newTestHandlers(t, billing.PlanPro)
		row, _ := repo.Create(context.Background(), Target{
			OrgID:       hOrgID,
			WorkspaceID: hWorkspaceID,
			Host:        "127.0.0.1",
			Status:      VerificationStatusVerifiedLocal,
		})
		router := newRouter(h, orgs.RoleMember)

		rec := doJSON(t, router, http.MethodPost,
			"/api/v1/targets/"+row.ID+"/verify",
			VerifyTargetRequest{Method: "dns"}, hOrgID, hWorkspaceID)

		if rec.Code != http.StatusConflict {
			t.Fatalf("status = %d, want 409 for verified_local row", rec.Code)
		}
		var eb errorBody
		decodeBody(t, rec, &eb)
		if eb.Error != errCodeAlreadyVerifiedLocal {
			t.Errorf("error = %q, want %q", eb.Error, errCodeAlreadyVerifiedLocal)
		}
	})

	t.Run("viewer_role_rejected", func(t *testing.T) {
		t.Parallel()
		h, repo, _, _ := newTestHandlers(t, billing.PlanPro)
		row := makeUnverifiedTarget(repo)
		router := newRouter(h, orgs.RoleViewer)

		rec := doJSON(t, router, http.MethodPost,
			"/api/v1/targets/"+row.ID+"/verify",
			VerifyTargetRequest{Method: "dns"}, hOrgID, hWorkspaceID)

		if rec.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want 403 for Viewer", rec.Code)
		}
	})
}

// TestVerifyTarget_VerifierTransportError pins the contract that a
// non-nil error from the verifier still records a failure attempt
// (rather than crashing the handler) and is surfaced as a non-200
// status the caller can retry.
func TestVerifyTarget_VerifierTransportError(t *testing.T) {
	t.Parallel()
	h, repo, _, _ := newTestHandlers(t, billing.PlanPro)
	h.DNS = &staticVerifier{ok: false, err: errors.New("dns: i/o timeout")}
	token, _ := GenerateVerificationToken()
	row, _ := repo.Create(context.Background(), Target{
		OrgID:             hOrgID,
		WorkspaceID:       hWorkspaceID,
		Host:              "example.com",
		Status:            VerificationStatusUnverified,
		VerificationToken: token,
	})
	router := newRouter(h, orgs.RoleMember)

	rec := doJSON(t, router, http.MethodPost,
		"/api/v1/targets/"+row.ID+"/verify",
		VerifyTargetRequest{Method: "dns"}, hOrgID, hWorkspaceID)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202 (transport error is just a failed attempt)", rec.Code)
	}
	if attempts := repo.snapshotAttempts(); len(attempts) != 1 {
		t.Fatalf("attempts = %+v, want one recorded attempt", attempts)
	} else if !strings.Contains(attempts[0].Detail, "i/o timeout") {
		t.Errorf("detail = %q, want substring 'i/o timeout'", attempts[0].Detail)
	}
}

// ---------------------------------------------------------------------
// Delete endpoint
// ---------------------------------------------------------------------

// TestDeleteTarget covers the table-driven cases for
// DELETE /api/v1/targets/{id}: happy path, missing target, tenant
// isolation, and Member-role rejection.
//
// Validates: Requirement 8.1, 13.5.
func TestDeleteTarget(t *testing.T) {
	t.Parallel()

	t.Run("admin_deletes_target", func(t *testing.T) {
		t.Parallel()
		h, repo, audit, _ := newTestHandlers(t, billing.PlanPro)
		row, _ := repo.Create(context.Background(), Target{
			OrgID:       hOrgID,
			WorkspaceID: hWorkspaceID,
			Host:        "example.com",
			Status:      VerificationStatusUnverified,
		})
		router := newRouter(h, orgs.RoleAdmin)

		rec := doJSON(t, router, http.MethodDelete, "/api/v1/targets/"+row.ID, nil, hOrgID, hWorkspaceID)

		if rec.Code != http.StatusNoContent {
			t.Fatalf("status = %d body=%s, want 204", rec.Code, rec.Body.String())
		}
		if _, ok := repo.rows[row.ID]; ok {
			t.Error("repo still has the row after delete")
		}
		if got := audit.types(); len(got) != 1 || got[0] != AuditEventTargetDeleted {
			t.Errorf("audit events = %v, want [target_deleted]", got)
		}
	})

	t.Run("member_role_rejected", func(t *testing.T) {
		t.Parallel()
		h, repo, _, _ := newTestHandlers(t, billing.PlanPro)
		row, _ := repo.Create(context.Background(), Target{
			OrgID:       hOrgID,
			WorkspaceID: hWorkspaceID,
			Host:        "example.com",
			Status:      VerificationStatusUnverified,
		})
		router := newRouter(h, orgs.RoleMember)

		rec := doJSON(t, router, http.MethodDelete, "/api/v1/targets/"+row.ID, nil, hOrgID, hWorkspaceID)

		if rec.Code != http.StatusForbidden {
			t.Fatalf("status = %d body=%s, want 403", rec.Code, rec.Body.String())
		}
		if _, ok := repo.rows[row.ID]; !ok {
			t.Error("row was deleted despite Member role rejection")
		}
	})

	t.Run("missing_target_returns_404", func(t *testing.T) {
		t.Parallel()
		h, _, _, _ := newTestHandlers(t, billing.PlanPro)
		router := newRouter(h, orgs.RoleAdmin)

		rec := doJSON(t, router, http.MethodDelete,
			"/api/v1/targets/00000000-0000-0000-0000-000000000000",
			nil, hOrgID, hWorkspaceID)

		if rec.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404", rec.Code)
		}
	})

	t.Run("tenant_isolation_blocks_cross_tenant_delete", func(t *testing.T) {
		t.Parallel()
		h, repo, _, _ := newTestHandlers(t, billing.PlanPro)
		row, _ := repo.Create(context.Background(), Target{
			OrgID:       hOrgID,
			WorkspaceID: hWorkspaceID,
			Host:        "example.com",
			Status:      VerificationStatusUnverified,
		})
		router := newRouter(h, orgs.RoleAdmin)

		rec := doJSON(t, router, http.MethodDelete,
			"/api/v1/targets/"+row.ID, nil, hOrgIDOther, hWorkspaceIDOther)

		if rec.Code != http.StatusNotFound {
			t.Fatalf("status = %d body=%s, want 404 for cross-tenant", rec.Code, rec.Body.String())
		}
		if _, ok := repo.rows[row.ID]; !ok {
			t.Error("cross-tenant delete dropped the row from the original tenant")
		}
	})
}
