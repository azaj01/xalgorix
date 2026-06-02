package tenancy

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// fakeTx records every Exec call and tracks whether Commit or Rollback
// was invoked. It satisfies the Tx interface so middleware_test.go can
// run without a real PostgreSQL connection.
type fakeTx struct {
	mu          sync.Mutex
	execs       []execCall
	committed   bool
	rolledBack  bool
	execErrOnce error // returned by the next Exec call, then cleared
}

type execCall struct {
	sql  string
	args []any
}

func (f *fakeTx) Exec(_ context.Context, sql string, args ...any) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.execs = append(f.execs, execCall{sql: sql, args: append([]any(nil), args...)})
	if f.execErrOnce != nil {
		err := f.execErrOnce
		f.execErrOnce = nil
		return err
	}
	return nil
}

func (f *fakeTx) Commit(_ context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.rolledBack {
		return errors.New("commit after rollback")
	}
	f.committed = true
	return nil
}

func (f *fakeTx) Rollback(_ context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.rolledBack = true
	return nil
}

func (f *fakeTx) snapshot() (execs []execCall, committed, rolledBack bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]execCall, len(f.execs))
	copy(out, f.execs)
	return out, f.committed, f.rolledBack
}

// newFakeBegin returns a BeginTxFunc that always hands out the same
// fakeTx instance, so tests can inspect its state after the request.
func newFakeBegin(tx *fakeTx) BeginTxFunc {
	return func(ctx context.Context, _ TxOptions) (context.Context, Tx, error) {
		return ctx, tx, nil
	}
}

func TestWithTenantInfo_RoundTrip(t *testing.T) {
	t.Parallel()
	ctx := WithTenantInfo(context.Background(), "org-1", "ws-1")
	if got := OrgID(ctx); got != "org-1" {
		t.Fatalf("OrgID = %q, want %q", got, "org-1")
	}
	if got := WorkspaceID(ctx); got != "ws-1" {
		t.Fatalf("WorkspaceID = %q, want %q", got, "ws-1")
	}
}

func TestWithTenantInfo_EmptyValuesIgnored(t *testing.T) {
	t.Parallel()
	ctx := WithTenantInfo(context.Background(), "", "")
	if OrgID(ctx) != "" || WorkspaceID(ctx) != "" {
		t.Fatalf("expected no tenant info, got org=%q ws=%q", OrgID(ctx), WorkspaceID(ctx))
	}
}

func TestWithTenant_HappyPath_SetsLocalAndCommits(t *testing.T) {
	t.Parallel()
	tx := &fakeTx{}
	mw := WithTenant(newFakeBegin(tx))

	called := false
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		// The middleware should have stashed the tx on the
		// request context.
		if got := TxFromContext(r.Context()); got == nil {
			t.Errorf("TxFromContext returned nil; expected the active tx")
		}
		w.WriteHeader(http.StatusCreated)
	}))

	req := httptest.NewRequest(http.MethodPost, "/api/v1/scans", strings.NewReader(`{}`))
	req = req.WithContext(WithTenantInfo(req.Context(), "org-1", "ws-1"))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if !called {
		t.Fatal("inner handler was not invoked")
	}
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusCreated)
	}

	execs, committed, rolledBack := tx.snapshot()
	if len(execs) != 2 {
		t.Fatalf("expected 2 set_config exec calls, got %d (%v)", len(execs), execs)
	}
	if !strings.Contains(execs[0].sql, "set_config") || !strings.Contains(execs[0].sql, "app.organization_id") {
		t.Errorf("first exec was %q, expected set_config(app.organization_id, ...)", execs[0].sql)
	}
	if got := execs[0].args[0]; got != "org-1" {
		t.Errorf("organization_id arg = %v, want org-1", got)
	}
	if !strings.Contains(execs[1].sql, "set_config") || !strings.Contains(execs[1].sql, "app.workspace_id") {
		t.Errorf("second exec was %q, expected set_config(app.workspace_id, ...)", execs[1].sql)
	}
	if got := execs[1].args[0]; got != "ws-1" {
		t.Errorf("workspace_id arg = %v, want ws-1", got)
	}
	if !committed {
		t.Error("expected Commit to be called on success")
	}
	if rolledBack {
		t.Error("did not expect Rollback on success")
	}
}

func TestWithTenant_MutatingWithoutTenant_Rejected(t *testing.T) {
	t.Parallel()
	for _, method := range []string{
		http.MethodPost,
		http.MethodPut,
		http.MethodPatch,
		http.MethodDelete,
	} {
		method := method
		t.Run(method, func(t *testing.T) {
			t.Parallel()
			tx := &fakeTx{}
			beginCalled := false
			mw := WithTenant(func(ctx context.Context, _ TxOptions) (context.Context, Tx, error) {
				beginCalled = true
				return ctx, tx, nil
			})

			handlerCalled := false
			handler := mw(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				handlerCalled = true
			}))

			req := httptest.NewRequest(method, "/api/v1/scans", strings.NewReader(`{}`))
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401", rec.Code)
			}
			if handlerCalled {
				t.Error("inner handler should not run when tenant is missing")
			}
			if beginCalled {
				t.Error("BeginTxFunc should not be called when tenant is missing")
			}
			execs, committed, rolledBack := tx.snapshot()
			if len(execs) != 0 || committed || rolledBack {
				t.Errorf("tx should be untouched, got execs=%v committed=%v rolledBack=%v",
					execs, committed, rolledBack)
			}
		})
	}
}

func TestWithTenant_ReadOnlyWithoutTenant_PassesThrough(t *testing.T) {
	t.Parallel()
	// GET requests without a tenant should still flow through;
	// RLS will return zero rows because no GUC is set. We rely on
	// this for endpoints like `/healthz` that don't need scoping.
	tx := &fakeTx{}
	mw := WithTenant(newFakeBegin(tx))

	called := false
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/scans", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if !called {
		t.Fatal("inner handler was not invoked")
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	execs, committed, rolledBack := tx.snapshot()
	if len(execs) != 0 {
		t.Errorf("expected no set_config calls without tenant, got %v", execs)
	}
	// GET is non-mutating, so the design rolls back rather than
	// committing.
	if committed {
		t.Error("non-mutating request should roll back, not commit")
	}
	if !rolledBack {
		t.Error("expected Rollback for non-mutating request")
	}
}

func TestWithTenant_HandlerErrorRollsBack(t *testing.T) {
	t.Parallel()
	tx := &fakeTx{}
	mw := WithTenant(newFakeBegin(tx))

	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simulate an internal error after partial work.
		MarkErrored(r.Context())
		http.Error(w, "boom", http.StatusInternalServerError)
	}))

	req := httptest.NewRequest(http.MethodPost, "/api/v1/scans", strings.NewReader(`{}`))
	req = req.WithContext(WithTenantInfo(req.Context(), "org-2", "ws-2"))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
	_, committed, rolledBack := tx.snapshot()
	if committed {
		t.Error("Commit must not be called when the handler errored")
	}
	if !rolledBack {
		t.Error("expected Rollback when the handler errored")
	}
}

func TestWithTenant_HandlerPanicRollsBackAndRepanics(t *testing.T) {
	t.Parallel()
	tx := &fakeTx{}
	mw := WithTenant(newFakeBegin(tx))

	handler := mw(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic("kaboom")
	}))

	req := httptest.NewRequest(http.MethodPost, "/api/v1/scans", strings.NewReader(`{}`))
	req = req.WithContext(WithTenantInfo(req.Context(), "org-3", "ws-3"))
	rec := httptest.NewRecorder()

	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic to propagate to outer recovery middleware")
		}
		_, committed, rolledBack := tx.snapshot()
		if committed {
			t.Error("Commit must not be called when the handler panics")
		}
		if !rolledBack {
			t.Error("expected Rollback when the handler panics")
		}
	}()

	handler.ServeHTTP(rec, req)
}

func TestWithTenant_BeginTxFailureReturns500(t *testing.T) {
	t.Parallel()
	mw := WithTenant(func(ctx context.Context, _ TxOptions) (context.Context, Tx, error) {
		return ctx, nil, errors.New("pool exhausted")
	})

	handlerCalled := false
	handler := mw(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		handlerCalled = true
	}))

	req := httptest.NewRequest(http.MethodPost, "/api/v1/scans", strings.NewReader(`{}`))
	req = req.WithContext(WithTenantInfo(req.Context(), "org-4", "ws-4"))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
	if handlerCalled {
		t.Error("handler should not run when BeginTx fails")
	}
}

func TestWithTenant_SetConfigFailureRollsBack(t *testing.T) {
	t.Parallel()
	tx := &fakeTx{execErrOnce: errors.New("set_config failed")}
	mw := WithTenant(newFakeBegin(tx))

	handlerCalled := false
	handler := mw(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		handlerCalled = true
	}))

	req := httptest.NewRequest(http.MethodPost, "/api/v1/scans", strings.NewReader(`{}`))
	req = req.WithContext(WithTenantInfo(req.Context(), "org-5", "ws-5"))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
	if handlerCalled {
		t.Error("handler should not run when set_config fails")
	}
	_, committed, rolledBack := tx.snapshot()
	if committed {
		t.Error("Commit must not be called when set_config fails")
	}
	if !rolledBack {
		t.Error("expected Rollback when set_config fails")
	}
}

func TestWithTenant_NilBeginTxFuncPanics(t *testing.T) {
	t.Parallel()
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic when BeginTxFunc is nil")
		}
	}()
	WithTenant(nil)
}
