package orgs

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestAllow_Matrix exhaustively asserts the (role, action, resource)
// decision for every cell described by Requirement 4.2. The expectation
// table is hand-written from the requirement text so a regression in the
// generated `allowMatrix` is caught directly. Any cell not listed below
// defaults to false; the helper builds the full Cartesian space.
//
// Validates: Requirement 4.2.
func TestAllow_Matrix(t *testing.T) {
	t.Parallel()

	// expected[role][resource] is the set of actions that role is
	// allowed to perform on that resource. Anything missing is denied.
	expected := map[Role]map[Resource][]Action{
		// Owner: every action on every resource, plus transfer ownership.
		RoleOwner: ownerExpectations(),

		// Admin: every action on every resource except (a) deleting the
		// Organization and (b) transferring ownership. Changing the
		// Owner's role is enforced at the row level by MemberService and
		// is not expressible in this matrix, so Admin's update on
		// Member is allowed at the cell granularity.
		RoleAdmin: adminExpectations(),

		// Member: read on every resource, plus full manage on the six
		// resources called out in Requirement 4.2, plus update on
		// Finding (Requirement 6.10 finding status changes).
		RoleMember: memberExpectations(),

		// Viewer: read on every resource, nothing else.
		RoleViewer: viewerExpectations(),
	}

	allActions := []Action{
		ActionCreate,
		ActionRead,
		ActionUpdate,
		ActionDelete,
		ActionTransferOwnership,
	}
	roles := []Role{RoleOwner, RoleAdmin, RoleMember, RoleViewer}

	for _, role := range roles {
		for _, res := range allResources {
			for _, act := range allActions {
				want := actionInList(act, expected[role][res])
				got := Allow(role, act, res)
				if got != want {
					t.Errorf("Allow(%s, %s, %s) = %v, want %v",
						role, act, res, got, want)
				}
			}
		}
	}
}

// ownerExpectations returns the full Owner permission table.
func ownerExpectations() map[Resource][]Action {
	out := map[Resource][]Action{}
	for _, r := range allResources {
		out[r] = []Action{ActionCreate, ActionRead, ActionUpdate, ActionDelete}
	}
	out[ResourceOrganization] = append(out[ResourceOrganization], ActionTransferOwnership)
	return out
}

// adminExpectations returns the full Admin permission table.
func adminExpectations() map[Resource][]Action {
	out := map[Resource][]Action{}
	for _, r := range allResources {
		out[r] = []Action{ActionCreate, ActionRead, ActionUpdate, ActionDelete}
	}
	// Two cell-level removals from "any action":
	out[ResourceOrganization] = []Action{ActionCreate, ActionRead, ActionUpdate}
	// Admin must not transfer ownership (already excluded by default).
	return out
}

// memberExpectations returns the full Member permission table.
func memberExpectations() map[Resource][]Action {
	out := map[Resource][]Action{}
	for _, r := range allResources {
		out[r] = []Action{ActionRead}
	}
	managed := []Resource{
		ResourceScan,
		ResourceTarget,
		ResourceReport,
		ResourceAPIKey,
		ResourceWebhook,
		ResourceIntegration,
	}
	for _, r := range managed {
		out[r] = []Action{ActionCreate, ActionRead, ActionUpdate, ActionDelete}
	}
	// Finding status changes — Members may update.
	out[ResourceFinding] = []Action{ActionRead, ActionUpdate}
	return out
}

// viewerExpectations returns the full Viewer permission table.
func viewerExpectations() map[Resource][]Action {
	out := map[Resource][]Action{}
	for _, r := range allResources {
		out[r] = []Action{ActionRead}
	}
	return out
}

func actionInList(needle Action, haystack []Action) bool {
	for _, a := range haystack {
		if a == needle {
			return true
		}
	}
	return false
}

// TestAllow_DeniesUnknownInputs documents that the matrix is closed: any
// role/action/resource not declared in this package is denied by default.
//
// Validates: Requirement 4.2.
func TestAllow_DeniesUnknownInputs(t *testing.T) {
	t.Parallel()
	if Allow(Role("bogus"), ActionRead, ResourceScan) {
		t.Errorf("Allow with unknown role should be false")
	}
	if Allow(RoleOwner, Action("bogus"), ResourceScan) {
		t.Errorf("Allow with unknown action should be false")
	}
	if Allow(RoleOwner, ActionRead, Resource("bogus")) {
		t.Errorf("Allow with unknown resource should be false")
	}
}

// TestAllow_ForbidsKeyFourTwoBoundaries pins down the boundary cases that
// Requirement 4.2 calls out by name, so a future refactor cannot quietly
// promote a role past its limit.
//
// Validates: Requirement 4.2, Requirement 4.9.
func TestAllow_ForbidsKeyFourTwoBoundaries(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name          string
		role          Role
		action        Action
		resource      Resource
		shouldBeFalse bool
	}{
		{"admin cannot delete org", RoleAdmin, ActionDelete, ResourceOrganization, true},
		{"admin cannot transfer ownership", RoleAdmin, ActionTransferOwnership, ResourceOrganization, true},
		{"member cannot invite (create member)", RoleMember, ActionCreate, ResourceMember, true},
		{"member cannot change billing", RoleMember, ActionUpdate, ResourceBilling, true},
		{"member cannot create billing", RoleMember, ActionCreate, ResourceBilling, true},
		{"member cannot delete billing", RoleMember, ActionDelete, ResourceBilling, true},
		{"member cannot create finding", RoleMember, ActionCreate, ResourceFinding, true},
		{"viewer cannot create scan", RoleViewer, ActionCreate, ResourceScan, true},
		{"viewer cannot update finding", RoleViewer, ActionUpdate, ResourceFinding, true},
		{"viewer cannot delete report", RoleViewer, ActionDelete, ResourceReport, true},
		{"owner can transfer ownership", RoleOwner, ActionTransferOwnership, ResourceOrganization, false},
		{"owner can delete org", RoleOwner, ActionDelete, ResourceOrganization, false},
		{"member can update finding status", RoleMember, ActionUpdate, ResourceFinding, false},
		{"member can manage scan", RoleMember, ActionCreate, ResourceScan, false},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := Allow(tc.role, tc.action, tc.resource)
			if tc.shouldBeFalse && got {
				t.Fatalf("expected Allow(%s,%s,%s)=false, got true",
					tc.role, tc.action, tc.resource)
			}
			if !tc.shouldBeFalse && !got {
				t.Fatalf("expected Allow(%s,%s,%s)=true, got false",
					tc.role, tc.action, tc.resource)
			}
		})
	}
}

// TestRoleContext_RoundTrip asserts WithRole / RoleFromContext stash and
// retrieve the active role symmetrically.
func TestRoleContext_RoundTrip(t *testing.T) {
	t.Parallel()
	ctx := WithRole(context.Background(), RoleAdmin)
	got, ok := RoleFromContext(ctx)
	if !ok {
		t.Fatal("RoleFromContext: ok=false on populated ctx")
	}
	if got != RoleAdmin {
		t.Fatalf("RoleFromContext = %q, want %q", got, RoleAdmin)
	}
	if _, ok := RoleFromContext(context.Background()); ok {
		t.Fatal("RoleFromContext: ok=true on empty ctx")
	}
}

// TestRequireRole_RejectsUnauthorized covers the missing-role path: when
// no role has been stashed on the context, the middleware emits HTTP 403
// `forbidden_role` and never invokes the wrapped handler.
//
// Validates: Requirement 4.2, Requirement 8.3.
func TestRequireRole_RejectsUnauthorized(t *testing.T) {
	t.Parallel()
	mw := RequireRole(RoleViewer)
	called := false
	handler := mw(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		called = true
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/scans", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
	if called {
		t.Fatal("inner handler should not run when role is missing")
	}
	assertForbiddenRoleBody(t, rec)
}

// TestRequireRole_RejectsForbidden covers the insufficient-rank path:
// a role lower than the required minimum is rejected with HTTP 403.
//
// Validates: Requirement 4.2, Requirement 8.3.
func TestRequireRole_RejectsForbidden(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		min  Role
		have Role
	}{
		{"viewer trying admin route", RoleAdmin, RoleViewer},
		{"member trying owner route", RoleOwner, RoleMember},
		{"admin trying owner-only route", RoleOwner, RoleAdmin},
		{"viewer trying member route", RoleMember, RoleViewer},
		{"unknown role rejected", RoleViewer, Role("bogus")},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			mw := RequireRole(tc.min)
			called := false
			handler := mw(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				called = true
			}))

			req := httptest.NewRequest(http.MethodPost, "/api/v1/scans", strings.NewReader("{}"))
			req = req.WithContext(WithRole(req.Context(), tc.have))
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if rec.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want 403 (have=%s, min=%s)", rec.Code, tc.have, tc.min)
			}
			if called {
				t.Fatalf("inner handler ran for forbidden request (have=%s, min=%s)", tc.have, tc.min)
			}
			assertForbiddenRoleBody(t, rec)
		})
	}
}

// TestRequireRole_AllowsSufficient covers the happy path: roles at or
// above the required rank flow through to the wrapped handler.
//
// Validates: Requirement 4.2, Requirement 8.3.
func TestRequireRole_AllowsSufficient(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		min  Role
		have Role
	}{
		{"owner satisfies owner", RoleOwner, RoleOwner},
		{"owner satisfies admin", RoleAdmin, RoleOwner},
		{"admin satisfies admin", RoleAdmin, RoleAdmin},
		{"admin satisfies member", RoleMember, RoleAdmin},
		{"member satisfies member", RoleMember, RoleMember},
		{"member satisfies viewer", RoleViewer, RoleMember},
		{"viewer satisfies viewer", RoleViewer, RoleViewer},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			mw := RequireRole(tc.min)
			called := false
			handler := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				called = true
				w.WriteHeader(http.StatusNoContent)
			}))

			req := httptest.NewRequest(http.MethodGet, "/api/v1/scans", nil)
			req = req.WithContext(WithRole(req.Context(), tc.have))
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if !called {
				t.Fatalf("inner handler did not run (have=%s, min=%s)", tc.have, tc.min)
			}
			if rec.Code != http.StatusNoContent {
				t.Fatalf("status = %d, want 204 (have=%s, min=%s)",
					rec.Code, tc.have, tc.min)
			}
		})
	}
}

// TestRequireRole_PanicsOnUnknownMin documents that supplying an invalid
// minimum role to the factory is a programming error caught at boot.
func TestRequireRole_PanicsOnUnknownMin(t *testing.T) {
	t.Parallel()
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic when min is unknown")
		}
	}()
	RequireRole(Role("ghost"))
}

func assertForbiddenRoleBody(t *testing.T, rec *httptest.ResponseRecorder) {
	t.Helper()
	if got := rec.Header().Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", got)
	}
	var body map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("response body is not JSON: %v", err)
	}
	if body["error"] != "forbidden_role" {
		t.Errorf("error = %q, want forbidden_role", body["error"])
	}
}
