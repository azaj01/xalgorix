package orgs

import (
	"context"
	"errors"
	"sort"
	"strings"
	"sync"
	"testing"
)

// fakeWorkspaceRepo is a small in-memory [WorkspaceRepository] used by
// the table-driven tests below. It mirrors the production semantics
// just enough to exercise [WorkspaceService] without booting Postgres:
//
//   - workspaces are keyed by id and store the (org_id, name) tuple,
//   - CreateWorkspace enforces the `UNIQUE (org_id, name)` invariant
//     after a case-insensitive trim (matching the citext-leaning
//     equality the platform uses for human-supplied names),
//   - DeleteWorkspace returns [ErrWorkspaceNotFound] when no row
//     matches the (orgID, workspaceID) pair,
//   - UpdateMemberWorkspaceAccess models the `members.workspace_access`
//     uuid array with set semantics and validates both the member row
//     and that workspaceID belongs to orgID.
//
// The fake is concurrency-safe so the same instance can back parallel
// subtests if a future case needs them.
type fakeWorkspaceRepo struct {
	mu sync.Mutex
	// nextID generates deterministic ids of the form "ws-N" so test
	// assertions can match on the value without depending on UUID
	// generation.
	nextID int
	// workspaces is keyed by workspace id.
	workspaces map[string]Workspace
	// memberAccess maps (orgID, accountID) -> set of workspace ids.
	memberAccess map[string]map[string]struct{}
	// existingMembers records (orgID, accountID) tuples that should be
	// considered "real" members. AddAccess against a missing member
	// returns [ErrMemberNotFound] regardless of the memberAccess map.
	existingMembers map[string]struct{}
}

func newFakeWorkspaceRepo() *fakeWorkspaceRepo {
	return &fakeWorkspaceRepo{
		workspaces:      make(map[string]Workspace),
		memberAccess:    make(map[string]map[string]struct{}),
		existingMembers: make(map[string]struct{}),
	}
}

func memberKey(orgID, accountID string) string { return orgID + "|" + accountID }

// addMember registers (orgID, accountID) so AddAccess / RemoveAccess do
// not return [ErrMemberNotFound]. Tests call this to set up fixtures.
func (f *fakeWorkspaceRepo) addMember(orgID, accountID string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.existingMembers[memberKey(orgID, accountID)] = struct{}{}
}

// access returns a snapshot copy of (orgID, accountID)'s workspace
// access set so tests can assert without holding the lock.
func (f *fakeWorkspaceRepo) access(orgID, accountID string) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	set := f.memberAccess[memberKey(orgID, accountID)]
	out := make([]string, 0, len(set))
	for ws := range set {
		out = append(out, ws)
	}
	sort.Strings(out)
	return out
}

func (f *fakeWorkspaceRepo) CreateWorkspace(_ context.Context, orgID, name string) (Workspace, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	wantKey := strings.ToLower(strings.TrimSpace(name))
	for _, ws := range f.workspaces {
		if ws.OrgID == orgID && strings.ToLower(strings.TrimSpace(ws.Name)) == wantKey {
			return Workspace{}, ErrDuplicateWorkspaceName
		}
	}
	f.nextID++
	ws := Workspace{
		ID:    "ws-" + itoa(f.nextID),
		OrgID: orgID,
		Name:  name,
	}
	f.workspaces[ws.ID] = ws
	return ws, nil
}

func (f *fakeWorkspaceRepo) ListWorkspaces(_ context.Context, orgID string) ([]Workspace, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]Workspace, 0, len(f.workspaces))
	for _, ws := range f.workspaces {
		if ws.OrgID == orgID {
			out = append(out, ws)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (f *fakeWorkspaceRepo) DeleteWorkspace(_ context.Context, orgID, workspaceID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	ws, ok := f.workspaces[workspaceID]
	if !ok || ws.OrgID != orgID {
		return ErrWorkspaceNotFound
	}
	delete(f.workspaces, workspaceID)
	// Drop any lingering access entries so future AddAccess calls
	// against this workspace surface ErrWorkspaceNotFound.
	for _, set := range f.memberAccess {
		delete(set, workspaceID)
	}
	return nil
}

func (f *fakeWorkspaceRepo) UpdateMemberWorkspaceAccess(_ context.Context, orgID, accountID, workspaceID string, grant bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.existingMembers[memberKey(orgID, accountID)]; !ok {
		return ErrMemberNotFound
	}
	ws, ok := f.workspaces[workspaceID]
	if !ok || ws.OrgID != orgID {
		return ErrWorkspaceNotFound
	}
	mk := memberKey(orgID, accountID)
	set := f.memberAccess[mk]
	if set == nil {
		set = make(map[string]struct{})
		f.memberAccess[mk] = set
	}
	if grant {
		set[workspaceID] = struct{}{}
	} else {
		delete(set, workspaceID)
	}
	return nil
}

// itoa is a small wrapper around strconv.Itoa kept local so the import
// list stays minimal in test files.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	digits := []byte{}
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	if neg {
		digits = append([]byte{'-'}, digits...)
	}
	return string(digits)
}

func newServiceForTest(t *testing.T) (*WorkspaceService, *fakeWorkspaceRepo) {
	t.Helper()
	repo := newFakeWorkspaceRepo()
	svc, err := NewWorkspaceService(repo)
	if err != nil {
		t.Fatalf("NewWorkspaceService: unexpected error: %v", err)
	}
	return svc, repo
}

func TestNewWorkspaceService(t *testing.T) {
	t.Run("nil repo is rejected", func(t *testing.T) {
		if _, err := NewWorkspaceService(nil); err == nil {
			t.Fatal("expected an error for nil repo, got nil")
		}
	})
	t.Run("non-nil repo succeeds", func(t *testing.T) {
		repo := newFakeWorkspaceRepo()
		svc, err := NewWorkspaceService(repo)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if svc == nil {
			t.Fatal("expected non-nil service")
		}
	})
}

func TestWorkspaceService_Create(t *testing.T) {
	cases := []struct {
		name      string
		orgID     string
		input     string
		seed      []Workspace // workspaces inserted before the test case
		wantName  string
		wantErr   error
		wantCount int
	}{
		{
			name:      "creates a new workspace",
			orgID:     "org-1",
			input:     "default",
			wantName:  "default",
			wantCount: 1,
		},
		{
			name:      "trims surrounding whitespace",
			orgID:     "org-1",
			input:     "   prod-eu   ",
			wantName:  "prod-eu",
			wantCount: 1,
		},
		{
			name:    "empty org id is rejected",
			orgID:   "",
			input:   "default",
			wantErr: ErrOrgIDRequired,
		},
		{
			name:    "empty name is rejected",
			orgID:   "org-1",
			input:   "",
			wantErr: ErrWorkspaceNameRequired,
		},
		{
			name:    "whitespace-only name is rejected",
			orgID:   "org-1",
			input:   "   \t",
			wantErr: ErrWorkspaceNameRequired,
		},
		{
			name:  "duplicate name in same org is rejected",
			orgID: "org-1",
			seed: []Workspace{
				{OrgID: "org-1", Name: "default"},
			},
			input:     "default",
			wantErr:   ErrDuplicateWorkspaceName,
			wantCount: 1,
		},
		{
			name:  "duplicate name with different casing is rejected",
			orgID: "org-1",
			seed: []Workspace{
				{OrgID: "org-1", Name: "Default"},
			},
			input:     "default",
			wantErr:   ErrDuplicateWorkspaceName,
			wantCount: 1,
		},
		{
			name:  "same name in a different org is allowed",
			orgID: "org-2",
			seed: []Workspace{
				{OrgID: "org-1", Name: "default"},
			},
			input:     "default",
			wantName:  "default",
			wantCount: 2,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svc, repo := newServiceForTest(t)
			for _, ws := range tc.seed {
				if _, err := repo.CreateWorkspace(context.Background(), ws.OrgID, ws.Name); err != nil {
					t.Fatalf("seed CreateWorkspace: %v", err)
				}
			}

			got, err := svc.Create(context.Background(), tc.orgID, tc.input)

			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("Create error: want %v, got %v", tc.wantErr, err)
				}
			} else {
				if err != nil {
					t.Fatalf("Create: unexpected error: %v", err)
				}
				if got.OrgID != tc.orgID {
					t.Errorf("Workspace.OrgID: want %q, got %q", tc.orgID, got.OrgID)
				}
				if got.Name != tc.wantName {
					t.Errorf("Workspace.Name: want %q, got %q", tc.wantName, got.Name)
				}
				if got.ID == "" {
					t.Error("Workspace.ID: expected non-empty id from repository")
				}
			}

			if tc.wantCount != 0 && len(repo.workspaces) != tc.wantCount {
				t.Errorf("repo workspace count: want %d, got %d", tc.wantCount, len(repo.workspaces))
			}
		})
	}
}

func TestWorkspaceService_List(t *testing.T) {
	cases := []struct {
		name    string
		seed    []Workspace
		orgID   string
		want    []string // expected workspace names in order
		wantErr error
	}{
		{
			name:    "empty org id is rejected",
			orgID:   "",
			wantErr: ErrOrgIDRequired,
		},
		{
			name:  "returns empty slice for an org with no workspaces",
			orgID: "org-empty",
			seed: []Workspace{
				{OrgID: "org-other", Name: "alpha"},
			},
			want: []string{},
		},
		{
			name:  "returns workspaces sorted by name",
			orgID: "org-1",
			seed: []Workspace{
				{OrgID: "org-1", Name: "zebra"},
				{OrgID: "org-1", Name: "alpha"},
				{OrgID: "org-1", Name: "mango"},
				{OrgID: "org-other", Name: "noise"},
			},
			want: []string{"alpha", "mango", "zebra"},
		},
		{
			name:  "filters out other organizations",
			orgID: "org-1",
			seed: []Workspace{
				{OrgID: "org-1", Name: "in-scope"},
				{OrgID: "org-2", Name: "out-of-scope"},
			},
			want: []string{"in-scope"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svc, repo := newServiceForTest(t)
			for _, ws := range tc.seed {
				if _, err := repo.CreateWorkspace(context.Background(), ws.OrgID, ws.Name); err != nil {
					t.Fatalf("seed CreateWorkspace: %v", err)
				}
			}

			got, err := svc.List(context.Background(), tc.orgID)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("List error: want %v, got %v", tc.wantErr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("List: unexpected error: %v", err)
			}
			gotNames := make([]string, 0, len(got))
			for _, ws := range got {
				gotNames = append(gotNames, ws.Name)
			}
			if !equalStrings(gotNames, tc.want) {
				t.Errorf("List names: want %v, got %v", tc.want, gotNames)
			}
		})
	}
}

func TestWorkspaceService_AddAccess(t *testing.T) {
	cases := []struct {
		name        string
		orgID       string
		accountID   string
		workspaceID string
		setup       func(t *testing.T, svc *WorkspaceService, repo *fakeWorkspaceRepo) (orgID, accountID, workspaceID string)
		wantErr     error
		wantAccess  []string
	}{
		{
			name:    "empty org id is rejected",
			orgID:   "",
			wantErr: ErrOrgIDRequired,
		},
		{
			name:      "empty account id is rejected",
			orgID:     "org-1",
			accountID: "",
			wantErr:   ErrAccountIDRequired,
		},
		{
			name:        "empty workspace id is rejected",
			orgID:       "org-1",
			accountID:   "acct-1",
			workspaceID: "",
			wantErr:     ErrWorkspaceIDRequired,
		},
		{
			name: "missing member is rejected",
			setup: func(t *testing.T, _ *WorkspaceService, repo *fakeWorkspaceRepo) (string, string, string) {
				ws, err := repo.CreateWorkspace(context.Background(), "org-1", "default")
				if err != nil {
					t.Fatalf("seed: %v", err)
				}
				// Note: no addMember call; AddAccess should reject.
				return "org-1", "acct-1", ws.ID
			},
			wantErr: ErrMemberNotFound,
		},
		{
			name: "missing workspace is rejected",
			setup: func(t *testing.T, _ *WorkspaceService, repo *fakeWorkspaceRepo) (string, string, string) {
				repo.addMember("org-1", "acct-1")
				return "org-1", "acct-1", "ws-does-not-exist"
			},
			wantErr: ErrWorkspaceNotFound,
		},
		{
			name: "workspace from another org is rejected",
			setup: func(t *testing.T, _ *WorkspaceService, repo *fakeWorkspaceRepo) (string, string, string) {
				repo.addMember("org-1", "acct-1")
				ws, err := repo.CreateWorkspace(context.Background(), "org-2", "stranger")
				if err != nil {
					t.Fatalf("seed: %v", err)
				}
				return "org-1", "acct-1", ws.ID
			},
			wantErr: ErrWorkspaceNotFound,
		},
		{
			name: "grants access to a member",
			setup: func(t *testing.T, _ *WorkspaceService, repo *fakeWorkspaceRepo) (string, string, string) {
				repo.addMember("org-1", "acct-1")
				ws, err := repo.CreateWorkspace(context.Background(), "org-1", "default")
				if err != nil {
					t.Fatalf("seed: %v", err)
				}
				return "org-1", "acct-1", ws.ID
			},
			wantAccess: []string{"ws-1"},
		},
		{
			name: "is idempotent on repeated grant",
			setup: func(t *testing.T, svc *WorkspaceService, repo *fakeWorkspaceRepo) (string, string, string) {
				repo.addMember("org-1", "acct-1")
				ws, err := repo.CreateWorkspace(context.Background(), "org-1", "default")
				if err != nil {
					t.Fatalf("seed: %v", err)
				}
				if err := svc.AddAccess(context.Background(), "org-1", "acct-1", ws.ID); err != nil {
					t.Fatalf("first AddAccess: %v", err)
				}
				return "org-1", "acct-1", ws.ID
			},
			wantAccess: []string{"ws-1"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svc, repo := newServiceForTest(t)
			orgID, accountID, workspaceID := tc.orgID, tc.accountID, tc.workspaceID
			if tc.setup != nil {
				orgID, accountID, workspaceID = tc.setup(t, svc, repo)
			}

			err := svc.AddAccess(context.Background(), orgID, accountID, workspaceID)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("AddAccess error: want %v, got %v", tc.wantErr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("AddAccess: unexpected error: %v", err)
			}
			gotAccess := repo.access(orgID, accountID)
			if !equalStrings(gotAccess, tc.wantAccess) {
				t.Errorf("workspace_access: want %v, got %v", tc.wantAccess, gotAccess)
			}
		})
	}
}

func TestWorkspaceService_RemoveAccess(t *testing.T) {
	cases := []struct {
		name        string
		setup       func(t *testing.T, svc *WorkspaceService, repo *fakeWorkspaceRepo) (orgID, accountID, workspaceID string)
		orgID       string
		accountID   string
		workspaceID string
		wantErr     error
		wantAccess  []string
	}{
		{
			name:    "empty org id is rejected",
			wantErr: ErrOrgIDRequired,
		},
		{
			name:      "empty account id is rejected",
			orgID:     "org-1",
			wantErr:   ErrAccountIDRequired,
		},
		{
			name:        "empty workspace id is rejected",
			orgID:       "org-1",
			accountID:   "acct-1",
			wantErr:     ErrWorkspaceIDRequired,
		},
		{
			name: "removes existing access",
			setup: func(t *testing.T, svc *WorkspaceService, repo *fakeWorkspaceRepo) (string, string, string) {
				repo.addMember("org-1", "acct-1")
				ws, err := repo.CreateWorkspace(context.Background(), "org-1", "default")
				if err != nil {
					t.Fatalf("seed: %v", err)
				}
				if err := svc.AddAccess(context.Background(), "org-1", "acct-1", ws.ID); err != nil {
					t.Fatalf("AddAccess seed: %v", err)
				}
				return "org-1", "acct-1", ws.ID
			},
			wantAccess: []string{},
		},
		{
			name: "is idempotent when access is not present",
			setup: func(t *testing.T, _ *WorkspaceService, repo *fakeWorkspaceRepo) (string, string, string) {
				repo.addMember("org-1", "acct-1")
				ws, err := repo.CreateWorkspace(context.Background(), "org-1", "default")
				if err != nil {
					t.Fatalf("seed: %v", err)
				}
				return "org-1", "acct-1", ws.ID
			},
			wantAccess: []string{},
		},
		{
			name: "leaves unrelated access untouched",
			setup: func(t *testing.T, svc *WorkspaceService, repo *fakeWorkspaceRepo) (string, string, string) {
				repo.addMember("org-1", "acct-1")
				keep, err := repo.CreateWorkspace(context.Background(), "org-1", "keep")
				if err != nil {
					t.Fatalf("seed keep: %v", err)
				}
				drop, err := repo.CreateWorkspace(context.Background(), "org-1", "drop")
				if err != nil {
					t.Fatalf("seed drop: %v", err)
				}
				if err := svc.AddAccess(context.Background(), "org-1", "acct-1", keep.ID); err != nil {
					t.Fatalf("AddAccess keep: %v", err)
				}
				if err := svc.AddAccess(context.Background(), "org-1", "acct-1", drop.ID); err != nil {
					t.Fatalf("AddAccess drop: %v", err)
				}
				return "org-1", "acct-1", drop.ID
			},
			wantAccess: []string{"ws-1"},
		},
		{
			name: "missing member is rejected",
			setup: func(t *testing.T, _ *WorkspaceService, repo *fakeWorkspaceRepo) (string, string, string) {
				ws, err := repo.CreateWorkspace(context.Background(), "org-1", "default")
				if err != nil {
					t.Fatalf("seed: %v", err)
				}
				return "org-1", "acct-1", ws.ID
			},
			wantErr: ErrMemberNotFound,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svc, repo := newServiceForTest(t)
			orgID, accountID, workspaceID := tc.orgID, tc.accountID, tc.workspaceID
			if tc.setup != nil {
				orgID, accountID, workspaceID = tc.setup(t, svc, repo)
			}

			err := svc.RemoveAccess(context.Background(), orgID, accountID, workspaceID)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("RemoveAccess error: want %v, got %v", tc.wantErr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("RemoveAccess: unexpected error: %v", err)
			}
			gotAccess := repo.access(orgID, accountID)
			if !equalStrings(gotAccess, tc.wantAccess) {
				t.Errorf("workspace_access: want %v, got %v", tc.wantAccess, gotAccess)
			}
		})
	}
}

func TestWorkspaceService_Delete(t *testing.T) {
	cases := []struct {
		name        string
		setup       func(t *testing.T, svc *WorkspaceService, repo *fakeWorkspaceRepo) (orgID, workspaceID string)
		orgID       string
		workspaceID string
		wantErr     error
	}{
		{
			name:    "empty org id is rejected",
			wantErr: ErrOrgIDRequired,
		},
		{
			name:    "empty workspace id is rejected",
			orgID:   "org-1",
			wantErr: ErrWorkspaceIDRequired,
		},
		{
			name: "deletes an existing workspace",
			setup: func(t *testing.T, _ *WorkspaceService, repo *fakeWorkspaceRepo) (string, string) {
				ws, err := repo.CreateWorkspace(context.Background(), "org-1", "default")
				if err != nil {
					t.Fatalf("seed: %v", err)
				}
				return "org-1", ws.ID
			},
		},
		{
			name: "missing workspace is reported",
			setup: func(t *testing.T, _ *WorkspaceService, _ *fakeWorkspaceRepo) (string, string) {
				return "org-1", "ws-missing"
			},
			wantErr: ErrWorkspaceNotFound,
		},
		{
			name: "workspace from another org is reported",
			setup: func(t *testing.T, _ *WorkspaceService, repo *fakeWorkspaceRepo) (string, string) {
				ws, err := repo.CreateWorkspace(context.Background(), "org-2", "stranger")
				if err != nil {
					t.Fatalf("seed: %v", err)
				}
				return "org-1", ws.ID
			},
			wantErr: ErrWorkspaceNotFound,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svc, repo := newServiceForTest(t)
			orgID, workspaceID := tc.orgID, tc.workspaceID
			if tc.setup != nil {
				orgID, workspaceID = tc.setup(t, svc, repo)
			}

			err := svc.Delete(context.Background(), orgID, workspaceID)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("Delete error: want %v, got %v", tc.wantErr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("Delete: unexpected error: %v", err)
			}
			if _, ok := repo.workspaces[workspaceID]; ok {
				t.Errorf("expected workspace %q to be removed from repo", workspaceID)
			}
		})
	}
}

// TestWorkspace_String exercises the [Workspace.String] formatter so a
// future field addition does not silently break the log output the
// package exposes.
func TestWorkspace_String(t *testing.T) {
	got := Workspace{ID: "ws-1", OrgID: "org-1", Name: "default"}.String()
	want := `Workspace{id=ws-1,org=org-1,name="default"}`
	if got != want {
		t.Errorf("Workspace.String: want %q, got %q", want, got)
	}
}

func equalStrings(a, b []string) bool {
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
