package orgs

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
)

// ----------------------------------------------------------------------
// Test fixtures
// ----------------------------------------------------------------------

// fakeMemberRepo is an in-memory [MemberRepository] used to exercise
// [MemberService] without a live PostgreSQL. The fake mirrors the
// production semantics that matter to the service-level tests:
//
//   - CreateInvite enforces the partial unique-pending invariant
//     declared by `invites_org_email_pending_idx`.
//   - AcceptInvite atomically validates the invite is still pending
//     and not expired before inserting the matching `members` row.
//   - ChangeMemberRole and RemoveMember enforce the "≥ 1 Owner"
//     invariant from Requirement 4.9.
//
// Concurrency safety is provided by a single mutex; the tests never
// fan out across goroutines but the lock makes the fake
// composition-friendly for future tests.
type fakeMemberRepo struct {
	mu sync.Mutex

	// invites is keyed by invite id.
	invites map[uuid.UUID]Invite
	// inviteByHash indexes the same set by token_hash so AcceptInvite
	// can perform its O(1) lookup.
	inviteByHash map[string]uuid.UUID
	// members is keyed by (orgID, accountID).
	members map[memberPK]Member
}

type memberPK struct {
	orgID     uuid.UUID
	accountID uuid.UUID
}

func newFakeMemberRepo() *fakeMemberRepo {
	return &fakeMemberRepo{
		invites:      make(map[uuid.UUID]Invite),
		inviteByHash: make(map[string]uuid.UUID),
		members:      make(map[memberPK]Member),
	}
}

func (f *fakeMemberRepo) CreateInvite(_ context.Context, in CreateInviteInput) (Invite, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	// Partial unique index: a single (org_id, email) pending invite.
	for _, existing := range f.invites {
		if existing.OrgID == in.OrgID &&
			existing.Email == in.Email &&
			existing.AcceptedAt == nil &&
			existing.RevokedAt == nil {
			return Invite{}, fmt.Errorf("orgs: pending invite already exists for %s", in.Email)
		}
	}
	id := uuid.New()
	invite := Invite{
		ID:        id,
		OrgID:     in.OrgID,
		Email:     in.Email,
		Role:      in.Role,
		InvitedBy: in.InvitedBy,
		ExpiresAt: in.ExpiresAt,
		CreatedAt: time.Now().UTC(),
	}
	f.invites[id] = invite
	f.inviteByHash[in.TokenHash] = id
	return invite, nil
}

func (f *fakeMemberRepo) ResendInvite(_ context.Context, orgID, inviteID uuid.UUID, expiresAt time.Time) (Invite, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	invite, ok := f.invites[inviteID]
	if !ok || invite.OrgID != orgID {
		return Invite{}, ErrInviteNotFound
	}
	if invite.AcceptedAt != nil || invite.RevokedAt != nil {
		return Invite{}, ErrInviteNotPending
	}
	invite.ExpiresAt = expiresAt
	f.invites[inviteID] = invite
	return invite, nil
}

func (f *fakeMemberRepo) AcceptInvite(_ context.Context, tokenHash string, accountID uuid.UUID, acceptedAt time.Time) (Member, Invite, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	id, ok := f.inviteByHash[tokenHash]
	if !ok {
		return Member{}, Invite{}, ErrInviteNotFound
	}
	invite := f.invites[id]
	if invite.AcceptedAt != nil || invite.RevokedAt != nil {
		return Member{}, Invite{}, ErrInviteNotPending
	}
	if !invite.ExpiresAt.IsZero() && invite.ExpiresAt.Before(acceptedAt) {
		return Member{}, Invite{}, ErrInviteExpired
	}
	pk := memberPK{orgID: invite.OrgID, accountID: accountID}
	if _, exists := f.members[pk]; exists {
		// In production this would be a CHECK violation surfaced
		// as a unique-key error. For the service-level tests we
		// surface a simple sentinel.
		return Member{}, Invite{}, fmt.Errorf("orgs: account already a member")
	}
	member := Member{
		OrgID:     invite.OrgID,
		AccountID: accountID,
		Role:      invite.Role,
		CreatedAt: acceptedAt,
	}
	f.members[pk] = member
	stamp := acceptedAt
	invite.AcceptedAt = &stamp
	f.invites[id] = invite
	return member, invite, nil
}

func (f *fakeMemberRepo) ChangeMemberRole(_ context.Context, orgID, accountID uuid.UUID, newRole Role) (Member, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	pk := memberPK{orgID: orgID, accountID: accountID}
	member, ok := f.members[pk]
	if !ok {
		return Member{}, ErrMemberNotFound
	}
	if member.Role == RoleOwner && newRole != RoleOwner {
		// Atomic "≥ 1 Owner" check.
		if f.countOwners(orgID) <= 1 {
			return Member{}, ErrLastOwner
		}
	}
	member.Role = newRole
	f.members[pk] = member
	return member, nil
}

func (f *fakeMemberRepo) RemoveMember(_ context.Context, orgID, accountID uuid.UUID) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	pk := memberPK{orgID: orgID, accountID: accountID}
	member, ok := f.members[pk]
	if !ok {
		return ErrMemberNotFound
	}
	if member.Role == RoleOwner && f.countOwners(orgID) <= 1 {
		return ErrLastOwner
	}
	delete(f.members, pk)
	return nil
}

// countOwners walks the in-memory members map. The test fake is
// small so a linear scan is plenty.
func (f *fakeMemberRepo) countOwners(orgID uuid.UUID) int {
	n := 0
	for pk, m := range f.members {
		if pk.orgID == orgID && m.Role == RoleOwner {
			n++
		}
	}
	return n
}

// addMember bypasses CreateInvite/Accept to seed members directly,
// which is useful for ChangeRole and Remove tests that don't care
// about the invite lifecycle.
func (f *fakeMemberRepo) addMember(orgID, accountID uuid.UUID, role Role) {
	f.mu.Lock()
	defer f.mu.Unlock()
	pk := memberPK{orgID: orgID, accountID: accountID}
	f.members[pk] = Member{OrgID: orgID, AccountID: accountID, Role: role, CreatedAt: time.Now().UTC()}
}

// ----------------------------------------------------------------------
// Recording session revoker
// ----------------------------------------------------------------------

// recordingRevoker captures every RevokeFor call so tests can assert
// the contract from Requirement 4.6 — that Remove fires the revoker
// exactly once for the (orgID, accountID) it just deleted.
type recordingRevoker struct {
	mu    sync.Mutex
	calls []revokeCall
	err   error
}

type revokeCall struct {
	OrgID     uuid.UUID
	AccountID uuid.UUID
	At        time.Time
}

func (r *recordingRevoker) RevokeFor(_ context.Context, orgID, accountID uuid.UUID) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, revokeCall{OrgID: orgID, AccountID: accountID, At: time.Now().UTC()})
	return r.err
}

func (r *recordingRevoker) snapshot() []revokeCall {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]revokeCall, len(r.calls))
	copy(out, r.calls)
	return out
}

// ----------------------------------------------------------------------
// Helpers
// ----------------------------------------------------------------------

// testHMACKey returns a fixed 32-byte signing key. Using a constant
// key lets the tests recompute the expected HMAC of a known token
// independently and compare it against `invites.token_hash` to
// confirm the service is hashing exactly what it claims.
func testHMACKey() []byte {
	k := make([]byte, 32)
	for i := range k {
		k[i] = byte(i + 1)
	}
	return k
}

// fixedClock returns a clock function bound to t. Useful for driving
// Accept across the expiry boundary without time.Sleep.
func fixedClock(t time.Time) func() time.Time {
	return func() time.Time { return t }
}

// fixedReader returns a reader that fills any buffer with payload,
// truncating or repeating as needed. The pattern keeps token bytes
// reproducible across test runs.
func fixedReader(payload []byte) func(b []byte) (int, error) {
	return func(b []byte) (int, error) {
		for i := range b {
			b[i] = payload[i%len(payload)]
		}
		return len(b), nil
	}
}

// expectedHash returns the lowercase hex HMAC-SHA256 the service
// would compute for token under the test signing key.
func expectedHash(token string) string {
	mac := hmac.New(sha256.New, testHMACKey())
	mac.Write([]byte(token))
	return hex.EncodeToString(mac.Sum(nil))
}

func newMemberServiceForTest(t *testing.T, opts ...MemberServiceOption) (*MemberService, *fakeMemberRepo, *recordingRevoker) {
	t.Helper()
	repo := newFakeMemberRepo()
	rev := &recordingRevoker{}
	svc := NewMemberService(repo, rev, testHMACKey(), opts...)
	return svc, repo, rev
}

// ----------------------------------------------------------------------
// Constructor
// ----------------------------------------------------------------------

func TestNewMemberService_PanicsOnBadInputs(t *testing.T) {
	cases := []struct {
		name    string
		repo    MemberRepository
		revoker SessionRevoker
		key     []byte
	}{
		{"nil repo", nil, NoopSessionRevoker, testHMACKey()},
		{"nil revoker", newFakeMemberRepo(), nil, testHMACKey()},
		{"short key", newFakeMemberRepo(), NoopSessionRevoker, make([]byte, 16)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r == nil {
					t.Fatal("expected panic, got none")
				}
			}()
			_ = NewMemberService(tc.repo, tc.revoker, tc.key)
		})
	}
}

// ----------------------------------------------------------------------
// Invite
// ----------------------------------------------------------------------

// TestInvite_HashesTokenAtRest exercises the core Requirement 4.3
// invariant: the raw token is returned to the caller exactly once
// while only its HMAC-SHA256 hash is persisted. The test also
// confirms the token is 43 URL-safe base64 chars (32 random bytes,
// no padding).
//
// Validates: Requirement 4.3.
func TestInvite_HashesTokenAtRest(t *testing.T) {
	svc, repo, _ := newMemberServiceForTest(t,
		WithRandReader(fixedReader([]byte{0xAA, 0xBB, 0xCC, 0xDD})),
	)
	orgID := uuid.New()
	inviter := uuid.New()

	got, err := svc.Invite(context.Background(), orgID, inviter, "alice@example.com", RoleMember)
	if err != nil {
		t.Fatalf("Invite: unexpected error: %v", err)
	}
	if got.RawToken == "" {
		t.Fatal("RawToken: expected a non-empty raw token")
	}
	if len(got.RawToken) != 43 {
		t.Errorf("RawToken length: want 43, got %d (%q)", len(got.RawToken), got.RawToken)
	}
	// The raw token must decode as 32 URL-safe base64 bytes.
	decoded, err := base64.RawURLEncoding.DecodeString(got.RawToken)
	if err != nil {
		t.Errorf("RawToken: not URL-safe base64: %v", err)
	} else if len(decoded) != InviteTokenBytes {
		t.Errorf("RawToken: decoded %d bytes, want %d", len(decoded), InviteTokenBytes)
	}

	// The persisted invite must NOT contain the raw token in any
	// printable field, only the HMAC of it.
	wantHash := expectedHash(got.RawToken)
	repo.mu.Lock()
	defer repo.mu.Unlock()
	if id, ok := repo.inviteByHash[wantHash]; !ok || id != got.Invite.ID {
		t.Fatalf("token_hash: did not find expected hash for the issued invite")
	}
	for _, hash := range keysOf(repo.inviteByHash) {
		if hash == got.RawToken {
			t.Fatal("invites store: raw token leaked into the persisted hash column")
		}
	}
}

// TestInvite_ValidatesInputs covers the early-validation matrix.
func TestInvite_ValidatesInputs(t *testing.T) {
	svc, _, _ := newMemberServiceForTest(t)
	ctx := context.Background()

	cases := []struct {
		name    string
		orgID   uuid.UUID
		invBy   uuid.UUID
		email   string
		role    Role
		wantErr error
	}{
		{"missing org id", uuid.Nil, uuid.New(), "x@y.z", RoleMember, ErrOrgIDRequired},
		{"missing inviter", uuid.New(), uuid.Nil, "x@y.z", RoleMember, ErrAccountIDRequired},
		{"empty email", uuid.New(), uuid.New(), "  ", RoleMember, ErrInviteEmailRequired},
		{"role owner rejected", uuid.New(), uuid.New(), "x@y.z", RoleOwner, ErrInviteRoleInvalid},
		{"role unknown rejected", uuid.New(), uuid.New(), "x@y.z", Role("god"), ErrInviteRoleInvalid},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := svc.Invite(ctx, tc.orgID, tc.invBy, tc.email, tc.role)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("Invite error: want %v, got %v", tc.wantErr, err)
			}
		})
	}
}

// TestInvite_SetsExpiryToSevenDays asserts the invite TTL matches
// Requirement 4.3 ("valid for 7 days"). We pin the clock so the
// test does not race with a leap-second drift.
//
// Validates: Requirement 4.3.
func TestInvite_SetsExpiryToSevenDays(t *testing.T) {
	now := time.Date(2025, 1, 15, 12, 0, 0, 0, time.UTC)
	svc, _, _ := newMemberServiceForTest(t, WithClock(fixedClock(now)))

	got, err := svc.Invite(context.Background(), uuid.New(), uuid.New(), "alice@example.com", RoleAdmin)
	if err != nil {
		t.Fatalf("Invite: unexpected error: %v", err)
	}
	want := now.Add(InviteTTL)
	if !got.Invite.ExpiresAt.Equal(want) {
		t.Errorf("ExpiresAt: want %v, got %v", want, got.Invite.ExpiresAt)
	}
}

// ----------------------------------------------------------------------
// Resend
// ----------------------------------------------------------------------

// TestResend_RollsExpiryForward asserts a pending invite's
// expires_at is reset to now+7d.
//
// Validates: Requirement 4.3 (resend rolls the window forward).
func TestResend_RollsExpiryForward(t *testing.T) {
	t0 := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	clock := &mutableClock{t: t0}
	svc, _, _ := newMemberServiceForTest(t, WithClock(clock.now))

	issued, err := svc.Invite(context.Background(), uuid.New(), uuid.New(), "alice@example.com", RoleMember)
	if err != nil {
		t.Fatalf("Invite: %v", err)
	}
	originalExpiry := issued.Invite.ExpiresAt

	// Move the clock forward by 3 days and resend.
	clock.advance(3 * 24 * time.Hour)
	resent, err := svc.Resend(context.Background(), issued.Invite.OrgID, issued.Invite.ID)
	if err != nil {
		t.Fatalf("Resend: %v", err)
	}
	want := clock.now().Add(InviteTTL)
	if !resent.ExpiresAt.Equal(want) {
		t.Errorf("ExpiresAt after Resend: want %v, got %v", want, resent.ExpiresAt)
	}
	if !resent.ExpiresAt.After(originalExpiry) {
		t.Errorf("Resend should advance ExpiresAt past %v, got %v", originalExpiry, resent.ExpiresAt)
	}
}

// TestResend_RejectsAcceptedInvite covers the "only allowed when
// status is pending" rule of task 3.3.
//
// Validates: Requirement 4.3.
func TestResend_RejectsAcceptedInvite(t *testing.T) {
	now := time.Date(2025, 6, 1, 12, 0, 0, 0, time.UTC)
	svc, _, _ := newMemberServiceForTest(t, WithClock(fixedClock(now)))

	issued, err := svc.Invite(context.Background(), uuid.New(), uuid.New(), "alice@example.com", RoleViewer)
	if err != nil {
		t.Fatalf("Invite: %v", err)
	}
	if _, err := svc.Accept(context.Background(), issued.RawToken, uuid.New()); err != nil {
		t.Fatalf("Accept: %v", err)
	}
	_, err = svc.Resend(context.Background(), issued.Invite.OrgID, issued.Invite.ID)
	if !errors.Is(err, ErrInviteNotPending) {
		t.Fatalf("Resend: want ErrInviteNotPending, got %v", err)
	}
}

func TestResend_ValidatesInputs(t *testing.T) {
	svc, _, _ := newMemberServiceForTest(t)
	ctx := context.Background()
	if _, err := svc.Resend(ctx, uuid.Nil, uuid.New()); !errors.Is(err, ErrOrgIDRequired) {
		t.Errorf("nil orgID: want ErrOrgIDRequired, got %v", err)
	}
	if _, err := svc.Resend(ctx, uuid.New(), uuid.Nil); !errors.Is(err, ErrInviteIDRequired) {
		t.Errorf("nil inviteID: want ErrInviteIDRequired, got %v", err)
	}
}

// ----------------------------------------------------------------------
// Accept
// ----------------------------------------------------------------------

// TestAccept_HappyPath issues an invite, accepts it, and asserts a
// `members` row materialises with the invited role.
//
// Validates: Requirement 4.4.
func TestAccept_HappyPath(t *testing.T) {
	now := time.Date(2025, 6, 1, 12, 0, 0, 0, time.UTC)
	svc, repo, _ := newMemberServiceForTest(t, WithClock(fixedClock(now)))

	orgID := uuid.New()
	inviter := uuid.New()
	issued, err := svc.Invite(context.Background(), orgID, inviter, "bob@example.com", RoleAdmin)
	if err != nil {
		t.Fatalf("Invite: %v", err)
	}
	accountID := uuid.New()
	got, err := svc.Accept(context.Background(), issued.RawToken, accountID)
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	if got.OrgID != orgID || got.AccountID != accountID {
		t.Errorf("Member identity: want (%s,%s), got (%s,%s)", orgID, accountID, got.OrgID, got.AccountID)
	}
	if got.Role != RoleAdmin {
		t.Errorf("Member.Role: want %q, got %q", RoleAdmin, got.Role)
	}
	// The invite should now be marked accepted.
	repo.mu.Lock()
	persisted := repo.invites[issued.Invite.ID]
	repo.mu.Unlock()
	if persisted.AcceptedAt == nil {
		t.Errorf("invite.accepted_at: want non-nil, got nil")
	}
}

// TestAccept_ExpiredReturnsHTTP410Sentinel asserts an invite past
// its expires_at is rejected with ErrInviteExpired (HTTP 410 per
// Requirement 4.5).
//
// Validates: Requirement 4.5.
func TestAccept_ExpiredReturnsHTTP410Sentinel(t *testing.T) {
	clock := &mutableClock{t: time.Date(2025, 6, 1, 12, 0, 0, 0, time.UTC)}
	svc, _, _ := newMemberServiceForTest(t, WithClock(clock.now))

	issued, err := svc.Invite(context.Background(), uuid.New(), uuid.New(), "bob@example.com", RoleMember)
	if err != nil {
		t.Fatalf("Invite: %v", err)
	}

	// Push the clock past the 7-day TTL.
	clock.advance(InviteTTL + time.Minute)

	_, err = svc.Accept(context.Background(), issued.RawToken, uuid.New())
	if !errors.Is(err, ErrInviteExpired) {
		t.Fatalf("Accept on expired invite: want ErrInviteExpired (HTTP 410), got %v", err)
	}
}

// TestAccept_RejectsUnknownToken asserts a token that does not
// match any persisted invite hash is rejected with the
// generic-not-found sentinel so an attacker cannot enumerate live
// invites.
func TestAccept_RejectsUnknownToken(t *testing.T) {
	svc, _, _ := newMemberServiceForTest(t)
	// Construct a structurally valid but unknown token.
	bogus := base64.RawURLEncoding.EncodeToString(make([]byte, InviteTokenBytes))
	_, err := svc.Accept(context.Background(), bogus, uuid.New())
	if !errors.Is(err, ErrInviteNotFound) {
		t.Fatalf("Accept unknown token: want ErrInviteNotFound, got %v", err)
	}
}

// TestAccept_RejectsMalformedToken asserts a structurally invalid
// token is rejected before reaching the repository.
func TestAccept_RejectsMalformedToken(t *testing.T) {
	svc, _, _ := newMemberServiceForTest(t)
	_, err := svc.Accept(context.Background(), "not a valid token", uuid.New())
	if !errors.Is(err, ErrInviteTokenInvalid) {
		t.Fatalf("Accept malformed token: want ErrInviteTokenInvalid, got %v", err)
	}
}

func TestAccept_ValidatesInputs(t *testing.T) {
	svc, _, _ := newMemberServiceForTest(t)
	ctx := context.Background()
	if _, err := svc.Accept(ctx, "  ", uuid.New()); !errors.Is(err, ErrInviteTokenRequired) {
		t.Errorf("empty token: want ErrInviteTokenRequired, got %v", err)
	}
	bogus := base64.RawURLEncoding.EncodeToString(make([]byte, InviteTokenBytes))
	if _, err := svc.Accept(ctx, bogus, uuid.Nil); !errors.Is(err, ErrAccountIDRequired) {
		t.Errorf("nil account id: want ErrAccountIDRequired, got %v", err)
	}
}

// ----------------------------------------------------------------------
// ChangeRole
// ----------------------------------------------------------------------

// TestChangeRole_DemotesAdmin asserts a regular role change works.
func TestChangeRole_DemotesAdmin(t *testing.T) {
	svc, repo, _ := newMemberServiceForTest(t)
	orgID, accountID := uuid.New(), uuid.New()
	repo.addMember(orgID, accountID, RoleAdmin)

	got, err := svc.ChangeRole(context.Background(), orgID, accountID, RoleViewer)
	if err != nil {
		t.Fatalf("ChangeRole: %v", err)
	}
	if got.Role != RoleViewer {
		t.Errorf("Role: want %q, got %q", RoleViewer, got.Role)
	}
}

// TestChangeRole_GuardsLastOwner asserts demoting a sole Owner
// returns ErrLastOwner per Requirement 4.9.
//
// Validates: Requirement 4.9.
func TestChangeRole_GuardsLastOwner(t *testing.T) {
	svc, repo, _ := newMemberServiceForTest(t)
	orgID, sole := uuid.New(), uuid.New()
	repo.addMember(orgID, sole, RoleOwner)

	_, err := svc.ChangeRole(context.Background(), orgID, sole, RoleAdmin)
	if !errors.Is(err, ErrLastOwner) {
		t.Fatalf("ChangeRole sole Owner -> Admin: want ErrLastOwner, got %v", err)
	}

	// Adding a second owner unblocks the demotion.
	other := uuid.New()
	repo.addMember(orgID, other, RoleOwner)
	got, err := svc.ChangeRole(context.Background(), orgID, sole, RoleAdmin)
	if err != nil {
		t.Fatalf("ChangeRole with two Owners: %v", err)
	}
	if got.Role != RoleAdmin {
		t.Errorf("Role: want %q, got %q", RoleAdmin, got.Role)
	}
}

// TestChangeRole_RejectsBadRole asserts the validation guard.
func TestChangeRole_RejectsBadRole(t *testing.T) {
	svc, repo, _ := newMemberServiceForTest(t)
	orgID, accountID := uuid.New(), uuid.New()
	repo.addMember(orgID, accountID, RoleMember)

	_, err := svc.ChangeRole(context.Background(), orgID, accountID, Role("emperor"))
	if !errors.Is(err, ErrMemberRoleInvalid) {
		t.Fatalf("ChangeRole bad role: want ErrMemberRoleInvalid, got %v", err)
	}
}

func TestChangeRole_ValidatesIDs(t *testing.T) {
	svc, _, _ := newMemberServiceForTest(t)
	ctx := context.Background()
	if _, err := svc.ChangeRole(ctx, uuid.Nil, uuid.New(), RoleMember); !errors.Is(err, ErrOrgIDRequired) {
		t.Errorf("nil orgID: want ErrOrgIDRequired, got %v", err)
	}
	if _, err := svc.ChangeRole(ctx, uuid.New(), uuid.Nil, RoleMember); !errors.Is(err, ErrAccountIDRequired) {
		t.Errorf("nil accountID: want ErrAccountIDRequired, got %v", err)
	}
}

// ----------------------------------------------------------------------
// Remove
// ----------------------------------------------------------------------

// TestRemove_TriggersSessionRevocation asserts the
// Requirement 4.6 contract: once Remove returns the session
// revoker has been called for the (orgID, accountID) pair, so
// the workspace-access fan-out can flip within 5 seconds.
//
// Validates: Requirement 4.6.
func TestRemove_TriggersSessionRevocation(t *testing.T) {
	svc, repo, rev := newMemberServiceForTest(t)
	orgID, accountID := uuid.New(), uuid.New()
	// Two owners so removing this one does not trip the
	// "≥ 1 Owner" guard.
	repo.addMember(orgID, uuid.New(), RoleOwner)
	repo.addMember(orgID, accountID, RoleAdmin)

	if err := svc.Remove(context.Background(), orgID, accountID); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	calls := rev.snapshot()
	if len(calls) != 1 {
		t.Fatalf("revoker calls: want 1, got %d (%+v)", len(calls), calls)
	}
	got := calls[0]
	if got.OrgID != orgID || got.AccountID != accountID {
		t.Errorf("revoker call: want (%s,%s), got (%s,%s)", orgID, accountID, got.OrgID, got.AccountID)
	}
	// The member row must be gone.
	repo.mu.Lock()
	_, present := repo.members[memberPK{orgID: orgID, accountID: accountID}]
	repo.mu.Unlock()
	if present {
		t.Error("member row still present after Remove")
	}
}

// TestRemove_GuardsLastOwner asserts removing the only Owner is
// rejected and that the revoker is NOT called when the row remains.
//
// Validates: Requirement 4.9.
func TestRemove_GuardsLastOwner(t *testing.T) {
	svc, repo, rev := newMemberServiceForTest(t)
	orgID, sole := uuid.New(), uuid.New()
	repo.addMember(orgID, sole, RoleOwner)

	err := svc.Remove(context.Background(), orgID, sole)
	if !errors.Is(err, ErrLastOwner) {
		t.Fatalf("Remove sole Owner: want ErrLastOwner, got %v", err)
	}
	if got := rev.snapshot(); len(got) != 0 {
		t.Errorf("revoker should not be called when remove fails, got %d call(s)", len(got))
	}
}

// TestRemove_SurfacesRevokerError asserts a revoker failure
// produces ErrSessionRevocation. The member row is still gone —
// the returned error exists for alerting.
//
// Validates: Requirement 4.6 (best-effort + observable failure).
func TestRemove_SurfacesRevokerError(t *testing.T) {
	repo := newFakeMemberRepo()
	rev := &recordingRevoker{err: errors.New("redis dial timeout")}
	svc := NewMemberService(repo, rev, testHMACKey())
	orgID, accountID := uuid.New(), uuid.New()
	repo.addMember(orgID, uuid.New(), RoleOwner)
	repo.addMember(orgID, accountID, RoleMember)

	err := svc.Remove(context.Background(), orgID, accountID)
	if !errors.Is(err, ErrSessionRevocation) {
		t.Fatalf("Remove: want ErrSessionRevocation, got %v", err)
	}
	repo.mu.Lock()
	_, present := repo.members[memberPK{orgID: orgID, accountID: accountID}]
	repo.mu.Unlock()
	if present {
		t.Error("member row should still be deleted even if revocation fails")
	}
}

func TestRemove_ValidatesIDs(t *testing.T) {
	svc, _, _ := newMemberServiceForTest(t)
	ctx := context.Background()
	if err := svc.Remove(ctx, uuid.Nil, uuid.New()); !errors.Is(err, ErrOrgIDRequired) {
		t.Errorf("nil orgID: want ErrOrgIDRequired, got %v", err)
	}
	if err := svc.Remove(ctx, uuid.New(), uuid.Nil); !errors.Is(err, ErrAccountIDRequired) {
		t.Errorf("nil accountID: want ErrAccountIDRequired, got %v", err)
	}
}

// ----------------------------------------------------------------------
// Invite.Status
// ----------------------------------------------------------------------

func TestInvite_Status(t *testing.T) {
	now := time.Date(2025, 6, 1, 12, 0, 0, 0, time.UTC)
	accepted := now.Add(-time.Hour)
	revoked := now.Add(-time.Hour)
	cases := []struct {
		name string
		in   Invite
		want InviteStatus
	}{
		{"pending", Invite{ExpiresAt: now.Add(time.Hour)}, InviteStatusPending},
		{"expired", Invite{ExpiresAt: now.Add(-time.Hour)}, InviteStatusExpired},
		{"accepted", Invite{ExpiresAt: now.Add(-time.Hour), AcceptedAt: &accepted}, InviteStatusAccepted},
		{"revoked", Invite{ExpiresAt: now.Add(-time.Hour), RevokedAt: &revoked}, InviteStatusRevoked},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.in.Status(now)
			if got != tc.want {
				t.Errorf("Status: want %q, got %q", tc.want, got)
			}
		})
	}
}

// ----------------------------------------------------------------------
// Helpers
// ----------------------------------------------------------------------

// mutableClock is a test clock whose value advances explicitly, so
// tests can drive Resend / Accept across the expiry boundary
// without time.Sleep.
type mutableClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *mutableClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *mutableClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func keysOf(m map[string]uuid.UUID) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// constantTimeEqualHashes is exported test access to the package
// helper of the same name. We re-export here to avoid coupling
// tests to the implementation detail.
func TestConstantTimeEqualHashes(t *testing.T) {
	if !constantTimeEqualHashes("abc", "abc") {
		t.Error("equal hashes: expected true")
	}
	if constantTimeEqualHashes("abc", "abd") {
		t.Error("different hashes: expected false")
	}
	if constantTimeEqualHashes("abc", "abcd") {
		t.Error("different lengths: expected false")
	}
}
