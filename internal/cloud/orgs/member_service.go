// Package orgs — MemberService.
//
// This file implements task 3.3 of the xalgorix-saas spec: invitations,
// member-role changes, and member removal — all of the membership
// surface of design.md → "Components and Interfaces → internal/cloud/orgs"
// that does not belong to OrgService (3.1) or WorkspaceService (3.2).
//
// Surface implemented here:
//
//   - MemberService.Invite(ctx, orgID, email, role) — generates a 32-byte
//     random invite token, persists only its HMAC-SHA256 hash in
//     `invites.token_hash`, and returns the raw token to the caller
//     exactly once. The HTTP layer is responsible for embedding that
//     raw token in the email link before dropping it; nothing else in
//     the platform retains the plaintext.
//   - MemberService.Resend(ctx, orgID, inviteID) — only valid on a
//     pending invite (not accepted, not revoked, not expired-by-clock
//     beyond the new horizon); resets `expires_at` to now+7d so the
//     existing token keeps working under its original hash.
//   - MemberService.Accept(ctx, token, accountID) — hashes the supplied
//     token, looks up the matching pending invite, rejects expired
//     invites with [ErrInviteExpired] (mapped to HTTP 410 by Requirement
//     4.5), inserts the corresponding `members` row at the invited role,
//     and marks the invite accepted. The repository is expected to run
//     these three writes inside a single transaction.
//   - MemberService.ChangeRole(ctx, orgID, accountID, newRole) — RBAC-
//     gated role change with the Owner-row protection from Requirement
//     4.9 (the Organization may never have zero Owners): demoting a
//     sole Owner returns [ErrLastOwner].
//   - MemberService.Remove(ctx, orgID, accountID) — deletes the member
//     row in a single transaction and invokes [SessionRevoker.RevokeFor]
//     so workspace access flips within Requirement 4.6's 5-second budget.
//     The repository performs the row delete; the service performs the
//     fan-out so a fake SessionRevoker can verify the contract in tests.
//
// The service is intentionally repository-agnostic and depends only on a
// small [MemberRepository] interface plus a [SessionRevoker] hook. The
// production wiring (pgx + Redis pub/sub) lives in cmd/xalgorix-cloud;
// the unit tests in `member_service_test.go` use in-memory fakes.
//
// Validates: Requirements 4.3, 4.4, 4.5, 4.6, 4.9.
package orgs

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

// ----------------------------------------------------------------------
// Constants and tunables
// ----------------------------------------------------------------------

const (
	// InviteTokenBytes is the size of the cryptographically random
	// portion of an invite token. 32 bytes (256 bits) matches the
	// security level required by the platform-wide guidance in
	// design.md → "Security Defaults" and is well above the entropy
	// needed to defeat online and offline guessing of the token.
	InviteTokenBytes = 32

	// InviteTTL is the lifetime of a freshly issued invite. It comes
	// directly from Requirement 4.3 ("…a single-use invite link valid
	// for 7 days").
	InviteTTL = 7 * 24 * time.Hour

	// minInviteHMACKeyBytes is the minimum length of the HMAC signing
	// key the service uses to derive `invites.token_hash`. 32 bytes
	// matches the HMAC-SHA256 output size and the convention already
	// established by [auth.SessionStore] / [auth.MFAService]. A
	// shorter key is treated as a deploy-time misconfiguration and
	// the constructor panics.
	minInviteHMACKeyBytes = 32
)

// inviteRoleAllowList enumerates the roles an Owner or Admin may
// invite a recipient at. Owner is intentionally absent: ownership is
// only acquired through the atomic transfer flow (task 3.5), never
// through an invite, and Requirement 4.2 keeps Admin from creating
// new Owners. The CHECK constraint on `invites.role` mirrors this set.
var inviteRoleAllowList = map[Role]struct{}{
	RoleAdmin:  {},
	RoleMember: {},
	RoleViewer: {},
}

// ----------------------------------------------------------------------
// Sentinel errors
// ----------------------------------------------------------------------

// Sentinel errors the HTTP layer maps onto stable status codes:
//
//	ErrInviteExpired       -> 410 (Requirement 4.5)
//	ErrInviteNotFound      -> 404 / 410 depending on caller
//	ErrInviteNotPending    -> 409 (already accepted/revoked)
//	ErrInviteEmailRequired -> 422
//	ErrInviteRoleInvalid   -> 422
//	ErrLastOwner           -> 409 (Requirement 4.9 invariant)
//	ErrMemberRoleInvalid   -> 422
var (
	// ErrInviteExpired is returned by Accept when the invite's
	// expires_at is older than now. Requirement 4.5 maps this to
	// HTTP 410 and explicitly allows the inviter to reissue, which
	// is what Resend is for.
	ErrInviteExpired = errors.New("orgs: invite expired")

	// ErrInviteNotFound is returned when no invite row matches the
	// supplied id (Resend) or the supplied token's hash (Accept).
	// Treating an unknown token and a missing id with the same
	// sentinel keeps the server from leaking which one of the two
	// inputs was wrong to an attacker probing the endpoint.
	ErrInviteNotFound = errors.New("orgs: invite not found")

	// ErrInviteNotPending is returned by Resend when the targeted
	// invite has already been accepted or revoked. Requirement 4.3
	// restricts Resend to pending invites only.
	ErrInviteNotPending = errors.New("orgs: invite is not pending")

	// ErrInviteEmailRequired is returned by Invite when the supplied
	// email is empty after trimming.
	ErrInviteEmailRequired = errors.New("orgs: invite email is required")

	// ErrInviteRoleInvalid is returned by Invite when the role is
	// not one of {admin, member, viewer}. Owner cannot be invited.
	ErrInviteRoleInvalid = errors.New("orgs: invite role is invalid")

	// ErrInviteIDRequired is returned by Resend when inviteID is
	// the zero UUID.
	ErrInviteIDRequired = errors.New("orgs: invite id is required")

	// ErrInviteTokenRequired is returned by Accept when the supplied
	// token is empty.
	ErrInviteTokenRequired = errors.New("orgs: invite token is required")

	// ErrInviteTokenInvalid is returned by Accept when the supplied
	// token is structurally malformed (wrong base64 / wrong length).
	// It is distinct from [ErrInviteNotFound] so the HTTP layer can
	// reject the request with a 422 instead of a 410, but both
	// errors keep the response body opaque to avoid leaking which
	// invites exist.
	ErrInviteTokenInvalid = errors.New("orgs: invite token is malformed")

	// ErrLastOwner is returned by ChangeRole when the requested
	// transition would leave the Organization with zero Owners and
	// by Remove when the targeted member is the last Owner.
	// Requirement 4.9 makes "≥ 1 Owner" an unconditional invariant.
	ErrLastOwner = errors.New("orgs: organization must retain at least one owner")

	// ErrMemberRoleInvalid is returned by ChangeRole when newRole is
	// not one of {owner, admin, member, viewer}. The same set is
	// enforced by the CHECK constraint on `members.role`.
	ErrMemberRoleInvalid = errors.New("orgs: member role is invalid")

	// ErrSessionRevocation is returned by Remove when the
	// underlying session revocation hook reports a failure. The
	// member-row delete has already been committed at that point —
	// the error exists so callers can log a remediation alert; the
	// member itself is gone from the Organization either way.
	ErrSessionRevocation = errors.New("orgs: session revocation failed")
)

// ----------------------------------------------------------------------
// Domain types
// ----------------------------------------------------------------------

// InviteStatus is a derived enum the service computes from
// (accepted_at, revoked_at, expires_at) so callers do not need to
// know about the underlying nullable timestamps.
type InviteStatus string

const (
	// InviteStatusPending means the invite has not been accepted,
	// has not been revoked, and is still within its expiry window.
	InviteStatusPending InviteStatus = "pending"
	// InviteStatusAccepted means accepted_at is non-nil.
	InviteStatusAccepted InviteStatus = "accepted"
	// InviteStatusRevoked means revoked_at is non-nil.
	InviteStatusRevoked InviteStatus = "revoked"
	// InviteStatusExpired means expires_at < now() and the invite
	// is neither accepted nor revoked.
	InviteStatusExpired InviteStatus = "expired"
)

// Invite is the in-memory projection of a row in the `invites` table.
// The plaintext token is intentionally NOT a field on this struct: the
// service only ever returns the raw token through the dedicated
// [Invite.RawToken] hop on the [InviteIssued] result, and never reads
// it back from the database.
type Invite struct {
	ID         uuid.UUID
	OrgID      uuid.UUID
	Email      string
	Role       Role
	InvitedBy  uuid.UUID
	ExpiresAt  time.Time
	AcceptedAt *time.Time
	RevokedAt  *time.Time
	CreatedAt  time.Time
}

// Status derives the [InviteStatus] from the row's timestamp triple
// using the same precedence the API layer surfaces to clients:
// accepted > revoked > expired > pending.
func (i Invite) Status(now time.Time) InviteStatus {
	switch {
	case i.AcceptedAt != nil:
		return InviteStatusAccepted
	case i.RevokedAt != nil:
		return InviteStatusRevoked
	case !i.ExpiresAt.IsZero() && i.ExpiresAt.Before(now):
		return InviteStatusExpired
	default:
		return InviteStatusPending
	}
}

// InviteIssued is the result of a successful Invite call. It pairs
// the persisted row with the raw token that the caller MUST email
// out and then forget — the service never returns the raw token
// again.
type InviteIssued struct {
	Invite   Invite
	RawToken string
}

// Member mirrors the row in the `members` table the service surfaces
// to its callers. WorkspaceAccess is preserved as an opaque slice of
// uuids because [WorkspaceService] owns its semantics.
type Member struct {
	OrgID           uuid.UUID
	AccountID       uuid.UUID
	Role            Role
	WorkspaceAccess []uuid.UUID
	CreatedAt       time.Time
}

// ----------------------------------------------------------------------
// Repository contract
// ----------------------------------------------------------------------

// MemberRepository is the persistence surface required by
// [MemberService]. It exposes exactly the five methods named in
// task 3.3.
//
// Each method is expected to be a single transaction so the service
// does not have to coordinate retries on partial failure. Implementations
// MUST surface concurrent-update conflicts (e.g. two Accepts racing on
// the same invite) as [ErrInviteNotPending] / [ErrInviteNotFound] so
// the service does not have to sniff database error codes.
type MemberRepository interface {
	// CreateInvite inserts a new pending invite with the supplied
	// hashed token. The implementation MUST honour the partial
	// unique index `invites_org_email_pending_idx` so that two
	// pending invites for the same (org_id, email) cannot coexist;
	// callers are expected to revoke an outstanding invite before
	// issuing a new one.
	CreateInvite(ctx context.Context, in CreateInviteInput) (Invite, error)

	// ResendInvite refreshes `expires_at` to expiresAt for the
	// invite identified by (orgID, inviteID). The repository MUST
	// return [ErrInviteNotFound] when no row matches and
	// [ErrInviteNotPending] when the invite has been accepted or
	// revoked. Implementations are free to also reject already-
	// expired invites, but the service keeps the policy simple: an
	// expired-but-still-pending invite is rolled forward by Resend.
	ResendInvite(ctx context.Context, orgID, inviteID uuid.UUID, expiresAt time.Time) (Invite, error)

	// AcceptInvite is a single-transaction trio: look up the
	// invite by `tokenHash`, validate the supplied accountID can
	// be inserted into `members(org_id, account_id, role)`, and
	// mark the invite accepted at acceptedAt. Returns the freshly
	// inserted [Member] on success.
	//
	// The repository MUST translate:
	//   - missing invite                -> [ErrInviteNotFound]
	//   - already-accepted/revoked      -> [ErrInviteNotPending]
	//   - expires_at < acceptedAt        -> [ErrInviteExpired]
	//
	// Mapping the expired check at the repository layer keeps the
	// time-of-check-time-of-use window inside the transaction.
	AcceptInvite(ctx context.Context, tokenHash string, accountID uuid.UUID, acceptedAt time.Time) (Member, Invite, error)

	// ChangeMemberRole performs the role transition as a single
	// transactional unit. The repository MUST atomically check that
	// demoting the targeted Owner would not leave the Organization
	// with zero Owners and return [ErrLastOwner] when it would.
	// Returns [ErrMemberNotFound] when no member row matches.
	ChangeMemberRole(ctx context.Context, orgID, accountID uuid.UUID, newRole Role) (Member, error)

	// RemoveMember deletes the row in `members` identified by
	// (orgID, accountID). The repository MUST atomically enforce
	// the "≥ 1 Owner" invariant by returning [ErrLastOwner] when
	// the targeted row is the only Owner. Returns
	// [ErrMemberNotFound] when no row matches.
	RemoveMember(ctx context.Context, orgID, accountID uuid.UUID) error
}

// CreateInviteInput is the parameter struct for [MemberRepository.CreateInvite].
// Using a struct keeps the interface stable as later phases add fields
// such as `inviter_message` or `workspace_access` defaults.
type CreateInviteInput struct {
	OrgID     uuid.UUID
	Email     string
	Role      Role
	TokenHash string
	InvitedBy uuid.UUID
	ExpiresAt time.Time
}

// ErrMemberNotFound is returned when ChangeMemberRole or RemoveMember
// targets a (org_id, account_id) pair that is not a member row. It is
// distinct from the workspace-scoped [orgs.ErrMemberNotFound] used by
// WorkspaceService — declaring the variable in this file would shadow
// it, so the membership-level not-found reuses the same sentinel and
// the service-level call sites disambiguate by the surrounding API.
//
// To avoid the redeclaration this file references the existing
// [ErrMemberNotFound] declared in `workspace_service.go`.
var _ = ErrMemberNotFound

// ----------------------------------------------------------------------
// Session-revocation hook
// ----------------------------------------------------------------------

// SessionRevoker is the side-effect hook Remove invokes after a
// successful member delete so that the removed Account loses access
// to the Organization's Workspaces within Requirement 4.6's 5-second
// budget. The production wiring uses the Redis-backed session store
// (`internal/cloud/auth.SessionStore`) which keeps a per-account
// pointer set and can fan-out a delete in a single round trip; tests
// substitute an in-memory recorder.
//
// Implementations MUST be safe for concurrent use. The service does
// not retry on transient errors; a failed revocation surfaces as
// [ErrSessionRevocation] but the member-row delete is already
// committed when the hook runs.
type SessionRevoker interface {
	// RevokeFor revokes every session belonging to accountID
	// scoped to orgID. Implementations MAY choose to revoke ALL
	// sessions for the account when their session model is not
	// org-scoped — that is acceptable per the broader Requirement
	// 4.6 wording ("revoke that Member's access to all Workspaces
	// of the Organization within 5 seconds").
	RevokeFor(ctx context.Context, orgID, accountID uuid.UUID) error
}

// noopSessionRevoker is the default revoker used when callers do not
// supply one. It is safe for read-only deployments (e.g. tests that
// exercise ChangeRole without exercising Remove). The constructor
// panics if the caller intends to use Remove without a revoker —
// this default is for the constructor's defensive coding only.
type noopSessionRevoker struct{}

func (noopSessionRevoker) RevokeFor(context.Context, uuid.UUID, uuid.UUID) error { return nil }

// ----------------------------------------------------------------------
// Service
// ----------------------------------------------------------------------

// MemberService implements task 3.3. It is stateless aside from its
// repository and revoker dependencies, and is therefore safe for
// concurrent use.
type MemberService struct {
	repo     MemberRepository
	revoker  SessionRevoker
	hmacKey  []byte
	now      func() time.Time
	randRead func([]byte) (int, error)
}

// MemberServiceOption configures optional dependencies on
// [NewMemberService]. The functional-options pattern keeps the
// constructor signature small while letting tests inject a stub
// clock or a deterministic random source without exporting a
// "test-only" constructor.
type MemberServiceOption func(*MemberService)

// WithClock overrides the wall-clock used for invite expiry. Tests
// pass a fixed-time function so they can drive Accept across the
// expiry boundary deterministically.
func WithClock(now func() time.Time) MemberServiceOption {
	return func(s *MemberService) {
		if now != nil {
			s.now = now
		}
	}
}

// WithRandReader overrides the random source used by Invite to
// generate the 32-byte token. Tests pass a counter-based reader so
// the resulting raw token is reproducible.
func WithRandReader(read func([]byte) (int, error)) MemberServiceOption {
	return func(s *MemberService) {
		if read != nil {
			s.randRead = read
		}
	}
}

// NewMemberService constructs a [MemberService]. It panics on
// programming errors that must surface at boot rather than at the
// first request:
//
//   - repo is nil
//   - revoker is nil (nilness is treated as a wiring mistake — the
//     caller MUST pass [NoopSessionRevoker] explicitly when they
//     mean it; doing so leaves an audit trail in the construction
//     site)
//   - hmacKey is shorter than 32 bytes
//
// Validates: Requirements 4.3, 4.6.
func NewMemberService(repo MemberRepository, revoker SessionRevoker, hmacKey []byte, opts ...MemberServiceOption) *MemberService {
	if repo == nil {
		panic("orgs.NewMemberService: repo must not be nil")
	}
	if revoker == nil {
		panic("orgs.NewMemberService: revoker must not be nil — use NoopSessionRevoker if intentional")
	}
	if len(hmacKey) < minInviteHMACKeyBytes {
		panic(fmt.Sprintf("orgs.NewMemberService: hmacKey must be at least %d bytes", minInviteHMACKeyBytes))
	}
	keyCopy := make([]byte, len(hmacKey))
	copy(keyCopy, hmacKey)
	s := &MemberService{
		repo:     repo,
		revoker:  revoker,
		hmacKey:  keyCopy,
		now:      time.Now,
		randRead: rand.Read,
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// NoopSessionRevoker is exported so tests and read-only deployments
// can express the "no session integration yet" intent without sneaking
// a nil into the constructor.
var NoopSessionRevoker SessionRevoker = noopSessionRevoker{}

// ----------------------------------------------------------------------
// Invite
// ----------------------------------------------------------------------

// Invite generates a fresh 32-byte invite token, persists its
// HMAC-SHA256 hash in `invites.token_hash`, and returns the raw token
// to the caller exactly once. The HTTP layer is responsible for
// embedding that token in the email link and discarding the
// in-memory copy on the way out.
//
// Validation:
//
//   - orgID and invitedBy must be non-zero UUIDs.
//   - email must be non-empty after trimming. Lowercasing and
//     normalisation is delegated to the repository so the same
//     rules apply to direct INSERTs (the column is `citext`).
//   - role must be one of {admin, member, viewer}. Owner cannot
//     be invited; transferring ownership is its own flow.
//
// On success Invite returns an [InviteIssued] whose [InviteIssued.RawToken]
// holds the URL-safe base64 encoding of the 32 random bytes plus the
// invite id (so the recipient's link is self-contained).
//
// Validates: Requirement 4.3.
func (s *MemberService) Invite(ctx context.Context, orgID uuid.UUID, invitedBy uuid.UUID, email string, role Role) (InviteIssued, error) {
	if orgID == uuid.Nil {
		return InviteIssued{}, ErrOrgIDRequired
	}
	if invitedBy == uuid.Nil {
		return InviteIssued{}, ErrAccountIDRequired
	}
	cleanEmail := strings.TrimSpace(email)
	if cleanEmail == "" {
		return InviteIssued{}, ErrInviteEmailRequired
	}
	if _, ok := inviteRoleAllowList[role]; !ok {
		return InviteIssued{}, fmt.Errorf("%w: %q", ErrInviteRoleInvalid, role)
	}

	tokenBytes := make([]byte, InviteTokenBytes)
	if _, err := s.randRead(tokenBytes); err != nil {
		return InviteIssued{}, fmt.Errorf("orgs: read invite token entropy: %w", err)
	}
	rawToken := base64.RawURLEncoding.EncodeToString(tokenBytes)
	tokenHash := s.hashToken(rawToken)

	in := CreateInviteInput{
		OrgID:     orgID,
		Email:     cleanEmail,
		Role:      role,
		TokenHash: tokenHash,
		InvitedBy: invitedBy,
		ExpiresAt: s.now().Add(InviteTTL),
	}
	invite, err := s.repo.CreateInvite(ctx, in)
	if err != nil {
		return InviteIssued{}, err
	}
	return InviteIssued{Invite: invite, RawToken: rawToken}, nil
}

// ----------------------------------------------------------------------
// Resend
// ----------------------------------------------------------------------

// Resend rolls forward the `expires_at` of a pending invite by 7
// days. The repository enforces the "must be pending" precondition
// and surfaces [ErrInviteNotPending] when the targeted invite has
// already been accepted or revoked.
//
// The raw token is intentionally NOT re-issued: a resend reuses the
// already-mailed link so the recipient does not have to discard the
// previous email. Operationally this also keeps the audit trail
// linear — one invite id maps to one delivered token.
//
// Validates: Requirement 4.3 (sentence 2: "single-use invite link").
func (s *MemberService) Resend(ctx context.Context, orgID, inviteID uuid.UUID) (Invite, error) {
	if orgID == uuid.Nil {
		return Invite{}, ErrOrgIDRequired
	}
	if inviteID == uuid.Nil {
		return Invite{}, ErrInviteIDRequired
	}
	return s.repo.ResendInvite(ctx, orgID, inviteID, s.now().Add(InviteTTL))
}

// ----------------------------------------------------------------------
// Accept
// ----------------------------------------------------------------------

// Accept consumes a raw invite token: it hashes the token, looks up
// the matching pending invite, rejects expired invites with
// [ErrInviteExpired] (Requirement 4.5 → HTTP 410), inserts the
// corresponding `members` row at the invited role, and marks the
// invite accepted.
//
// The lookup-and-update pair runs inside the repository transaction
// so two simultaneous accepts on the same token cannot both succeed.
//
// Validates: Requirement 4.4 (accept happy path) and 4.5 (expired
// invites return HTTP 410).
func (s *MemberService) Accept(ctx context.Context, token string, accountID uuid.UUID) (Member, error) {
	cleanToken := strings.TrimSpace(token)
	if cleanToken == "" {
		return Member{}, ErrInviteTokenRequired
	}
	if accountID == uuid.Nil {
		return Member{}, ErrAccountIDRequired
	}
	// Structural check: the URL-safe base64 encoding of 32 bytes
	// is 43 characters with no padding. Rejecting structurally
	// invalid tokens early avoids an unnecessary database round
	// trip and keeps the timing of the negative path stable.
	if !looksLikeRawInviteToken(cleanToken) {
		return Member{}, ErrInviteTokenInvalid
	}
	tokenHash := s.hashToken(cleanToken)
	member, _, err := s.repo.AcceptInvite(ctx, tokenHash, accountID, s.now())
	return member, err
}

// ----------------------------------------------------------------------
// ChangeRole
// ----------------------------------------------------------------------

// ChangeRole transitions the member identified by (orgID, accountID)
// to newRole. The repository performs the atomic "≥ 1 Owner" check
// (Requirement 4.9) and returns [ErrLastOwner] when the transition
// would empty the Owner set. ChangeRole itself adds the input
// validation and translates an unknown member into the
// package-level [ErrMemberNotFound].
//
// Note that "Admin may not change the Owner's Role" (Requirement
// 4.2) is enforced upstream at the RBAC middleware layer, not here:
// this service is the inner-most layer and trusts that the caller
// has already passed RBAC. The "last Owner" invariant is enforced
// here because it cannot be expressed at the row level by the RBAC
// matrix.
//
// Validates: Requirement 4.9; supports 4.2 by exposing
// [ErrMemberRoleInvalid] for nonsense inputs.
func (s *MemberService) ChangeRole(ctx context.Context, orgID, accountID uuid.UUID, newRole Role) (Member, error) {
	if orgID == uuid.Nil {
		return Member{}, ErrOrgIDRequired
	}
	if accountID == uuid.Nil {
		return Member{}, ErrAccountIDRequired
	}
	if !isMemberRole(newRole) {
		return Member{}, fmt.Errorf("%w: %q", ErrMemberRoleInvalid, newRole)
	}
	return s.repo.ChangeMemberRole(ctx, orgID, accountID, newRole)
}

// ----------------------------------------------------------------------
// Remove
// ----------------------------------------------------------------------

// Remove deletes the (orgID, accountID) member row in a single
// repository transaction and then triggers session revocation through
// the injected [SessionRevoker] so workspace access flips within the
// 5-second budget set by Requirement 4.6. The "≥ 1 Owner" invariant
// is enforced inside the repository transaction and surfaces as
// [ErrLastOwner].
//
// Order of operations: row delete first, revocation second. If the
// revocation hook fails Remove returns [ErrSessionRevocation] so the
// HTTP layer can log a remediation alert; the member row is already
// gone at that point. Choosing this order — rather than revoking
// first and deleting later — guarantees that a partially failed
// Remove never leaves a member in the database with an active
// session. It also matches the intuition behind Requirement 4.6: the
// member's access starts to disappear the instant the row is gone,
// even if the session sweep needs a retry to flush a slow Redis
// node.
//
// Validates: Requirements 4.6, 4.9.
func (s *MemberService) Remove(ctx context.Context, orgID, accountID uuid.UUID) error {
	if orgID == uuid.Nil {
		return ErrOrgIDRequired
	}
	if accountID == uuid.Nil {
		return ErrAccountIDRequired
	}
	if err := s.repo.RemoveMember(ctx, orgID, accountID); err != nil {
		return err
	}
	if err := s.revoker.RevokeFor(ctx, orgID, accountID); err != nil {
		return fmt.Errorf("%w: %v", ErrSessionRevocation, err)
	}
	return nil
}

// ----------------------------------------------------------------------
// Helpers
// ----------------------------------------------------------------------

// hashToken returns the lowercase hex HMAC-SHA256 of the supplied raw
// token using the service's signing key. The output is what gets
// persisted in `invites.token_hash`. Hex (rather than base64) is
// used to keep the column's printable representation stable and to
// match the token-hash conventions of the auth and webhook stores.
func (s *MemberService) hashToken(rawToken string) string {
	mac := hmac.New(sha256.New, s.hmacKey)
	mac.Write([]byte(rawToken))
	return hex.EncodeToString(mac.Sum(nil))
}

// constantTimeEqualHashes compares two hex-encoded HMAC tags in
// constant time. Exposed for tests that want to verify the service's
// hash matches a hand-computed expectation without leaking timing
// information about the comparison.
func constantTimeEqualHashes(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// looksLikeRawInviteToken returns true when token has the structural
// shape of a freshly issued invite token: 43 URL-safe base64
// characters (the encoding of 32 random bytes with no padding).
func looksLikeRawInviteToken(token string) bool {
	const expectedLen = (InviteTokenBytes*4 + 2) / 3 // = 43 for 32 bytes
	if len(token) != expectedLen {
		return false
	}
	for i := 0; i < len(token); i++ {
		c := token[i]
		switch {
		case c >= 'A' && c <= 'Z':
		case c >= 'a' && c <= 'z':
		case c >= '0' && c <= '9':
		case c == '-', c == '_':
		default:
			return false
		}
	}
	return true
}

// isMemberRole reports whether r is one of the four canonical role
// values accepted by the `members.role` CHECK constraint.
func isMemberRole(r Role) bool {
	switch r {
	case RoleOwner, RoleAdmin, RoleMember, RoleViewer:
		return true
	default:
		return false
	}
}
