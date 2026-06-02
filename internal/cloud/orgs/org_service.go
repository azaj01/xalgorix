// OrgService implements the organization-level lifecycle operations
// described in design.md → "Components and Interfaces → internal/cloud/orgs"
// and tasks.md task 3.1 ("OrgService CRUD + state transitions").
//
// Scope of this file (task 3.1 only):
//
//   - [OrgService.Create]               creates a new organization in `active` status.
//   - [OrgService.Suspend]              transitions an `active` org to `suspended`.
//   - [OrgService.RestoreFromSuspend]   transitions a `suspended` org back to `active`.
//   - [OrgService.Delete]               transitions an `active` org to `pending_delete`,
//                                       which kicks off the 30-day soft-delete grace
//                                       window enforced by task 13.4.
//
// Sibling tasks 3.2–3.5 (workspaces, members, invites, ownership transfer) are
// intentionally NOT implemented here so this file stays small and focused.
//
// The service depends on a small [Repository] interface — not on the live
// pgx pool — so unit tests can supply a fake without spinning up Postgres.
// The production binary wires [NewPgxRepository] which adapts a
// `*pgxpool.Pool` (or any [PgxQuerier]) to the same interface.
//
// Validates: Requirements 4.1, 11.8, 13.4.
package orgs

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ----------------------------------------------------------------------
// Domain types
// ----------------------------------------------------------------------

// Region is the data residency region an Organization is pinned to.
// design.md → "Decisions and Defaults → Compliance Defaults" requires
// every Organization to live in exactly one region with no cross-region
// replication.
type Region string

const (
	// RegionUSEast1 is the default region used at signup unless the
	// customer requests EU residency.
	RegionUSEast1 Region = "us-east-1"
	// RegionEUWest1 is the EU-residency region available on Enterprise.
	RegionEUWest1 Region = "eu-west-1"
)

// Plan is one of the four subscription tiers from
// design.md → "Pricing and Plans".
type Plan string

const (
	PlanFree       Plan = "free"
	PlanPro        Plan = "pro"
	PlanTeam       Plan = "team"
	PlanEnterprise Plan = "enterprise"
)

// Status is the Organization lifecycle status. Values match the CHECK
// constraint declared by migration 20250101000200 on `organizations.status`.
type Status string

const (
	// StatusActive is the only status from which an Organization can
	// dispatch scans, accept members, or be billed.
	StatusActive Status = "active"
	// StatusPastDue marks an Organization whose latest invoice failed
	// (set by the billing webhook handler in task 4.5, not task 3.1).
	StatusPastDue Status = "past_due"
	// StatusSuspended is set by the admin back office (task 11.8 /
	// 12.6) and by [OrgService.Suspend].
	StatusSuspended Status = "suspended"
	// StatusPendingDelete is the soft-delete grace window required by
	// Requirement 13.4. The hard-delete cron (task 13.4) walks rows
	// in this status and purges them after 30 days.
	StatusPendingDelete Status = "pending_delete"
)

// Org mirrors the columns of the `organizations` table the
// [OrgService] needs to surface to its callers.
type Org struct {
	ID                uuid.UUID
	Name              string
	Slug              string
	Region            Region
	Plan              Plan
	Status            Status
	OverageEnabled    bool
	SSORequiredDomain string
	Timezone          string
	CreatedAt         time.Time
}

// ----------------------------------------------------------------------
// Errors
// ----------------------------------------------------------------------

// ErrInvalidStateTransition is returned by [OrgService.Suspend],
// [OrgService.RestoreFromSuspend], and [OrgService.Delete] when the
// requested transition is not allowed from the current status. The
// allowed transitions are:
//
//	active     -> suspended       (Suspend)
//	active     -> pending_delete  (Delete)
//	suspended  -> active          (RestoreFromSuspend)
//
// Every other (from, to) pair returns ErrInvalidStateTransition.
//
// Validates: Requirements 4.1, 11.8, 13.4.
var ErrInvalidStateTransition = errors.New("orgs: invalid state transition")

// ErrOrgNotFound is returned when the supplied org id does not match an
// existing row.
var ErrOrgNotFound = errors.New("orgs: organization not found")

// ErrInvalidArgument wraps a caller-supplied input that violates a
// validation rule on Create. Use [errors.Is] against ErrInvalidArgument
// to detect.
var ErrInvalidArgument = errors.New("orgs: invalid argument")

// ----------------------------------------------------------------------
// Repository abstraction
// ----------------------------------------------------------------------

// Repository is the storage-layer dependency the [OrgService] uses to
// persist and retrieve Organization rows. It is intentionally small so
// unit tests can implement it without dragging in pgx, and so future
// repository implementations (e.g. a tx-bound repository for the
// tenancy middleware) can satisfy the same contract.
//
// Implementations MUST treat all methods as transactional units: the
// service does not currently wrap calls in a transaction itself.
type Repository interface {
	// CreateOrg inserts a new Organization row using the supplied
	// values, defaults `status` to `active`, and returns the
	// fully-populated row. Implementations should surface unique
	// constraint violations (e.g. duplicate slug) as a wrapped
	// `*pgconn.PgError` so the service can map them onto a
	// validation error.
	CreateOrg(ctx context.Context, in CreateOrgInput) (Org, error)

	// GetOrg loads the Organization with id. Returns [ErrOrgNotFound]
	// when no such row exists. The lookup MUST work even when the
	// tenancy GUC has not been set, because the service uses GetOrg
	// to read the current status before applying a transition.
	GetOrg(ctx context.Context, id uuid.UUID) (Org, error)

	// UpdateOrgStatus transitions the Organization's status from
	// `from` to `to` and returns the updated row. Implementations
	// MUST atomically check that the current status equals `from`
	// (using `UPDATE ... WHERE status = $from`) and return
	// [ErrInvalidStateTransition] when no row matches, so concurrent
	// callers cannot race past each other into an inconsistent
	// state.
	UpdateOrgStatus(ctx context.Context, id uuid.UUID, from, to Status) (Org, error)
}

// CreateOrgInput is the parameter struct for [Repository.CreateOrg].
// Using a struct keeps the interface stable as we add fields like
// `Timezone` or `SSORequiredDomain` in later phases.
type CreateOrgInput struct {
	Name   string
	Slug   string
	Region Region
	Plan   Plan
}

// ----------------------------------------------------------------------
// Service
// ----------------------------------------------------------------------

// OrgService implements the organization-lifecycle subset of the design
// document's `OrgService` type. It is intentionally stateless aside
// from its [Repository] dependency so it is safe for concurrent use.
type OrgService struct {
	repo Repository
}

// NewOrgService returns an [OrgService] backed by repo. repo MUST NOT
// be nil; the constructor panics on nil so the wiring error is caught
// at process start rather than on the first request.
func NewOrgService(repo Repository) *OrgService {
	if repo == nil {
		panic("orgs.NewOrgService: repo must not be nil")
	}
	return &OrgService{repo: repo}
}

// Create persists a new Organization in `active` status with the
// supplied name, slug, region, and plan. Validation:
//
//   - name and slug must be non-empty after trimming whitespace.
//   - region must be one of the values declared by [Region].
//   - plan must be one of the values declared by [Plan].
//
// On any validation failure Create returns a wrapped
// [ErrInvalidArgument]. On a duplicate-slug collision returned by the
// repository (Postgres error code `23505`) Create maps the error onto
// [ErrInvalidArgument] as well so callers can render a single
// "slug already in use" 4xx without sniffing pgx error types.
//
// Validates: Requirements 4.1.
func (s *OrgService) Create(ctx context.Context, name, slug string, region Region, plan Plan) (Org, error) {
	if name == "" {
		return Org{}, fmt.Errorf("%w: name is required", ErrInvalidArgument)
	}
	if slug == "" {
		return Org{}, fmt.Errorf("%w: slug is required", ErrInvalidArgument)
	}
	if !isValidRegion(region) {
		return Org{}, fmt.Errorf("%w: region %q is not allowed", ErrInvalidArgument, region)
	}
	if !isValidPlan(plan) {
		return Org{}, fmt.Errorf("%w: plan %q is not allowed", ErrInvalidArgument, plan)
	}

	org, err := s.repo.CreateOrg(ctx, CreateOrgInput{
		Name:   name,
		Slug:   slug,
		Region: region,
		Plan:   plan,
	})
	if err != nil {
		// Map unique-constraint violations (e.g. duplicate slug)
		// onto ErrInvalidArgument so HTTP handlers can render a
		// 409 / 422 without importing pgx error types.
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return Org{}, fmt.Errorf("%w: slug %q is already in use", ErrInvalidArgument, slug)
		}
		return Org{}, fmt.Errorf("orgs: create: %w", err)
	}
	return org, nil
}

// Get returns the Organization identified by orgID. The lookup goes
// through the repository's [Repository.GetOrg], so callers receive
// [ErrOrgNotFound] when no row matches and [ErrInvalidArgument] when
// orgID is the zero UUID. Get does NOT require a tenant GUC to be
// stamped on the connection because the admin / internal endpoints
// that consume it are explicitly cross-tenant.
//
// Validates: Requirements 4.1.
func (s *OrgService) Get(ctx context.Context, orgID uuid.UUID) (Org, error) {
	if orgID == uuid.Nil {
		return Org{}, fmt.Errorf("%w: org id is required", ErrInvalidArgument)
	}
	return s.repo.GetOrg(ctx, orgID)
}

// Suspend transitions the Organization with id from `active` to
// `suspended`. The reason argument is currently informational; later
// tasks (12.6 admin back office, 13.5 audit logs) will persist it as
// part of the `support_org_suspended` audit event.
//
// Returns [ErrInvalidStateTransition] when the Organization is not in
// the `active` status.
//
// Validates: Requirements 11.8, 4.1.
func (s *OrgService) Suspend(ctx context.Context, orgID uuid.UUID, reason string) (Org, error) {
	_ = reason // reserved for the audit-log integration in task 12.6
	return s.transition(ctx, orgID, StatusActive, StatusSuspended)
}

// RestoreFromSuspend transitions the Organization with id from
// `suspended` back to `active`. Returns [ErrInvalidStateTransition]
// when the Organization is not in the `suspended` status.
//
// Validates: Requirements 11.8, 4.1.
func (s *OrgService) RestoreFromSuspend(ctx context.Context, orgID uuid.UUID) (Org, error) {
	return s.transition(ctx, orgID, StatusSuspended, StatusActive)
}

// Delete moves the Organization with id into `pending_delete`. The row
// is NOT removed; the hard-delete cron added by task 13.4 will purge
// rows in `pending_delete` after the 30-day grace window required by
// Requirement 13.4.
//
// Returns [ErrInvalidStateTransition] when the Organization is not in
// the `active` status.
//
// Validates: Requirements 13.4.
func (s *OrgService) Delete(ctx context.Context, orgID uuid.UUID) (Org, error) {
	return s.transition(ctx, orgID, StatusActive, StatusPendingDelete)
}

// transition is the shared helper behind every status-changing service
// method. It performs the optimistic state-machine check at the
// repository layer, so two concurrent callers cannot both observe
// `active` and both transition the row.
func (s *OrgService) transition(ctx context.Context, orgID uuid.UUID, from, to Status) (Org, error) {
	if orgID == uuid.Nil {
		return Org{}, fmt.Errorf("%w: org id is required", ErrInvalidArgument)
	}
	org, err := s.repo.UpdateOrgStatus(ctx, orgID, from, to)
	if err != nil {
		return Org{}, err
	}
	return org, nil
}

// ----------------------------------------------------------------------
// Validation helpers
// ----------------------------------------------------------------------

func isValidRegion(r Region) bool {
	switch r {
	case RegionUSEast1, RegionEUWest1:
		return true
	default:
		return false
	}
}

func isValidPlan(p Plan) bool {
	switch p {
	case PlanFree, PlanPro, PlanTeam, PlanEnterprise:
		return true
	default:
		return false
	}
}

// ----------------------------------------------------------------------
// pgx repository
// ----------------------------------------------------------------------

// PgxQuerier is the subset of pgx the [PgxRepository] needs. Both
// `*pgxpool.Pool` and `pgx.Tx` satisfy it, so the same repository can
// run inside the tenancy middleware's transaction or against the raw
// pool when no tenant is bound.
type PgxQuerier interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// PgxRepository adapts a [PgxQuerier] to the [Repository] interface.
// It is the production wiring used by `cmd/xalgorix-cloud`; tests use
// the in-memory fake in `org_service_test.go` instead.
type PgxRepository struct {
	q PgxQuerier
}

// NewPgxRepository builds a [PgxRepository] backed by pool. pool MUST
// NOT be nil.
func NewPgxRepository(pool *pgxpool.Pool) *PgxRepository {
	if pool == nil {
		panic("orgs.NewPgxRepository: pool must not be nil")
	}
	return &PgxRepository{q: pool}
}

// NewPgxRepositoryFromQuerier builds a [PgxRepository] backed by an
// arbitrary [PgxQuerier]. The tenancy middleware uses this constructor
// to bind the repository to its per-request transaction so RLS-scoped
// reads pick up the `app.organization_id` GUC.
func NewPgxRepositoryFromQuerier(q PgxQuerier) *PgxRepository {
	if q == nil {
		panic("orgs.NewPgxRepositoryFromQuerier: querier must not be nil")
	}
	return &PgxRepository{q: q}
}

// CreateOrg implements [Repository.CreateOrg].
func (r *PgxRepository) CreateOrg(ctx context.Context, in CreateOrgInput) (Org, error) {
	const sql = `
		INSERT INTO organizations (name, slug, region, plan)
		VALUES ($1, $2, $3, $4)
		RETURNING id, name, slug, region, plan, status,
		          overage_enabled, COALESCE(sso_required_domain, ''),
		          timezone, created_at`
	row := r.q.QueryRow(ctx, sql, in.Name, in.Slug, string(in.Region), string(in.Plan))
	return scanOrg(row)
}

// GetOrg implements [Repository.GetOrg].
func (r *PgxRepository) GetOrg(ctx context.Context, id uuid.UUID) (Org, error) {
	const sql = `
		SELECT id, name, slug, region, plan, status,
		       overage_enabled, COALESCE(sso_required_domain, ''),
		       timezone, created_at
		FROM organizations
		WHERE id = $1`
	row := r.q.QueryRow(ctx, sql, id)
	org, err := scanOrg(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return Org{}, ErrOrgNotFound
	}
	return org, err
}

// UpdateOrgStatus implements [Repository.UpdateOrgStatus] using an
// optimistic `WHERE status = $from` filter so concurrent callers
// cannot race past each other.
func (r *PgxRepository) UpdateOrgStatus(ctx context.Context, id uuid.UUID, from, to Status) (Org, error) {
	const sql = `
		UPDATE organizations
		SET status = $3
		WHERE id = $1 AND status = $2
		RETURNING id, name, slug, region, plan, status,
		          overage_enabled, COALESCE(sso_required_domain, ''),
		          timezone, created_at`
	row := r.q.QueryRow(ctx, sql, id, string(from), string(to))
	org, err := scanOrg(row)
	if errors.Is(err, pgx.ErrNoRows) {
		// Either the org does not exist or it is not in the
		// expected `from` status. Resolve the ambiguity with a
		// follow-up read so callers can distinguish a missing
		// row from a forbidden transition.
		got, getErr := r.GetOrg(ctx, id)
		if getErr != nil {
			return Org{}, getErr
		}
		return Org{}, fmt.Errorf("%w: %s -> %s rejected, current status is %s",
			ErrInvalidStateTransition, from, to, got.Status)
	}
	return org, err
}

// scanOrg pulls a row into an [Org] using the canonical column order
// shared by every SELECT in this file.
func scanOrg(row pgx.Row) (Org, error) {
	var (
		o      Org
		region string
		plan   string
		status string
	)
	if err := row.Scan(
		&o.ID,
		&o.Name,
		&o.Slug,
		&region,
		&plan,
		&status,
		&o.OverageEnabled,
		&o.SSORequiredDomain,
		&o.Timezone,
		&o.CreatedAt,
	); err != nil {
		return Org{}, err
	}
	o.Region = Region(region)
	o.Plan = Plan(plan)
	o.Status = Status(status)
	return o, nil
}
