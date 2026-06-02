// Signed S3 URL issuer for branded report downloads. This file
// implements task 6.4 of the xalgorix-saas spec — "Signed S3 URL with
// TTL ≤ 15 minutes".
//
// The [Presigner] looks up the persisted `reports` row, verifies the
// calling principal's tenant matches the row's `(org_id, workspace_id)`
// pair (using the [tenancy] context populated by `WithTenant`), and
// hands the canonical `s3_key` to the tenant-scoped
// [storage.Storage.Presign] which issues a SSE-KMS signed GET URL with
// a TTL clamped at 15 minutes per design.md "Property 12: Report URL
// TTL ≤ 15 minutes" and Requirements 6.6 and 20.7.
//
// On every successful presign the [Presigner] also emits a
// `report_downloaded` audit event so the Audit Log carries a permanent
// record of who downloaded which report. The emission is intentionally
// non-blocking: an audit failure is logged via zerolog and the URL is
// still returned to the caller. This matches the task brief
// ("don't block on audit failure — log and continue") and prevents an
// audit outage from breaking a Member's report download.
//
// Validates: Requirements 6.6, 20.7.
package reports

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog/log"

	"github.com/xalgord/xalgorix/v4/internal/cloud/storage"
	"github.com/xalgord/xalgorix/v4/internal/cloud/tenancy"
)

// MaxPresignTTL caps every report download URL at 15 minutes. The
// limit mirrors [storage.MaxPresignTTL]; we re-declare it here so the
// reports package documents the contract independently of the storage
// wrapper. [Presigner.Presign] clamps any caller-configured TTL down
// to this value before dispatching to storage.
//
// Validates: Requirements 6.6, 20.7.
const MaxPresignTTL = 15 * time.Minute

// AuditEventReportDownloaded is the canonical `event_type` emitted on
// every successful presign. The Audit Log viewer (task 13.1) renders
// this row alongside the supplied `report_id` so operators can answer
// "who downloaded report X" without inspecting S3 access logs.
const AuditEventReportDownloaded = "report_downloaded"

// ErrReportNotFound is returned by [Presigner.Presign] when the
// configured [ReportRepo] reports the row does not exist. The
// presigner wraps the repository's error in this sentinel so callers
// can `errors.Is(err, ErrReportNotFound)` without coupling to the
// pgx-specific `pgx.ErrNoRows`.
var ErrReportNotFound = errors.New("reports: not found")

// ReportRow is the projection of the persisted `reports` row consumed
// by [Presigner.Presign]. The shape carries the canonical S3 key plus
// the tenancy-scoping pair that the presigner uses to enforce the
// request principal's `(org_id, workspace_id)` matches the row.
//
// Validates: Requirements 6.6, 20.7.
type ReportRow struct {
	ID          uuid.UUID
	OrgID       string
	WorkspaceID string
	S3Key       string
}

// ReportRepo is the persistence seam the [Presigner] depends on.
// Production wires a pgx-backed implementation that issues a single
// `SELECT id, org_id, workspace_id, s3_key FROM reports WHERE id = $1`
// inside the active tenancy transaction; tests inject an in-memory
// fake. Implementations MUST return [ErrReportNotFound] (or wrap it)
// when no row is found so callers can branch deterministically.
type ReportRepo interface {
	GetReport(ctx context.Context, id uuid.UUID) (ReportRow, error)
}

// AuditEvent is the minimal payload the [Presigner] emits for every
// `report_downloaded` event. Fields outside this struct (actor id,
// IP, request id) are filled in by the [AuditEmitter] implementation
// from the request context; the presigner only owns the report
// identifying triple.
//
// Validates: Requirements 6.6, 20.7.
type AuditEvent struct {
	OrgID       string
	WorkspaceID string
	EventType   string
	ReportID    uuid.UUID
	Key         string
	OccurredAt  time.Time
}

// AuditEmitter publishes audit events. The seam exists because
// `internal/cloud/audit` is still scaffolded (task 1.9 / 13.1 own the
// persistence layer); production wires a pgx-backed implementation
// once that lands. Implementations MUST be safe for concurrent use.
type AuditEmitter interface {
	Emit(ctx context.Context, event AuditEvent) error
}

// Clock is a tiny abstraction over `time.Now` so tests can drive the
// presigner at deterministic instants. Production callers leave Clock
// nil and the presigner defaults to `time.Now().UTC()`.
type Clock func() time.Time

// Presigner issues signed S3 GET URLs for branded PDF reports. A
// single Presigner is safe for concurrent use as long as the injected
// [ReportRepo], [storage.Storage], and [AuditEmitter] are.
//
// Construction does NOT verify that the [storage.Storage] is bound to
// the same `(org_id, workspace_id)` carried by every request — that
// is the caller's responsibility (the `WithTenant` middleware
// constructs a per-request tenant-scoped storage before invoking the
// handler). The presigner's own tenancy check fires on the row data
// returned from the repository; if the row's tenant pair does not
// match the request principal's, we return
// [storage.ErrTenantIsolationViolation] and skip the presign entirely.
//
// Validates: Requirements 6.6, 20.7.
type Presigner struct {
	// Repo is the persistence seam. Required.
	Repo ReportRepo

	// Storage issues the signed URL via SSE-KMS. Required.
	Storage storage.Storage

	// Audit publishes `report_downloaded` events. Required.
	Audit AuditEmitter

	// TTL is the requested presign lifetime. Values ≤ 0 or greater
	// than [MaxPresignTTL] are clamped to [MaxPresignTTL] before the
	// URL is signed; this guarantees the 15-minute upper bound from
	// Requirement 6.6 even if the caller sets the field to a longer
	// value.
	TTL time.Duration

	// Now overrides the wall clock for tests. Leave nil in
	// production; the presigner falls back to `time.Now().UTC()`.
	Now Clock
}

// NewPresigner returns a Presigner with TTL pre-set to
// [MaxPresignTTL]. The constructor validates every required dependency
// is non-nil so a wiring mistake at startup surfaces immediately
// rather than mid-request.
//
// Validates: Requirements 6.6, 20.7.
func NewPresigner(repo ReportRepo, store storage.Storage, audit AuditEmitter) (*Presigner, error) {
	if repo == nil {
		return nil, errors.New("reports: NewPresigner requires a non-nil report repo")
	}
	if store == nil {
		return nil, errors.New("reports: NewPresigner requires a non-nil storage")
	}
	if audit == nil {
		return nil, errors.New("reports: NewPresigner requires a non-nil audit emitter")
	}
	return &Presigner{
		Repo:    repo,
		Storage: store,
		Audit:   audit,
		TTL:     MaxPresignTTL,
	}, nil
}

// Presign returns a signed S3 GET URL for the report identified by
// reportID along with the absolute timestamp at which the URL
// expires. The TTL is the smaller of [Presigner.TTL] and
// [MaxPresignTTL] (15 minutes), so a misconfigured caller cannot
// exceed the platform-wide upper bound.
//
// The function performs four steps in order:
//
//  1. Resolve `(org_id, workspace_id)` from the [tenancy] context.
//     A request whose tenant context is empty is rejected with
//     [storage.ErrTenantIsolationViolation] (the canonical sentinel
//     for "this caller is not allowed to touch tenant-scoped state").
//  2. Look up the report row via [ReportRepo]. A missing row maps to
//     [ErrReportNotFound]; transport errors are returned verbatim.
//  3. Compare the row's `(org_id, workspace_id)` against the request
//     principal's. A mismatch returns
//     [storage.ErrTenantIsolationViolation]; the storage layer also
//     guards against this (its Presign call validates the key prefix)
//     but the application-layer check produces a clearer error and
//     keeps the signed URL out of S3 entirely.
//  4. Call [storage.Storage.Presign] with the clamped TTL and emit a
//     `report_downloaded` audit event. The audit emission is
//     non-blocking: a failure is logged via zerolog and the URL is
//     still returned, matching the task brief
//     ("don't block on audit failure — log and continue").
//
// Validates: Requirements 6.6, 20.7.
func (p *Presigner) Presign(ctx context.Context, reportID uuid.UUID) (string, time.Time, error) {
	if p == nil {
		return "", time.Time{}, errors.New("reports: nil presigner")
	}
	if p.Repo == nil || p.Storage == nil || p.Audit == nil {
		return "", time.Time{}, errors.New("reports: presigner dependencies not configured")
	}
	if reportID == uuid.Nil {
		return "", time.Time{}, errors.New("reports: report id is required")
	}

	callerOrg := tenancy.OrgID(ctx)
	callerWs := tenancy.WorkspaceID(ctx)
	if callerOrg == "" || callerWs == "" {
		return "", time.Time{}, fmt.Errorf("%w: tenant context unresolved", storage.ErrTenantIsolationViolation)
	}

	row, err := p.Repo.GetReport(ctx, reportID)
	if err != nil {
		if errors.Is(err, ErrReportNotFound) {
			return "", time.Time{}, err
		}
		return "", time.Time{}, fmt.Errorf("reports: lookup report %s: %w", reportID, err)
	}

	if row.OrgID != callerOrg || row.WorkspaceID != callerWs {
		return "", time.Time{}, fmt.Errorf(
			"%w: report %s belongs to a different tenant",
			storage.ErrTenantIsolationViolation, reportID,
		)
	}

	ttl := p.TTL
	if ttl <= 0 || ttl > MaxPresignTTL {
		ttl = MaxPresignTTL
	}

	now := p.now()

	url, err := p.Storage.Presign(ctx, row.S3Key, ttl)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("reports: presign %s: %w", reportID, err)
	}
	expiresAt := now.Add(ttl)

	if auditErr := p.Audit.Emit(ctx, AuditEvent{
		OrgID:       row.OrgID,
		WorkspaceID: row.WorkspaceID,
		EventType:   AuditEventReportDownloaded,
		ReportID:    row.ID,
		Key:         row.S3Key,
		OccurredAt:  now,
	}); auditErr != nil {
		// Audit emission is best-effort. A persistence outage on the
		// audit table must not break a Member's report download —
		// log loudly so on-call sees the event was missed and move
		// on. The signed URL is still returned to the caller.
		log.Warn().Err(auditErr).
			Str("event", AuditEventReportDownloaded).
			Str("org_id", row.OrgID).
			Str("workspace_id", row.WorkspaceID).
			Str("report_id", row.ID.String()).
			Str("key", row.S3Key).
			Msg("report_downloaded audit emit failed")
	}

	return url, expiresAt, nil
}

// now returns the configured clock or `time.Now().UTC()` when no
// clock has been injected. UTC is the canonical wall clock for every
// audit event emitted by the Cloud_Platform.
func (p *Presigner) now() time.Time {
	if p.Now != nil {
		return p.Now()
	}
	return time.Now().UTC()
}
