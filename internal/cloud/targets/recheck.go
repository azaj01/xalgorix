// Copyright (c) Xalgorix.
// SPDX-License-Identifier: AGPL-3.0-only

package targets

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/robfig/cron/v3"
)

// RecheckCadence is the design-pinned interval at which a Verified_Target's
// ownership signal is re-checked. Design.md ("Re-check") and Requirement
// 7.7 both specify a 7-day cadence: a target is only eligible for a fresh
// recheck attempt once 7 days have elapsed since its last successful
// verification (`targets.last_verified_at` / `targets.verified_at`).
//
// The constant is exported so callers (cron wiring, tests) and SQL
// migrations that derive partial indexes can stay in lockstep without
// hard-coding the same magic number twice.
const RecheckCadence = 7 * 24 * time.Hour

// RecheckDowngradeThreshold is the number of consecutive recheck failures
// that flips a Verified_Target back to `unverified`. Pinned by
// Requirement 7.7 ("two consecutive failed re-checks") and the design's
// "Re-check" block.
const RecheckDowngradeThreshold = 2

// AuditEventTargetDowngraded is the audit event_type emitted when a
// Verified_Target loses its `verified` status because of consecutive
// recheck failures. The string matches the convention used by
// `target_verified` (Requirement 7.4) and the broader audit catalog.
const AuditEventTargetDowngraded = "target_downgraded"

// RecheckMethodDNS / File / Meta mirror the `targets.verified_method` enum
// (`dns`, `file`, `meta`, `local` — see design.md). The recheck dispatcher
// uses these to pick which Verifier to drive against a given target. The
// `local` method is intentionally omitted: targets verified through the
// loopback short-circuit (Requirement 7.6) are never subject to external
// rechecks, so encountering it here is treated as a no-op rather than a
// dispatch.
const (
	RecheckMethodDNS  = "dns"
	RecheckMethodFile = "file"
	RecheckMethodMeta = "meta"

	// recheckMethodLocal is the loopback short-circuit method. It's
	// unexported because no caller outside the recheck dispatcher needs
	// to special-case it; the value still matches design.md / the DDL.
	recheckMethodLocal = "local"
)

// RecheckTarget is the minimal projection of a `targets` row the
// RechecksScheduler needs to drive a single recheck attempt. It exists as
// its own type so the storage interface can be expressed without leaking
// the full Target schema (which is owned by other tasks in Phase 7) into
// this file.
type RecheckTarget struct {
	// ID is the `targets.id` UUID. The value is opaque to this package
	// and is only used to thread audit events and ledger rows back to
	// the originating row.
	ID string

	// OrgID and WorkspaceID are propagated onto every recorded
	// verification attempt and audit event so tenant isolation
	// (Requirement 1.1, 1.5) is preserved when the writes hit
	// Postgres / S3.
	OrgID       string
	WorkspaceID string

	// Host is the value the verifier dispatchers operate on. For DNS
	// and meta-tag verifiers this is the apex hostname; for the file
	// verifier this is the host portion of the well-known URL.
	Host string

	// Method is the original verification method recorded on the
	// target (`targets.verified_method`). It pins which Verifier the
	// scheduler dispatches to during recheck — Requirement 7.7
	// requires re-checks to use the *same* signal that originally
	// granted verification rather than re-prompting the customer.
	Method string

	// Token is the bare 32-char base32 value section of the
	// `targets.verification_token`. Verifiers that need the full
	// display token (`xalgorix-site-verification=<value>`) reconstruct
	// it from this field.
	Token string

	// LastVerifiedAt is the timestamp the row was last promoted to
	// `verified`. Targets whose `LastVerifiedAt` is within
	// `RecheckCadence` of `now` are skipped on this run.
	LastVerifiedAt time.Time

	// ConsecutiveFails counts how many recheck attempts have failed
	// in a row since the last success. A successful attempt resets
	// the counter to zero; reaching `RecheckDowngradeThreshold`
	// triggers the transition to `unverified`.
	ConsecutiveFails int
}

// VerificationAttempt is the row inserted into
// `target_verification_attempts` after every recheck dispatch. The shape
// mirrors the DDL in design.md ("Targets and verification") so the
// repository implementation can persist it without further translation.
type VerificationAttempt struct {
	TargetID    string
	OrgID       string
	WorkspaceID string
	Method      string
	Succeeded   bool
	Detail      string
	AttemptedAt time.Time
}

// AuditEvent is the minimal payload emitted for every state-changing
// recheck outcome. The full audit-events table carries more columns
// (actor, IP, request id, etc.); the recheck job is a system actor so
// only the tenant-scoping triple plus event metadata is populated here.
// Other fields are filled in by the audit emitter implementation
// (`internal/cloud/audit`).
type AuditEvent struct {
	OrgID       string
	WorkspaceID string
	EventType   string
	TargetID    string
	OccurredAt  time.Time
	Detail      string
}

// TargetRepo is the storage seam the RechecksScheduler depends on. It is
// deliberately narrow — every method maps one-to-one to a SQL operation
// that the production repository will issue inside a tenant-scoped
// transaction — so that tests can drive the scheduler with an in-memory
// fake without booting Postgres.
//
// All methods take a context to honour the caller's deadline /
// cancellation; production implementations are expected to attach the
// `app.organization_id` and `app.workspace_id` GUCs via the
// `internal/cloud/tenancy` middleware before any of these run.
type TargetRepo interface {
	// ListDueRechecks returns every `verified` target whose
	// `last_verified_at < now - RecheckCadence`. The `now` argument is
	// passed in (rather than read from `time.Now()` inside the repo)
	// so tests can drive deterministic behaviour. Production
	// implementations should `ORDER BY last_verified_at ASC` so the
	// oldest pending rechecks are processed first under load.
	ListDueRechecks(ctx context.Context, now time.Time) ([]RecheckTarget, error)

	// RecordAttempt inserts a row into `target_verification_attempts`.
	// The implementation MUST NOT mutate `targets` itself — counter
	// updates and downgrades are routed through the dedicated methods
	// below to keep the SQL surface auditable.
	RecordAttempt(ctx context.Context, attempt VerificationAttempt) error

	// IncrementConsecutiveFails bumps the per-target counter and
	// returns the post-increment value. Implementations should use
	// `UPDATE ... SET consecutive_recheck_fails = consecutive_recheck_fails + 1 RETURNING consecutive_recheck_fails`
	// so the read-modify-write happens in a single round trip and is
	// safe against concurrent recheck runs.
	IncrementConsecutiveFails(ctx context.Context, targetID string) (int, error)

	// ResetConsecutiveFails zeroes the counter and stamps
	// `last_verified_at = now`. It is called on every successful
	// recheck so the cadence window resets even when the target was
	// already at zero fails.
	ResetConsecutiveFails(ctx context.Context, targetID string, now time.Time) error

	// MarkUnverified transitions the target from `verified` to
	// `unverified` and clears `verified_method` / `verified_at` so a
	// future ownership re-prove is required. Returning an error from
	// this method aborts the per-target work-unit but does not abort
	// the rest of the cron run.
	MarkUnverified(ctx context.Context, targetID string) error
}

// Verifier is the per-method ownership-check seam the scheduler dispatches
// to. The DNS, file, and meta verifiers in this package already match
// this shape (`Verify(ctx, host, expectedToken) (bool, error)`), so wiring
// is a direct field assignment in production; tests replace each verifier
// with a deterministic fake.
//
// Contract (matches `DNSVerifier.Verify` / `MetaVerifier.Verify`):
//
//	(true,  nil)  ownership signal still present.
//	(false, nil)  ownership signal absent — count this as a failure.
//	(false, err)  transport / parse error — also count as a failure but
//	              record the error in `VerificationAttempt.Detail` so
//	              operators can distinguish "owner removed the record"
//	              from "we couldn't reach the resolver".
type Verifier interface {
	Verify(ctx context.Context, host, expectedToken string) (bool, error)
}

// AuditEmitter publishes audit events. The recheck scheduler emits
// exactly one `target_downgraded` event per downgraded target. The seam
// exists because `internal/cloud/audit` is still scaffolded (task 1.9 /
// 13.1 own the persistence layer) and we don't want recheck wiring to
// block on those tasks.
type AuditEmitter interface {
	Emit(ctx context.Context, event AuditEvent) error
}

// Clock is a tiny abstraction over `time.Now` so tests can drive the
// scheduler at deterministic instants without monkey-patching the global
// clock. Production callers leave Clock nil and the scheduler defaults
// to `time.Now`.
type Clock func() time.Time

// RechecksScheduler walks every `verified` target whose
// `last_verified_at` is older than `RecheckCadence` and re-runs the
// verification method that originally promoted the row. Each attempt is
// appended to `target_verification_attempts`; consecutive failures are
// counted on the target row, and on the second consecutive failure the
// target is downgraded to `unverified` with a `target_downgraded` audit
// event.
//
// Implements Requirement 7.7. The cooldown logic from Requirement 7.5
// (3 fails / hour) is owned by task 7.6 in a separate file; the recheck
// scheduler runs at most once per day per target so the per-hour
// cooldown is never reached by recheck-driven attempts alone.
//
// The scheduler is safe for concurrent use only across distinct cron
// invocations: each `Run` call processes its work serially. Multiple
// API_Server pods running the cron simultaneously is fine *if* the
// repository's `IncrementConsecutiveFails` is implemented as a single
// SQL `UPDATE ... RETURNING`, which is the documented contract.
type RechecksScheduler struct {
	// Repo is the persistence seam. Required.
	Repo TargetRepo

	// DNS / File / Meta are the three external verifiers. Each is
	// only required if at least one target uses the corresponding
	// `verified_method`; missing verifiers cause the dispatch for
	// matching targets to fail with a deterministic error rather
	// than panic.
	DNS  Verifier
	File Verifier
	Meta Verifier

	// Audit publishes `target_downgraded` events. Required.
	Audit AuditEmitter

	// Now overrides the wall clock for tests. Leave nil in production.
	Now Clock
}

// NewRechecksScheduler is a small constructor that documents the required
// dependencies. It returns a usable scheduler when every required
// dependency is non-nil and an error otherwise — surfacing the
// configuration mistake at startup is far easier to debug than a nil
// pointer panic mid-run.
func NewRechecksScheduler(repo TargetRepo, dns, file, meta Verifier, audit AuditEmitter) (*RechecksScheduler, error) {
	if repo == nil {
		return nil, errors.New("targets: RechecksScheduler requires a non-nil repo")
	}
	if audit == nil {
		return nil, errors.New("targets: RechecksScheduler requires a non-nil audit emitter")
	}
	return &RechecksScheduler{
		Repo:  repo,
		DNS:   dns,
		File:  file,
		Meta:  meta,
		Audit: audit,
	}, nil
}

// Run executes one full recheck pass: list every due target, drive its
// configured verifier, record the attempt, and apply the failure /
// downgrade bookkeeping.
//
// Returning an error from Run aborts the *current* pass; the next
// scheduled tick will pick up where this one left off because every
// per-target effect is committed independently. A failure to record an
// attempt or update the counter for one target therefore does not stop
// the rest of the run from making progress.
//
// The error returned by Run is the *first* unrecoverable error
// encountered while iterating; per-target errors are logged into the
// `VerificationAttempt.Detail` column rather than returned, since they
// are the normal case for "site is briefly down" and should not abort
// the cron pass. Two failure modes do abort iteration outright:
//   - the initial `ListDueRechecks` call (we have no work without it),
//   - the supplied context being cancelled (caller deadline hit).
func (s *RechecksScheduler) Run(ctx context.Context) error {
	if s == nil {
		return errors.New("targets: nil RechecksScheduler")
	}
	if s.Repo == nil {
		return errors.New("targets: RechecksScheduler.Repo is nil")
	}
	if s.Audit == nil {
		return errors.New("targets: RechecksScheduler.Audit is nil")
	}

	now := s.now()
	due, err := s.Repo.ListDueRechecks(ctx, now)
	if err != nil {
		return fmt.Errorf("targets: list due rechecks: %w", err)
	}

	var firstErr error
	for _, t := range due {
		if err := ctx.Err(); err != nil {
			return err
		}
		if e := s.recheckOne(ctx, t, s.now()); e != nil && firstErr == nil {
			firstErr = e
		}
	}
	return firstErr
}

// recheckOne handles the per-target work-unit. Splitting it out keeps
// Run small and lets the unit tests target individual code paths
// (success, single fail, downgrade, missing verifier) without having to
// manufacture a full repo listing.
func (s *RechecksScheduler) recheckOne(ctx context.Context, t RecheckTarget, now time.Time) error {
	verifier, err := s.verifierFor(t.Method)
	if err != nil {
		// A target with no matching verifier cannot succeed and
		// cannot fail "cleanly" — record the misconfiguration as a
		// failure attempt so the operator notices, but do not bump
		// the consecutive-fail counter (we don't want a deployment
		// with a missing verifier to flush all customer targets).
		_ = s.Repo.RecordAttempt(ctx, VerificationAttempt{
			TargetID:    t.ID,
			OrgID:       t.OrgID,
			WorkspaceID: t.WorkspaceID,
			Method:      t.Method,
			Succeeded:   false,
			Detail:      err.Error(),
			AttemptedAt: now,
		})
		return err
	}

	// `local` short-circuits: the loopback short-circuit (Requirement
	// 7.6) is a static syntactic decision; the value of the host
	// can't drift between recheck windows the way DNS or HTML can. We
	// stamp a successful attempt and reset the cadence so the row
	// isn't re-listed every day, but never downgrade.
	if t.Method == recheckMethodLocal {
		if err := s.Repo.RecordAttempt(ctx, VerificationAttempt{
			TargetID:    t.ID,
			OrgID:       t.OrgID,
			WorkspaceID: t.WorkspaceID,
			Method:      t.Method,
			Succeeded:   true,
			Detail:      "verified_local short-circuit; no external check",
			AttemptedAt: now,
		}); err != nil {
			return fmt.Errorf("targets: record local recheck for %s: %w", t.ID, err)
		}
		if err := s.Repo.ResetConsecutiveFails(ctx, t.ID, now); err != nil {
			return fmt.Errorf("targets: reset local recheck for %s: %w", t.ID, err)
		}
		return nil
	}

	expected := tokenPrefix + t.Token
	ok, verifyErr := verifier.Verify(ctx, t.Host, expected)

	detail := ""
	if verifyErr != nil {
		// Truncated to keep the audit ledger from growing unbounded
		// when a misbehaving target streams 1 MiB error pages back
		// at us; full detail still lives in structured logs.
		detail = truncateDetail(verifyErr.Error())
	}

	attempt := VerificationAttempt{
		TargetID:    t.ID,
		OrgID:       t.OrgID,
		WorkspaceID: t.WorkspaceID,
		Method:      t.Method,
		Succeeded:   ok,
		Detail:      detail,
		AttemptedAt: now,
	}
	if err := s.Repo.RecordAttempt(ctx, attempt); err != nil {
		return fmt.Errorf("targets: record attempt for %s: %w", t.ID, err)
	}

	if ok {
		// Single success resets the counter and stamps the cadence
		// window — both updates happen in the same SQL statement
		// inside the production repo.
		if err := s.Repo.ResetConsecutiveFails(ctx, t.ID, now); err != nil {
			return fmt.Errorf("targets: reset fails for %s: %w", t.ID, err)
		}
		return nil
	}

	// Failure path: bump the counter and decide whether we crossed
	// the downgrade threshold. The post-increment value comes from
	// the repo so we observe exactly the value persisted in
	// Postgres rather than a stale in-memory copy.
	consecutive, err := s.Repo.IncrementConsecutiveFails(ctx, t.ID)
	if err != nil {
		return fmt.Errorf("targets: increment fails for %s: %w", t.ID, err)
	}
	if consecutive < RecheckDowngradeThreshold {
		return nil
	}

	if err := s.Repo.MarkUnverified(ctx, t.ID); err != nil {
		return fmt.Errorf("targets: mark unverified for %s: %w", t.ID, err)
	}

	// Best-effort audit emit. A failure to write the audit row
	// MUST NOT roll back the downgrade — we can lose the audit
	// trail for one event but we cannot afford to leave a target
	// flapping between `verified` and `unverified` because the
	// audit writer is briefly unavailable. Operators are expected
	// to alert on `audit_emitter_error` from the underlying
	// emitter.
	return s.Audit.Emit(ctx, AuditEvent{
		OrgID:       t.OrgID,
		WorkspaceID: t.WorkspaceID,
		EventType:   AuditEventTargetDowngraded,
		TargetID:    t.ID,
		OccurredAt:  now,
		Detail: fmt.Sprintf("%d consecutive recheck failures using method=%s",
			consecutive, t.Method),
	})
}

// verifierFor maps a `targets.verified_method` value onto the configured
// Verifier. The local short-circuit is handled by the caller; this
// method only fails when an *external* method is required but the
// corresponding verifier was not wired up.
func (s *RechecksScheduler) verifierFor(method string) (Verifier, error) {
	switch method {
	case RecheckMethodDNS:
		if s.DNS == nil {
			return nil, fmt.Errorf("targets: DNS verifier required for method=%s", method)
		}
		return s.DNS, nil
	case RecheckMethodFile:
		if s.File == nil {
			return nil, fmt.Errorf("targets: file verifier required for method=%s", method)
		}
		return s.File, nil
	case RecheckMethodMeta:
		if s.Meta == nil {
			return nil, fmt.Errorf("targets: meta verifier required for method=%s", method)
		}
		return s.Meta, nil
	case recheckMethodLocal:
		// Loopback targets are handled by the caller; return a nil
		// verifier and a nil error so the dispatcher can detect the
		// short-circuit explicitly.
		return nil, nil
	default:
		return nil, fmt.Errorf("targets: unknown verified_method %q", method)
	}
}

// now returns the scheduler's wall clock, defaulting to `time.Now` when
// no override is configured.
func (s *RechecksScheduler) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// recheckDetailMax bounds the size of an error string persisted in
// `target_verification_attempts.detail`. The column itself is `text`
// (unbounded) but a misbehaving target can stream a multi-MiB error page
// that we don't want to keep around row-for-row.
const recheckDetailMax = 1024

func truncateDetail(s string) string {
	if len(s) <= recheckDetailMax {
		return s
	}
	return s[:recheckDetailMax] + "...[truncated]"
}

// Schedule registers Run as a `@daily` job on the supplied
// robfig/cron/v3 scheduler. The returned EntryID can be used by callers
// to remove the job during graceful shutdown; passing a nil cron is a
// no-op so wiring code can call Schedule unconditionally.
//
// `@daily` is the descriptor pinned by the task spec ("Daily job
// re-verifies all verified targets"). robfig/cron/v3 expands it to
// `0 0 * * *` in the scheduler's local time zone — production callers
// are expected to construct the cron with `cron.New(cron.WithLocation(time.UTC))`
// so the run boundary is the same in every region.
//
// The job swallows non-fatal errors from Run so the cron loop keeps
// running on the next tick. Operators surface failures via the
// structured logs emitted around RecordAttempt in the repo
// implementation; the cron entry itself only reports panics.
func (s *RechecksScheduler) Schedule(c *cron.Cron) (cron.EntryID, error) {
	if s == nil {
		return 0, errors.New("targets: nil RechecksScheduler")
	}
	if c == nil {
		return 0, nil
	}
	id, err := c.AddFunc("@daily", func() {
		// Use Background here, not the cron's request context (it
		// has none), and rely on the repo's per-call timeouts to
		// bound work. Errors are intentionally discarded — see the
		// godoc above.
		_ = s.Run(context.Background())
	})
	if err != nil {
		return 0, fmt.Errorf("targets: schedule daily recheck: %w", err)
	}
	return id, nil
}
