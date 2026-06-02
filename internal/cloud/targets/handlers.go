// Copyright (c) Xalgorix.
// SPDX-License-Identifier: AGPL-3.0-only

package targets

// handlers.go implements task 7.8 of the xalgorix-saas spec — the three
// public REST endpoints that drive the target ownership lifecycle:
//
//   POST   /api/v1/targets             — register a new target
//   POST   /api/v1/targets/{id}/verify — run a verifier and (on success)
//                                        promote the target to `verified`
//   DELETE /api/v1/targets/{id}        — remove a target (soft or hard)
//
// The verifier primitives, token issuer, recheck cron, cooldown, and the
// `verified_local` short-circuit already live in this package (see
// token.go, dns_verifier.go, file_verifier.go, meta_verifier.go,
// recheck.go, cooldown.go, local.go). This file only wires them into
// HTTP handlers and persists state through a small repository seam.
//
// Tenancy, RBAC, and CSRF protection are enforced by middleware mounted
// at router-construction time:
//
//   * tenancy.WithTenant — opens the per-request transaction, stamps
//     `app.organization_id` / `app.workspace_id` GUCs so the
//     `targets_tenant_isolation` RLS policy from design.md fires.
//   * orgs.RequireRole(orgs.RoleMember) — gates create/verify.
//   * orgs.RequireRole(orgs.RoleAdmin)  — gates delete.
//   * api.CSRF — mounted on browser-driven routes by the API_Server
//     wiring (task 8.1); API_Key requests bear a Bearer token and the
//     CSRF middleware exempts them automatically.
//
// The handlers themselves are defensive: they re-check the resolved
// tenant on every call (a missing tenant is a 401), refuse to operate on
// targets that belong to a different workspace (404 — never leak the
// existence of a sibling tenant's target), and fail closed on any
// repository error.
//
// Validates: Requirements 7.1, 7.2, 7.4, 7.5, 7.6, 7.8, 8.1.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/rs/zerolog/log"

	"github.com/xalgord/xalgorix/v4/internal/cloud/billing"
	"github.com/xalgord/xalgorix/v4/internal/cloud/orgs"
	"github.com/xalgord/xalgorix/v4/internal/cloud/tenancy"
)

// Mode names the deployment mode a customer requests when adding a
// target. SaaS is the default — scans run in the shared Worker_Pool
// namespace with NetworkPolicy isolation. Enterprise is the per-Org
// dedicated namespace tier (design.md → "Per-Org Network Isolation");
// it is plan-locked behind PlanEnterprise.
type Mode string

// Mode constants. Values are lower-case to match the JSON wire format
// the dashboard and API_Key clients send.
const (
	ModeSaaS       Mode = "saas"
	ModeEnterprise Mode = "enterprise"
)

// IsValid reports whether m is one of the canonical Mode values.
func (m Mode) IsValid() bool {
	switch m {
	case ModeSaaS, ModeEnterprise:
		return true
	default:
		return false
	}
}

// Target is the lightweight projection of a `targets` row the handlers
// pass between repository and JSON. The full DDL lives in design.md
// (table `targets`); this struct intentionally omits columns the
// handlers don't read (created_at, etc.) so the repository can return
// either a hydrated row or a slim subset without breaking the wire
// format.
type Target struct {
	ID                string
	OrgID             string
	WorkspaceID       string
	Host              string
	Status            string
	VerificationToken string
	VerifiedMethod    string
	VerifiedAt        time.Time
}

// Repository is the storage seam the handlers depend on. It is
// deliberately narrow: every method maps one-to-one to a SQL operation
// that the production repository will issue inside the tenant-scoped
// transaction opened by `tenancy.WithTenant`. Tests inject an in-memory
// fake.
//
// The contract for tenancy is asymmetric on purpose: the middleware
// already stamps `app.workspace_id`, so the production implementation
// can rely on PostgreSQL RLS to scope every query. The interface still
// surfaces (orgID, workspaceID) on Create so the row carries explicit
// identifiers for logs, audit, and the Storage prefix check; reads
// trust RLS but the in-memory test fake performs the check by hand to
// keep tenant isolation exercised even without a real database.
type Repository interface {
	// Create inserts a fresh `targets` row and returns it with its
	// assigned id. The implementation MUST persist the supplied
	// status (`unverified` or `verified_local`) and verification_token
	// verbatim; collisions on `verification_token` (UNIQUE platform-
	// wide per Requirement 7.8) surface as ErrDuplicateToken so the
	// handler can retry once with a freshly minted token.
	Create(ctx context.Context, t Target) (Target, error)

	// Get returns the target with id. The implementation MUST return
	// ErrTargetNotFound for both "row missing" and "row exists but
	// belongs to a different tenant" — the second case is what
	// preserves Requirement 1.1 / 1.6 tenant isolation by refusing to
	// leak the existence of a sibling workspace's target.
	Get(ctx context.Context, id string) (Target, error)

	// MarkVerified transitions the target row from `unverified` to
	// `verified` and stamps `verified_method` and `verified_at`.
	// Returning an error from this method MUST NOT roll the cooldown
	// counter back; the verifier already wrote a successful attempt
	// row before this call.
	MarkVerified(ctx context.Context, id, method string, at time.Time) error

	// RecordAttempt appends a row to `target_verification_attempts`.
	// Implementations should not mutate `targets` here — counter
	// updates and downgrades are routed through the dedicated methods
	// on this interface and the recheck scheduler.
	RecordAttempt(ctx context.Context, attempt VerificationAttempt) error

	// Delete removes the target (soft or hard, at the implementation's
	// discretion — the design allows either, see Requirement 7.x and
	// the table DDL's ON DELETE CASCADE on `target_verification_attempts`).
	// Implementations MUST emit no audit themselves; the handler emits
	// `target_deleted` so the audit event carries the actor account.
	Delete(ctx context.Context, id string) error
}

// PlanResolver returns the Plan for an Organization. The handlers use
// it to gate `mode=enterprise` on PlanEnterprise (design.md → "Per-Org
// Network Isolation": "Per-Org K8s namespace on Enterprise; shared
// namespace + NetworkPolicies on lower tiers"). Production wiring
// looks the plan up from the `organizations.plan` column inside the
// already-open tenancy transaction; tests inject a static map.
type PlanResolver interface {
	Plan(ctx context.Context, orgID string) (billing.Plan, error)
}

// PlanResolverFunc adapts a plain function to the PlanResolver
// interface, mirroring `http.HandlerFunc`. Production wiring uses a
// closure over the org service; tests use a literal table.
type PlanResolverFunc func(ctx context.Context, orgID string) (billing.Plan, error)

// Plan implements PlanResolver.
func (f PlanResolverFunc) Plan(ctx context.Context, orgID string) (billing.Plan, error) {
	return f(ctx, orgID)
}

// ErrTargetNotFound is returned by Repository.Get when a target id is
// either absent or belongs to a different tenant. The handler maps this
// to HTTP 404 in both cases so the API never leaks the existence of a
// sibling workspace's target.
var ErrTargetNotFound = errors.New("targets: target not found")

// ErrDuplicateToken is returned by Repository.Create when the freshly
// minted verification_token collides with an existing row. The platform-
// wide UNIQUE constraint (Requirement 7.8) makes this vanishingly rare
// at 160 bits of entropy; the handler retries once with a fresh token
// before surfacing a 500.
var ErrDuplicateToken = errors.New("targets: duplicate verification_token")

// Handlers bundles the dependencies the three target endpoints need.
// The struct is constructed once at API_Server boot and shared across
// every request — the underlying repository, verifiers, and emitter
// are expected to be safe for concurrent use.
type Handlers struct {
	// Repo persists targets and verification attempts. Required.
	Repo Repository

	// Cooldown is the per-target verification rate limiter from
	// cooldown.go. Required for the verify endpoint; the create and
	// delete endpoints do not consult it.
	Cooldown *CooldownTracker

	// DNS / File / Meta are the three external verifiers from
	// dns_verifier.go / file_verifier.go / meta_verifier.go. Each is
	// only required if the corresponding `method` value is offered to
	// callers; missing verifiers cause a 503 for that specific method
	// rather than a panic.
	DNS  Verifier
	File Verifier
	Meta Verifier

	// Audit publishes audit events. Required. The handlers emit
	// `target_added`, `target_verified`, and `target_deleted` (plus
	// the existing `target_downgraded` from the recheck scheduler).
	Audit AuditEmitter

	// Plans resolves the Organization's billing plan for the
	// `mode=enterprise` plan-lock check. Required.
	Plans PlanResolver

	// Now overrides the wall clock for tests. Leave nil in production.
	Now func() time.Time
}

// AuditEventTargetAdded / Verified / Deleted are the audit event_type
// values emitted by these handlers. The strings match the convention
// established by AuditEventTargetDowngraded in recheck.go.
const (
	AuditEventTargetAdded    = "target_added"
	AuditEventTargetVerified = "target_verified"
	AuditEventTargetDeleted  = "target_deleted"
)

// errorCode is the canonical machine-readable error code returned to
// API clients. Keeping these as named constants centralises the
// catalog so the generated OpenAPI spec (task 8.2) and the dashboard
// JS can switch on the same strings.
const (
	errCodeTenantUnresolved          = "tenant_unresolved"
	errCodeInvalidJSON               = "invalid_json"
	errCodeInvalidHost               = "invalid_host"
	errCodeInvalidMode               = "invalid_mode"
	errCodeInvalidMethod             = "invalid_method"
	errCodeMissingTargetID           = "missing_target_id"
	errCodeTargetNotFound            = "target_not_found"
	errCodePlanLockedEnterprise      = "plan_does_not_include_enterprise_mode"
	errCodeVerifierUnavailable       = "verifier_unavailable"
	errCodeVerificationCooldown      = "target_verification_cooldown"
	errCodeAlreadyVerified           = "target_already_verified"
	errCodeAlreadyVerifiedLocal      = "target_verified_local"
	errCodeCreateTargetFailed        = "create_target_failed"
	errCodeDeleteTargetFailed        = "delete_target_failed"
	errCodeMarkVerifiedFailed        = "mark_verified_failed"
	errCodePlanLookupFailed          = "plan_lookup_failed"
	errCodeRecordAttemptFailed       = "record_attempt_failed"
)

// CreateTargetRequest is the JSON body shape POSTed to /api/v1/targets.
// The two fields mirror the task brief; additional columns from the
// `targets` DDL (kind, port, etc.) default to host-mode for now and
// are added by follow-up tasks.
type CreateTargetRequest struct {
	Host string `json:"host"`
	Mode Mode   `json:"mode"`
}

// CreateTargetResponse is the JSON body returned on a successful
// create. `VerificationMethods` lists the ownership-proof options the
// caller can next send to /verify; for `verified_local` targets the
// list is `["local"]` and the token is omitted (loopback rows skip the
// external check).
type CreateTargetResponse struct {
	ID                  string   `json:"id"`
	Host                string   `json:"host"`
	Status              string   `json:"status"`
	VerificationToken   string   `json:"verification_token,omitempty"`
	VerificationMethods []string `json:"verification_methods"`
}

// VerifyTargetRequest is the JSON body POSTed to
// /api/v1/targets/{id}/verify.
type VerifyTargetRequest struct {
	Method string `json:"method"`
}

// VerifyTargetResponse is returned with HTTP 202 from the verify
// endpoint. `Status` reports the target's status after the attempt was
// persisted (and the row was promoted on success).
type VerifyTargetResponse struct {
	ID     string `json:"id"`
	Status string `json:"status"`
}

// errorBody is the common error envelope. Matching the shape used by
// other handlers (see reports/logo_upload.go) keeps the dashboard JS
// branching on a single field.
type errorBody struct {
	Error string `json:"error"`
}

// Mount attaches the three target endpoints onto router. Callers are
// expected to wrap router with the standard middleware stack
// (tenancy.WithTenant, orgs.RequireRole, api.CSRF, RateLimit).
//
// The route definitions exist on chi.Router rather than chi.Mux so
// callers can mount the routes under their own subrouter prefix
// without forcing a particular mux to be the parent.
func (h *Handlers) Mount(router chi.Router) {
	if h == nil {
		panic("targets.Handlers.Mount: nil receiver")
	}
	if h.Repo == nil || h.Audit == nil || h.Plans == nil {
		panic("targets.Handlers.Mount: Repo, Audit, and Plans are required")
	}

	// Member and above (Owner > Admin > Member) may create targets and
	// trigger verification. Viewer is a read-only role and is rejected
	// by RequireRole before the handler runs.
	router.With(orgs.RequireRole(orgs.RoleMember)).Post("/", h.Create)
	router.With(orgs.RequireRole(orgs.RoleMember)).Post("/{id}/verify", h.Verify)
	// Delete requires Admin and above per the task brief.
	router.With(orgs.RequireRole(orgs.RoleAdmin)).Delete("/{id}", h.Delete)
}

// Create handles POST /api/v1/targets. It validates the body, gates
// `mode=enterprise` on PlanEnterprise, classifies the host (loopback →
// `verified_local`, else `unverified`), mints a verification token for
// non-loopback rows, persists the target, and returns the JSON body
// the dashboard / API_Key clients then use to drive verification.
//
// Validates: Requirements 7.1, 7.3, 7.6, 7.8, 8.1.
func (h *Handlers) Create(w http.ResponseWriter, r *http.Request) {
	orgID, workspaceID, ok := h.tenant(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, errCodeTenantUnresolved)
		return
	}

	var body CreateTargetRequest
	if err := decodeJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, errCodeInvalidJSON)
		return
	}

	host := strings.TrimSpace(body.Host)
	if host == "" || strings.ContainsAny(host, " \t\r\n/?#") {
		writeError(w, http.StatusUnprocessableEntity, errCodeInvalidHost)
		return
	}

	// Default mode is SaaS when omitted so callers that don't care
	// about the per-Org namespace tier don't have to send the field.
	if body.Mode == "" {
		body.Mode = ModeSaaS
	}
	if !body.Mode.IsValid() {
		writeError(w, http.StatusUnprocessableEntity, errCodeInvalidMode)
		return
	}

	if body.Mode == ModeEnterprise {
		plan, err := h.Plans.Plan(r.Context(), orgID)
		if err != nil {
			log.Error().Err(err).Str("org_id", orgID).Msg("targets: plan lookup failed")
			writeError(w, http.StatusInternalServerError, errCodePlanLookupFailed)
			return
		}
		if plan != billing.PlanEnterprise {
			// HTTP 402 mirrors the integration plan-lock pattern
			// from Requirement 9.7 ("plan_does_not_include_integration").
			writeError(w, http.StatusPaymentRequired, errCodePlanLockedEnterprise)
			return
		}
	}

	status := ClassifyVerification(host)
	token := ""
	methods := []string{"dns", "file", "meta"}
	if status == VerificationStatusVerifiedLocal {
		// Loopback short-circuit: no external check is performed,
		// so we don't issue a verification token and we surface the
		// `local` method in the response so dashboards render the
		// "no-action-needed" UI.
		methods = []string{"local"}
	} else {
		var err error
		token, err = h.mintToken()
		if err != nil {
			log.Error().Err(err).Msg("targets: mint verification token failed")
			writeError(w, http.StatusInternalServerError, errCodeCreateTargetFailed)
			return
		}
	}

	stored, err := h.createWithRetry(r.Context(), Target{
		OrgID:             orgID,
		WorkspaceID:       workspaceID,
		Host:              host,
		Status:            status,
		VerificationToken: token,
	})
	if err != nil {
		log.Error().Err(err).Str("org_id", orgID).Str("workspace_id", workspaceID).Msg("targets: create failed")
		writeError(w, http.StatusInternalServerError, errCodeCreateTargetFailed)
		return
	}

	// Best-effort audit emit. Failure to write the audit row does NOT
	// roll back the create — the row already exists and pretending it
	// doesn't would be worse than missing one audit event.
	_ = h.Audit.Emit(r.Context(), AuditEvent{
		OrgID:       orgID,
		WorkspaceID: workspaceID,
		EventType:   AuditEventTargetAdded,
		TargetID:    stored.ID,
		OccurredAt:  h.now(),
		Detail:      fmt.Sprintf("host=%s mode=%s status=%s", host, body.Mode, status),
	})

	writeJSON(w, http.StatusCreated, CreateTargetResponse{
		ID:                  stored.ID,
		Host:                stored.Host,
		Status:              stored.Status,
		VerificationToken:   stored.VerificationToken,
		VerificationMethods: methods,
	})
}

// Verify handles POST /api/v1/targets/{id}/verify. It runs the
// requested external verifier against the target's host, persists the
// attempt, applies the cooldown ledger, transitions the row to
// `verified` on success, and returns HTTP 202 with the post-attempt
// status. A target already in cooldown short-circuits with HTTP 429
// and `Retry-After`.
//
// Validates: Requirements 7.2, 7.4, 7.5, 8.1.
func (h *Handlers) Verify(w http.ResponseWriter, r *http.Request) {
	orgID, workspaceID, ok := h.tenant(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, errCodeTenantUnresolved)
		return
	}

	id := chi.URLParam(r, "id")
	if id == "" {
		writeError(w, http.StatusBadRequest, errCodeMissingTargetID)
		return
	}

	var body VerifyTargetRequest
	if err := decodeJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, errCodeInvalidJSON)
		return
	}
	method := strings.ToLower(strings.TrimSpace(body.Method))
	if method != RecheckMethodDNS && method != RecheckMethodFile && method != RecheckMethodMeta {
		writeError(w, http.StatusUnprocessableEntity, errCodeInvalidMethod)
		return
	}

	target, err := h.Repo.Get(r.Context(), id)
	if err != nil {
		if errors.Is(err, ErrTargetNotFound) {
			writeError(w, http.StatusNotFound, errCodeTargetNotFound)
			return
		}
		log.Error().Err(err).Str("target_id", id).Msg("targets: get failed")
		writeError(w, http.StatusInternalServerError, errCodeTargetNotFound)
		return
	}
	// Defensive double-check on tenancy. The repository should have
	// already filtered by RLS, but we never want to trust a single
	// layer for tenant isolation.
	if target.WorkspaceID != workspaceID || target.OrgID != orgID {
		writeError(w, http.StatusNotFound, errCodeTargetNotFound)
		return
	}

	// Loopback rows have no external signal to re-verify; surface a
	// 409 so the caller can render a friendly "this target is already
	// trusted" message rather than failing silently.
	if target.Status == VerificationStatusVerifiedLocal {
		writeError(w, http.StatusConflict, errCodeAlreadyVerifiedLocal)
		return
	}
	if target.Status == "verified" {
		writeError(w, http.StatusConflict, errCodeAlreadyVerified)
		return
	}

	// Cooldown gate. Locked is a single Redis EXISTS round-trip; the
	// 1-hour window is set in cooldown.go (Requirement 7.5).
	if h.Cooldown != nil {
		locked, err := h.Cooldown.Locked(r.Context(), id)
		if err != nil {
			log.Error().Err(err).Str("target_id", id).Msg("targets: cooldown probe failed")
			// Treat probe failures as fail-closed: refuse to run a
			// verification we couldn't rate-limit.
			writeError(w, http.StatusServiceUnavailable, errCodeVerifierUnavailable)
			return
		}
		if locked {
			w.Header().Set("Retry-After", strconv.Itoa(int(cooldownWindow/time.Second)))
			writeError(w, http.StatusTooManyRequests, errCodeVerificationCooldown)
			return
		}
	}

	// Resolve the verifier for the requested method. Verifiers are
	// optional dependencies on Handlers — if a deployment somehow
	// turns one off we surface a 503 rather than panic.
	verifier, err := h.verifierFor(method)
	if err != nil {
		log.Error().Err(err).Str("target_id", id).Str("method", method).Msg("targets: verifier missing")
		writeError(w, http.StatusServiceUnavailable, errCodeVerifierUnavailable)
		return
	}

	// Each verifier accepts a slightly different token shape (DNS:
	// bare 32-char value; File/Meta: full display token). The token
	// stored on the row is always the full display form, so we strip
	// the prefix for DNS and pass the row value directly to the rest.
	expected := target.VerificationToken
	if method == RecheckMethodDNS {
		expected = strings.TrimPrefix(expected, "xalgorix-site-verification=")
	}

	now := h.now()
	ok2, verr := verifier.Verify(r.Context(), target.Host, expected)
	detail := ""
	if verr != nil {
		detail = truncateDetail(verr.Error())
	}

	// Record the attempt regardless of outcome so the
	// `target_verification_attempts` ledger reflects every probe.
	// Failures to record are logged and surface as 500 so an operator
	// notices — losing audit-relevant rows silently is worse than a
	// failed verify.
	if rerr := h.Repo.RecordAttempt(r.Context(), VerificationAttempt{
		TargetID:    target.ID,
		OrgID:       target.OrgID,
		WorkspaceID: target.WorkspaceID,
		Method:      method,
		Succeeded:   ok2,
		Detail:      detail,
		AttemptedAt: now,
	}); rerr != nil {
		log.Error().Err(rerr).Str("target_id", id).Msg("targets: record attempt failed")
		writeError(w, http.StatusInternalServerError, errCodeRecordAttemptFailed)
		return
	}

	// Failure path: bump the cooldown counter. We don't return the
	// (locked, err) tuple from RecordFail to the client — the next
	// attempt will hit the lock check above and surface the 429 in a
	// consistent way regardless of whether *this* failure crossed the
	// threshold.
	if !ok2 {
		if h.Cooldown != nil {
			if _, cerr := h.Cooldown.RecordFail(r.Context(), id); cerr != nil {
				log.Error().Err(cerr).Str("target_id", id).Msg("targets: cooldown bump failed")
			}
		}
		// 202 Accepted with the unchanged status; the verifier ran,
		// the attempt was persisted, just not promoted.
		writeJSON(w, http.StatusAccepted, VerifyTargetResponse{
			ID:     target.ID,
			Status: target.Status,
		})
		return
	}

	// Success: promote the row, reset the cooldown counter, emit the
	// `target_verified` audit event.
	if err := h.Repo.MarkVerified(r.Context(), target.ID, method, now); err != nil {
		log.Error().Err(err).Str("target_id", id).Msg("targets: mark verified failed")
		writeError(w, http.StatusInternalServerError, errCodeMarkVerifiedFailed)
		return
	}
	if h.Cooldown != nil {
		if cerr := h.Cooldown.Reset(r.Context(), id); cerr != nil {
			// Non-fatal: a stale counter just means the next
			// failure window starts a little earlier. Log and move
			// on rather than fail the otherwise-successful verify.
			log.Warn().Err(cerr).Str("target_id", id).Msg("targets: cooldown reset failed")
		}
	}
	_ = h.Audit.Emit(r.Context(), AuditEvent{
		OrgID:       target.OrgID,
		WorkspaceID: target.WorkspaceID,
		EventType:   AuditEventTargetVerified,
		TargetID:    target.ID,
		OccurredAt:  now,
		Detail:      "method=" + method,
	})

	writeJSON(w, http.StatusAccepted, VerifyTargetResponse{
		ID:     target.ID,
		Status: "verified",
	})
}

// Delete handles DELETE /api/v1/targets/{id}. It looks up the target
// (with the same defensive tenancy double-check the verify endpoint
// uses), asks the repository to delete the row (the implementation
// chooses soft vs hard delete per task spec), emits the
// `target_deleted` audit event, and returns HTTP 204.
//
// Validates: Requirement 8.1, 13.5.
func (h *Handlers) Delete(w http.ResponseWriter, r *http.Request) {
	orgID, workspaceID, ok := h.tenant(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, errCodeTenantUnresolved)
		return
	}

	id := chi.URLParam(r, "id")
	if id == "" {
		writeError(w, http.StatusBadRequest, errCodeMissingTargetID)
		return
	}

	target, err := h.Repo.Get(r.Context(), id)
	if err != nil {
		if errors.Is(err, ErrTargetNotFound) {
			writeError(w, http.StatusNotFound, errCodeTargetNotFound)
			return
		}
		log.Error().Err(err).Str("target_id", id).Msg("targets: get failed")
		writeError(w, http.StatusInternalServerError, errCodeTargetNotFound)
		return
	}
	if target.WorkspaceID != workspaceID || target.OrgID != orgID {
		writeError(w, http.StatusNotFound, errCodeTargetNotFound)
		return
	}

	if err := h.Repo.Delete(r.Context(), target.ID); err != nil {
		log.Error().Err(err).Str("target_id", id).Msg("targets: delete failed")
		writeError(w, http.StatusInternalServerError, errCodeDeleteTargetFailed)
		return
	}

	_ = h.Audit.Emit(r.Context(), AuditEvent{
		OrgID:       target.OrgID,
		WorkspaceID: target.WorkspaceID,
		EventType:   AuditEventTargetDeleted,
		TargetID:    target.ID,
		OccurredAt:  h.now(),
		Detail:      "host=" + target.Host,
	})

	w.WriteHeader(http.StatusNoContent)
}

// tenant resolves the active org/workspace from the request context.
// The bool return makes the "either both are present or this is
// unauthorized" contract explicit at every call site.
func (h *Handlers) tenant(r *http.Request) (orgID, workspaceID string, ok bool) {
	orgID = tenancy.OrgID(r.Context())
	workspaceID = tenancy.WorkspaceID(r.Context())
	if orgID == "" || workspaceID == "" {
		return "", "", false
	}
	return orgID, workspaceID, true
}

// mintToken is a thin wrapper around GenerateVerificationToken so tests
// (and a future in-process token reservation strategy) can swap the
// generator without rewriting the handler.
func (h *Handlers) mintToken() (string, error) {
	return GenerateVerificationToken()
}

// createWithRetry runs Repo.Create with a single retry on
// ErrDuplicateToken. The retry mints a fresh token before re-issuing
// the insert so a (vanishingly rare) collision on the platform-wide
// UNIQUE constraint doesn't surface as a user-visible 500.
func (h *Handlers) createWithRetry(ctx context.Context, candidate Target) (Target, error) {
	stored, err := h.Repo.Create(ctx, candidate)
	if err == nil {
		return stored, nil
	}
	if !errors.Is(err, ErrDuplicateToken) {
		return Target{}, err
	}
	if candidate.VerificationToken == "" {
		// Nothing to retry — loopback rows don't carry a token.
		return Target{}, err
	}
	fresh, gerr := h.mintToken()
	if gerr != nil {
		return Target{}, gerr
	}
	candidate.VerificationToken = fresh
	return h.Repo.Create(ctx, candidate)
}

// verifierFor selects the configured verifier for a request method. It
// returns an error rather than nil when the verifier is missing so the
// handler can surface a deterministic 503 instead of a panic.
func (h *Handlers) verifierFor(method string) (Verifier, error) {
	switch method {
	case RecheckMethodDNS:
		if h.DNS == nil {
			return nil, errors.New("targets: DNS verifier not configured")
		}
		return h.DNS, nil
	case RecheckMethodFile:
		if h.File == nil {
			return nil, errors.New("targets: file verifier not configured")
		}
		return h.File, nil
	case RecheckMethodMeta:
		if h.Meta == nil {
			return nil, errors.New("targets: meta verifier not configured")
		}
		return h.Meta, nil
	default:
		return nil, fmt.Errorf("targets: unknown method %q", method)
	}
}

// now returns the wall clock the handlers should use, defaulting to
// time.Now when no override is configured. Mirrors the pattern in
// recheck.go.
func (h *Handlers) now() time.Time {
	if h.Now != nil {
		return h.Now()
	}
	return time.Now()
}

// decodeJSON enforces a strict JSON body decode: unknown fields and
// trailing junk are rejected so a typo in the request never silently
// reaches a default-valued field. The body cap is the caller's
// responsibility (the API_Server middleware stack mounts a 1 MiB
// http.MaxBytesReader on every request).
func decodeJSON(r *http.Request, into any) error {
	if r.Body == nil {
		return errors.New("missing body")
	}
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(into); err != nil {
		return err
	}
	// Reject trailing JSON tokens so a body of `{}{}` doesn't quietly
	// succeed.
	if dec.More() {
		return errors.New("unexpected trailing data")
	}
	return nil
}

// writeJSON marshals body and writes it to w with the supplied status
// and a JSON Content-Type. The encode error is swallowed because the
// status header has already been flushed by WriteHeader; callers that
// need observability should rely on the access log middleware.
func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// writeError is the error counterpart of writeJSON.
func writeError(w http.ResponseWriter, status int, code string) {
	writeJSON(w, status, errorBody{Error: code})
}

// NewID generates a fresh UUID for a target row. The function is
// exported so an in-memory test repository can reuse the same id
// generator the production repository will use, and so a future
// migration to a sortable UUIDv7 can land in one place rather than
// across every caller.
func NewID() string { return uuid.NewString() }
