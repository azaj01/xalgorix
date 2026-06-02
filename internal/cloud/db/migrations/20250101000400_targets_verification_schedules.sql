-- xalgorix-saas spec, task 1.5: targets, verification attempts, schedules with RLS.
--
-- Implements design.md "Data Models" → "Targets and verification" exactly:
--   * `targets` carries the per-Workspace target inventory with a
--     platform-wide UNIQUE constraint on `verification_token` (so a
--     given DNS TXT / file / meta token can verify at most one
--     Workspace, per requirement 7.8) and a `(workspace_id, status)`
--     composite index for the dispatch hot path.
--   * `target_verification_attempts` is an append-only audit trail of
--     verification probes, indexed by `(target_id, attempted_at DESC)`
--     for the "show last attempts" UI.
--   * `target_scan_schedules` powers the cron scheduler from design
--     "Components and Interfaces" → `internal/cloud/scans/scheduler.go`,
--     with a partial index on `(next_run_at)` filtered to
--     `enabled = true` so the scheduler's "fetch due rows" query stays
--     index-only.
--
-- All three tenant tables ENABLE + FORCE row level security and carry a
-- single canonical policy `<table>_tenant_isolation` matched on the
-- `app.workspace_id` GUC set by `internal/cloud/tenancy.WithTenant`.
--
-- Requirements: 7.1, 7.3, 7.6, 7.8.

-- +goose Up

CREATE TABLE targets (
    id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id              uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    workspace_id        uuid NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    kind                text NOT NULL CHECK (kind IN ('host','url','ip','cidr')),
    value               text NOT NULL,
    status              text NOT NULL CHECK (status IN ('unverified','verified','verified_local')),
    verification_token  text UNIQUE,
    verified_method     text CHECK (verified_method IN ('dns','file','meta','local')),
    verified_at         timestamptz,
    created_at          timestamptz NOT NULL DEFAULT now(),
    UNIQUE (workspace_id, value)
);

CREATE INDEX targets_workspace_idx ON targets(workspace_id, status);

ALTER TABLE targets ENABLE ROW LEVEL SECURITY;
ALTER TABLE targets FORCE  ROW LEVEL SECURITY;

CREATE POLICY targets_tenant_isolation ON targets
    USING (workspace_id = current_setting('app.workspace_id', true)::uuid);

CREATE TABLE target_verification_attempts (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    target_id       uuid NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    org_id          uuid NOT NULL,
    workspace_id    uuid NOT NULL,
    method          text NOT NULL,
    succeeded       boolean NOT NULL,
    detail          text,
    attempted_at    timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX tva_target_time_idx
    ON target_verification_attempts(target_id, attempted_at DESC);

ALTER TABLE target_verification_attempts ENABLE ROW LEVEL SECURITY;
ALTER TABLE target_verification_attempts FORCE  ROW LEVEL SECURITY;

CREATE POLICY target_verification_attempts_tenant_isolation
    ON target_verification_attempts
    USING (workspace_id = current_setting('app.workspace_id', true)::uuid);

CREATE TABLE target_scan_schedules (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    target_id       uuid NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    org_id          uuid NOT NULL,
    workspace_id    uuid NOT NULL,
    cron            text NOT NULL,
    timezone        text NOT NULL,
    next_run_at     timestamptz NOT NULL,
    last_run_at     timestamptz,
    enabled         boolean NOT NULL DEFAULT true
);

-- Partial index keeps the scheduler's hot "rows due next" query on a
-- compact, enabled-only subset sorted by next_run_at. The leading
-- `enabled` column is retained from design.md's index definition so
-- index-only scans can also satisfy queries that re-state the filter.
CREATE INDEX tss_next_run_idx
    ON target_scan_schedules(enabled, next_run_at)
    WHERE enabled = true;

ALTER TABLE target_scan_schedules ENABLE ROW LEVEL SECURITY;
ALTER TABLE target_scan_schedules FORCE  ROW LEVEL SECURITY;

CREATE POLICY target_scan_schedules_tenant_isolation
    ON target_scan_schedules
    USING (workspace_id = current_setting('app.workspace_id', true)::uuid);

-- +goose Down

DROP POLICY IF EXISTS target_scan_schedules_tenant_isolation ON target_scan_schedules;
DROP INDEX IF EXISTS tss_next_run_idx;
DROP TABLE IF EXISTS target_scan_schedules;

DROP POLICY IF EXISTS target_verification_attempts_tenant_isolation ON target_verification_attempts;
DROP INDEX IF EXISTS tva_target_time_idx;
DROP TABLE IF EXISTS target_verification_attempts;

DROP POLICY IF EXISTS targets_tenant_isolation ON targets;
DROP INDEX IF EXISTS targets_workspace_idx;
DROP TABLE IF EXISTS targets;
