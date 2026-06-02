-- xalgorix-saas spec — Phase 1 task 1.6
--
-- Migration: scans, scan_event_archive, findings, reports with RLS.
--
-- Source of truth: `.kiro/specs/xalgorix-saas/design.md` →
--   "Data Models" → "Scans, findings, reports" block, plus
--   "Critical indexes summary" for hot-path indexes.
--
-- Tenant isolation:
--   * Each table has `ENABLE` + `FORCE ROW LEVEL SECURITY` and a single
--     canonical policy named `<table>_tenant_isolation` matching the
--     per-request `app.workspace_id` GUC bound by the
--     `internal/cloud/tenancy` middleware (task 1.12).
--
-- Hot indexes (see design.md → "Critical indexes summary"):
--   * findings  (workspace_id, severity, status)            — dashboards
--   * scans     (workspace_id, status, requested_at DESC)   — list views
--   * reports   (workspace_id, generated_at DESC)           — list views
--   * findings  UNIQUE (workspace_id, target_id, signature_hash) — dedup
--
-- Requirements: 1.5, 1.7, 6.4, 6.5, 6.10.

-- +goose Up
-- +goose StatementBegin
CREATE TABLE scans (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id          uuid NOT NULL,
    workspace_id    uuid NOT NULL,
    target_id       uuid NOT NULL REFERENCES targets(id),
    requested_by    uuid NOT NULL REFERENCES accounts(id),
    mode            text NOT NULL CHECK (mode IN ('single','dast','wildcard','multi')),
    phases          int[] NOT NULL DEFAULT ARRAY[]::int[],
    severity_filter text[] NOT NULL DEFAULT ARRAY[]::text[],
    instructions    text,
    company_name    text,
    logo_s3_key     text,
    status          text NOT NULL CHECK (status IN ('queued','running','completed','failed','canceled')),
    worker_id       text,
    requested_at    timestamptz NOT NULL DEFAULT now(),
    started_at      timestamptz,
    finished_at     timestamptz,
    deadline_at     timestamptz NOT NULL,
    finding_counts  jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at      timestamptz NOT NULL DEFAULT now()
);
-- +goose StatementEnd

-- +goose StatementBegin
ALTER TABLE scans ENABLE ROW LEVEL SECURITY;
-- +goose StatementEnd
-- +goose StatementBegin
ALTER TABLE scans FORCE ROW LEVEL SECURITY;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE POLICY scans_tenant_isolation ON scans
    USING (workspace_id = current_setting('app.workspace_id', true)::uuid);
-- +goose StatementEnd

-- Hot list / concurrency cap indexes (design.md → Critical indexes summary).
-- +goose StatementBegin
CREATE INDEX scans_workspace_status_requested_idx
    ON scans (workspace_id, status, requested_at DESC);
-- +goose StatementEnd
-- +goose StatementBegin
CREATE INDEX scans_workspace_status_idx
    ON scans (workspace_id, status);
-- +goose StatementEnd
-- +goose StatementBegin
CREATE INDEX scans_workspace_created_at_idx
    ON scans (workspace_id, created_at DESC);
-- +goose StatementEnd
-- +goose StatementBegin
CREATE INDEX scans_org_active_idx
    ON scans (org_id)
    WHERE status IN ('queued','running');
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TABLE scan_event_archive (
    scan_id         uuid PRIMARY KEY REFERENCES scans(id) ON DELETE CASCADE,
    org_id          uuid NOT NULL,
    workspace_id    uuid NOT NULL,
    s3_key          text NOT NULL,
    event_count     int  NOT NULL,
    byte_size       bigint NOT NULL DEFAULT 0,
    sha256          bytea,
    archived_at     timestamptz NOT NULL DEFAULT now()
);
-- +goose StatementEnd

-- +goose StatementBegin
ALTER TABLE scan_event_archive ENABLE ROW LEVEL SECURITY;
-- +goose StatementEnd
-- +goose StatementBegin
ALTER TABLE scan_event_archive FORCE ROW LEVEL SECURITY;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE POLICY scan_event_archive_tenant_isolation ON scan_event_archive
    USING (workspace_id = current_setting('app.workspace_id', true)::uuid);
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TABLE findings (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id          uuid NOT NULL,
    workspace_id    uuid NOT NULL,
    scan_id         uuid NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    target_id       uuid NOT NULL REFERENCES targets(id),
    title           text NOT NULL,
    description     text,
    severity        text NOT NULL CHECK (severity IN ('info','low','medium','high','critical')),
    status          text NOT NULL DEFAULT 'open'
                        CHECK (status IN ('open','verified','false_positive','wont_fix')),
    cvss_vector     text,
    cvss_score      numeric(3,1),
    signature_hash  text NOT NULL,
    detail          jsonb NOT NULL DEFAULT '{}'::jsonb,
    integration_ticket_ids jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at      timestamptz NOT NULL DEFAULT now(),
    -- Dedup: one row per (workspace, target, normalized signature).
    -- Ingest path uses ON CONFLICT (workspace_id, target_id, signature_hash)
    -- DO UPDATE to refresh detail without spawning duplicates.
    CONSTRAINT findings_dedup UNIQUE (workspace_id, target_id, signature_hash)
);
-- +goose StatementEnd

-- +goose StatementBegin
ALTER TABLE findings ENABLE ROW LEVEL SECURITY;
-- +goose StatementEnd
-- +goose StatementBegin
ALTER TABLE findings FORCE ROW LEVEL SECURITY;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE POLICY findings_tenant_isolation ON findings
    USING (workspace_id = current_setting('app.workspace_id', true)::uuid);
-- +goose StatementEnd

-- Hot dashboard indexes (design.md → Critical indexes summary).
-- +goose StatementBegin
CREATE INDEX findings_workspace_severity_status_idx
    ON findings (workspace_id, severity, status);
-- +goose StatementEnd
-- +goose StatementBegin
CREATE INDEX findings_scan_idx
    ON findings (scan_id);
-- +goose StatementEnd
-- +goose StatementBegin
CREATE INDEX findings_workspace_created_idx
    ON findings (workspace_id, created_at DESC);
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TABLE reports (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id          uuid NOT NULL,
    workspace_id    uuid NOT NULL,
    scan_id         uuid UNIQUE NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    s3_key          text NOT NULL,
    bytes           bigint NOT NULL DEFAULT 0,
    sha256          bytea NOT NULL,
    watermark       boolean NOT NULL DEFAULT false,
    generated_at    timestamptz NOT NULL DEFAULT now()
);
-- +goose StatementEnd

-- +goose StatementBegin
ALTER TABLE reports ENABLE ROW LEVEL SECURITY;
-- +goose StatementEnd
-- +goose StatementBegin
ALTER TABLE reports FORCE ROW LEVEL SECURITY;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE POLICY reports_tenant_isolation ON reports
    USING (workspace_id = current_setting('app.workspace_id', true)::uuid);
-- +goose StatementEnd

-- Hot list index (design.md → Critical indexes summary).
-- +goose StatementBegin
CREATE INDEX reports_workspace_generated_idx
    ON reports (workspace_id, generated_at DESC);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS reports;
-- +goose StatementEnd
-- +goose StatementBegin
DROP TABLE IF EXISTS findings;
-- +goose StatementEnd
-- +goose StatementBegin
DROP TABLE IF EXISTS scan_event_archive;
-- +goose StatementEnd
-- +goose StatementBegin
DROP TABLE IF EXISTS scans;
-- +goose StatementEnd
