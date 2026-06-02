-- xalgorix-saas migration 1.10:
-- feature flags, global kill switch, announcements + dismissals,
-- per-cycle usage meters, and per-account onboarding progress.
--
-- Sources:
--   * design.md → "Data Models" → "Audit (immutable), feature flags,
--     kill switch, announcements" block.
--   * design.md → "Data Models" → "Usage metering and onboarding" block.
--
-- RLS posture (design.md → "Data Models" preamble, lines 461–468):
--   * Tenant-scoped tables (`feature_flags`, `usage_meters`,
--     `onboarding_progress`) carry `org_id NOT NULL` and get the
--     canonical `<table>_tenant_isolation` policy keyed on the
--     `app.organization_id` GUC, with both ENABLE and FORCE RLS.
--   * `kill_switch` and `announcements` are platform-global
--     (admin/back-office surfaces, served from
--     https://admin.xalgorix.com per Requirement 11.1) and therefore
--     deliberately have no RLS.
--   * `announcement_dismissals` is keyed on `account_id` only and is
--     served by the per-account Dashboard endpoint (Requirement 16.3);
--     it has no `org_id` column and therefore no tenant policy.
--
-- Requirements: 11.4, 11.5, 11.8, 15.1, 15.5, 16.1.

-- +goose Up
-- +goose StatementBegin

-- ------------------------------------------------------------
-- Per-Org feature flags (Requirement 11.4)
-- ------------------------------------------------------------
CREATE TABLE feature_flags (
    org_id          uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    key             text NOT NULL,
    value           jsonb NOT NULL,
    updated_at      timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, key)
);
ALTER TABLE feature_flags ENABLE ROW LEVEL SECURITY;
ALTER TABLE feature_flags FORCE  ROW LEVEL SECURITY;
CREATE POLICY feature_flags_tenant_isolation ON feature_flags
    USING (org_id = current_setting('app.organization_id', true)::uuid);

-- ------------------------------------------------------------
-- Singleton global kill switch (Requirement 11.5)
--
-- The boolean PK + CHECK (id) trick guarantees at most one row ever
-- exists: the only legal value for `id` is TRUE, and the PK forbids a
-- second TRUE. Admin-toggle code therefore upserts via
-- `UPDATE kill_switch SET enabled=...` against the single bootstrap row.
-- ------------------------------------------------------------
CREATE TABLE kill_switch (
    id              boolean PRIMARY KEY DEFAULT true CHECK (id),
    enabled         boolean NOT NULL DEFAULT false,
    reason          text,
    updated_by      uuid,
    updated_at      timestamptz NOT NULL DEFAULT now()
);
INSERT INTO kill_switch DEFAULT VALUES;

-- ------------------------------------------------------------
-- Changelog announcements + per-account dismissals
-- (Requirements 16.1, 16.3)
-- ------------------------------------------------------------
CREATE TABLE announcements (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    title           text NOT NULL,
    body_md         text NOT NULL,
    category        text NOT NULL CHECK (category IN ('new','improved','fixed','security')),
    published_at    timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE announcement_dismissals (
    account_id      uuid NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    announcement_id uuid NOT NULL REFERENCES announcements(id) ON DELETE CASCADE,
    dismissed_at    timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (account_id, announcement_id)
);

-- ------------------------------------------------------------
-- Per-cycle usage meters (Requirement 11.8 → suspended Orgs are
-- inspected via this surface; design's overage and metering logic
-- joins here).
-- ------------------------------------------------------------
CREATE TABLE usage_meters (
    org_id          uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    period_start    date NOT NULL,
    period_end      date NOT NULL,
    metric          text NOT NULL CHECK (metric IN ('scans','overage_scans','seats')),
    value           bigint NOT NULL DEFAULT 0,
    submitted_to_dodo_at timestamptz,
    PRIMARY KEY (org_id, period_start, metric)
);
ALTER TABLE usage_meters ENABLE ROW LEVEL SECURITY;
ALTER TABLE usage_meters FORCE  ROW LEVEL SECURITY;
CREATE POLICY usage_meters_tenant_isolation ON usage_meters
    USING (org_id = current_setting('app.organization_id', true)::uuid);

-- ------------------------------------------------------------
-- Per-account onboarding progress (Requirements 15.1, 15.5)
-- ------------------------------------------------------------
CREATE TABLE onboarding_progress (
    account_id      uuid PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,
    org_id          uuid NOT NULL,
    verified_target boolean NOT NULL DEFAULT false,
    created_scan    boolean NOT NULL DEFAULT false,
    invited_member  boolean NOT NULL DEFAULT false,
    configured_integration boolean NOT NULL DEFAULT false,
    set_notifications boolean NOT NULL DEFAULT false,
    completed_at    timestamptz,
    updated_at      timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE onboarding_progress ENABLE ROW LEVEL SECURITY;
ALTER TABLE onboarding_progress FORCE  ROW LEVEL SECURITY;
CREATE POLICY onboarding_progress_tenant_isolation ON onboarding_progress
    USING (org_id = current_setting('app.organization_id', true)::uuid);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP TABLE IF EXISTS onboarding_progress;
DROP TABLE IF EXISTS usage_meters;
DROP TABLE IF EXISTS announcement_dismissals;
DROP TABLE IF EXISTS announcements;
DROP TABLE IF EXISTS kill_switch;
DROP TABLE IF EXISTS feature_flags;

-- +goose StatementEnd
