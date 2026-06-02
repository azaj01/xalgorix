-- xalgorix-saas / Phase 1 / Task 1.9 — Migration: immutable audit_events.
--
-- Implements the append-only, tenant-isolated audit log called for in
-- design.md "Data Models → Audit (immutable)" and "Compliance and Data
-- Residency → Audit immutability". This migration:
--
--   * Creates a NOLOGIN application role `app` (idempotent) that is the
--     only grantee allowed to read or insert audit rows.
--   * Creates the `audit_events` table with the columns and indexes
--     enumerated in design.md. The hot indexes are organization-leading
--     so they satisfy both the per-tenant Audit log viewer (Requirement
--     13.6) and the tenant isolation policy below.
--   * Revokes everything from PUBLIC and grants `SELECT, INSERT` (and
--     only those) to `app`. PostgreSQL has no DDL knob to forbid UPDATE
--     and DELETE outright, so withholding the grants is the first line
--     of defence. A trigger guard added in a later phase makes the
--     immutability invariant from Requirement 13.7 absolute.
--   * Enables and FORCEs row-level security keyed on the per-request
--     GUC `app.organization_id` set by the tenancy middleware, so even a
--     row with the right GRANT can never leak across organizations.
--
-- Requirements: 13.5, 13.7.

-- +goose Up

-- Idempotent creation of the `app` role. We avoid Postgres 16's
-- `CREATE ROLE IF NOT EXISTS` so this migration runs against the 14/15
-- baselines documented in design.md.
-- +goose StatementBegin
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'app') THEN
        CREATE ROLE app NOINHERIT NOLOGIN;
    END IF;
END
$$;
-- +goose StatementEnd

CREATE TABLE audit_events (
    id               uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id  uuid        NOT NULL,
    actor_account_id uuid,
    actor_kind       text        NOT NULL
        CHECK (actor_kind IN ('account', 'api_key', 'system', 'admin', 'dodo')),
    action           text        NOT NULL,
    resource_type    text        NOT NULL,
    resource_id      text,
    request_id       text,
    ip               inet,
    user_agent       text,
    payload          jsonb       NOT NULL DEFAULT '{}'::jsonb,
    occurred_at      timestamptz NOT NULL DEFAULT now()
);

-- Per-tenant timeline (default Audit log viewer ordering).
CREATE INDEX audit_events_org_time_idx
    ON audit_events (organization_id, occurred_at DESC);

-- Per-tenant filter by action (Requirement 13.6 filters).
CREATE INDEX audit_events_org_action_time_idx
    ON audit_events (organization_id, action, occurred_at DESC);

-- Per-tenant filter by actor account.
CREATE INDEX audit_events_org_actor_time_idx
    ON audit_events (organization_id, actor_account_id, occurred_at DESC);

-- Privilege model: PUBLIC has nothing, `app` has SELECT + INSERT only.
-- The explicit `REVOKE UPDATE, DELETE` is redundant after `REVOKE ALL`
-- but is kept as living documentation of Requirement 13.7's intent.
REVOKE ALL              ON audit_events FROM PUBLIC;
REVOKE UPDATE, DELETE   ON audit_events FROM PUBLIC;
GRANT  SELECT, INSERT   ON audit_events TO app;

-- Tenant isolation enforced even for `app` (FORCE applies to owner too).
ALTER TABLE audit_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_events FORCE  ROW LEVEL SECURITY;

CREATE POLICY audit_events_tenant_isolation ON audit_events
    USING (organization_id = current_setting('app.organization_id')::uuid);


-- +goose Down

-- Drop the policy explicitly so re-running Up cleanly re-creates it
-- (DROP TABLE would cascade, but being explicit aids partial rollback
-- diagnostics if a future change adds dependent objects).
DROP POLICY IF EXISTS audit_events_tenant_isolation ON audit_events;

-- Revoke the grant from `app` only when both the role and the table
-- exist; either may have been dropped by a prior Down or by an operator
-- cleaning up a misbehaving environment. The role itself is left in
-- place because other migrations may grant additional privileges to it.
-- +goose StatementBegin
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'app')
       AND EXISTS (
            SELECT 1
            FROM pg_class c
            JOIN pg_namespace n ON n.oid = c.relnamespace
            WHERE c.relname = 'audit_events'
              AND c.relkind = 'r'
              AND n.nspname = current_schema()
       )
    THEN
        REVOKE SELECT, INSERT ON audit_events FROM app;
    END IF;
END
$$;
-- +goose StatementEnd

DROP TABLE IF EXISTS audit_events;
