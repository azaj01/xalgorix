-- xalgorix-saas spec — task 1.3
-- Organizations, workspaces, members, invites with PostgreSQL Row-Level
-- Security keyed on the `app.organization_id` GUC set by the per-request
-- transactional middleware in `internal/cloud/tenancy`.
--
-- DDL is reproduced exactly from `design.md → Data Models → Organizations
-- / workspaces / membership`. Each tenant-scoped table is `ENABLE`d **and**
-- `FORCE`d so RLS applies even to table owners, and each gets a single
-- canonical policy named `<table>_tenant_isolation` matching on the
-- organization GUC. The `current_setting(..., true)` form returns NULL
-- instead of erroring when the GUC has not been set, which lets goose run
-- the migration outside of a tenant context.
--
-- Depends on `20250101000100_accounts.sql` (task 1.2) for the
-- `accounts(id)` foreign key and the `citext` extension. Both are guarded
-- with IF NOT EXISTS so this migration is replay-safe under tooling that
-- recreates the schema piecewise.
--
-- Requirements: 1.1, 1.2, 4.1, 4.2, 4.3, 4.7, 4.10.

-- +goose Up
-- +goose StatementBegin
CREATE EXTENSION IF NOT EXISTS citext;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE EXTENSION IF NOT EXISTS pgcrypto;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TABLE organizations (
    id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name                text NOT NULL,
    slug                citext UNIQUE NOT NULL,
    region              text NOT NULL CHECK (region IN ('us-east-1','eu-west-1')),
    plan                text NOT NULL DEFAULT 'free' CHECK (plan IN ('free','pro','team','enterprise')),
    status              text NOT NULL DEFAULT 'active' CHECK (status IN ('active','past_due','suspended','pending_delete')),
    overage_enabled     boolean NOT NULL DEFAULT false,
    sso_required_domain citext,
    timezone            text NOT NULL DEFAULT 'UTC',
    created_at          timestamptz NOT NULL DEFAULT now()
);
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TABLE workspaces (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id      uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name        text NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    UNIQUE (org_id, name)
);
-- +goose StatementEnd

-- +goose StatementBegin
ALTER TABLE workspaces ENABLE ROW LEVEL SECURITY;
-- +goose StatementEnd

-- +goose StatementBegin
ALTER TABLE workspaces FORCE  ROW LEVEL SECURITY;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE POLICY workspaces_tenant_isolation ON workspaces
    USING (org_id = current_setting('app.organization_id', true)::uuid);
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TABLE members (
    org_id           uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    account_id       uuid NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    role             text NOT NULL CHECK (role IN ('owner','admin','member','viewer')),
    workspace_access uuid[] NOT NULL DEFAULT ARRAY[]::uuid[],
    created_at       timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, account_id)
);
-- +goose StatementEnd

-- +goose StatementBegin
ALTER TABLE members ENABLE ROW LEVEL SECURITY;
-- +goose StatementEnd

-- +goose StatementBegin
ALTER TABLE members FORCE  ROW LEVEL SECURITY;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE POLICY members_tenant_isolation ON members
    USING (org_id = current_setting('app.organization_id', true)::uuid);
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TABLE invites (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id      uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    email       citext NOT NULL,
    role        text NOT NULL CHECK (role IN ('admin','member','viewer')),
    token_hash  text NOT NULL,
    invited_by  uuid NOT NULL REFERENCES accounts(id),
    expires_at  timestamptz NOT NULL,
    accepted_at timestamptz,
    revoked_at  timestamptz,
    created_at  timestamptz NOT NULL DEFAULT now()
);
-- +goose StatementEnd

-- +goose StatementBegin
CREATE UNIQUE INDEX invites_org_email_pending_idx
    ON invites(org_id, email)
    WHERE accepted_at IS NULL AND revoked_at IS NULL;
-- +goose StatementEnd

-- +goose StatementBegin
ALTER TABLE invites ENABLE ROW LEVEL SECURITY;
-- +goose StatementEnd

-- +goose StatementBegin
ALTER TABLE invites FORCE  ROW LEVEL SECURITY;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE POLICY invites_tenant_isolation ON invites
    USING (org_id = current_setting('app.organization_id', true)::uuid);
-- +goose StatementEnd


-- +goose Down
-- +goose StatementBegin
DROP POLICY IF EXISTS invites_tenant_isolation ON invites;
-- +goose StatementEnd

-- +goose StatementBegin
DROP INDEX IF EXISTS invites_org_email_pending_idx;
-- +goose StatementEnd

-- +goose StatementBegin
DROP TABLE IF EXISTS invites;
-- +goose StatementEnd

-- +goose StatementBegin
DROP POLICY IF EXISTS members_tenant_isolation ON members;
-- +goose StatementEnd

-- +goose StatementBegin
DROP TABLE IF EXISTS members;
-- +goose StatementEnd

-- +goose StatementBegin
DROP POLICY IF EXISTS workspaces_tenant_isolation ON workspaces;
-- +goose StatementEnd

-- +goose StatementBegin
DROP TABLE IF EXISTS workspaces;
-- +goose StatementEnd

-- +goose StatementBegin
DROP TABLE IF EXISTS organizations;
-- +goose StatementEnd
