-- Migration 20250101000600_api_keys_webhooks_integrations
--
-- xalgorix-saas spec — task 1.7
--   Creates the API_Key, Webhook, Webhook_Delivery, and Integration
--   tables defined in design.md → "Data Models" → "API keys, webhooks,
--   integrations". RLS is enabled and forced on every table; the
--   canonical `<table>_tenant_isolation` policy keys on the per-request
--   `app.workspace_id` GUC set by the tenancy middleware
--   (`internal/cloud/tenancy`).
--
--   The dispatch worker pool (`internal/cloud/webhooks`) walks
--   `webhook_deliveries` ordered by `next_attempt_at` with
--   `SELECT ... FOR UPDATE SKIP LOCKED`. The partial index
--   `webhook_deliveries_due_idx` keeps that picker fast by indexing
--   only rows that have neither succeeded nor terminally failed yet.
--
-- Requirements: 8.3, 8.6, 9.1, 9.2

-- +goose Up
-- +goose StatementBegin

-- ------------------------------------------------------------
-- API keys
-- ------------------------------------------------------------
CREATE TABLE api_keys (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id          uuid NOT NULL,
    workspace_id    uuid NOT NULL,
    name            text NOT NULL,
    prefix          text NOT NULL,                -- xal_live_xxxx or xal_test_xxxx (head)
    last4           text NOT NULL,
    secret_hash     text NOT NULL,                -- Argon2id
    scopes          text[] NOT NULL,
    created_by      uuid NOT NULL REFERENCES accounts(id),
    created_at      timestamptz NOT NULL DEFAULT now(),
    last_used_at    timestamptz,
    revoked_at      timestamptz
);

ALTER TABLE api_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE api_keys FORCE  ROW LEVEL SECURITY;

CREATE POLICY api_keys_tenant_isolation ON api_keys
    USING (workspace_id = current_setting('app.workspace_id', true)::uuid);

CREATE INDEX api_keys_prefix_idx ON api_keys(prefix);

-- ------------------------------------------------------------
-- Webhooks
-- ------------------------------------------------------------
CREATE TABLE webhooks (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id          uuid NOT NULL,
    workspace_id    uuid NOT NULL,
    url             text NOT NULL,
    secret_enc      bytea NOT NULL,
    event_types     text[] NOT NULL,
    status          text NOT NULL DEFAULT 'active'
                    CHECK (status IN ('active','disabled','needs_reconnect')),
    created_at      timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE webhooks ENABLE ROW LEVEL SECURITY;
ALTER TABLE webhooks FORCE  ROW LEVEL SECURITY;

CREATE POLICY webhooks_tenant_isolation ON webhooks
    USING (workspace_id = current_setting('app.workspace_id', true)::uuid);

-- ------------------------------------------------------------
-- Webhook deliveries (dispatcher work queue)
-- ------------------------------------------------------------
CREATE TABLE webhook_deliveries (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    webhook_id      uuid NOT NULL REFERENCES webhooks(id) ON DELETE CASCADE,
    org_id          uuid NOT NULL,
    workspace_id    uuid NOT NULL,
    event_id        uuid NOT NULL,
    event_type      text NOT NULL,
    payload         jsonb NOT NULL,
    attempt         int  NOT NULL DEFAULT 0,
    next_attempt_at timestamptz NOT NULL DEFAULT now(),
    last_status     int,
    last_error      text,
    succeeded_at    timestamptz,
    failed_at       timestamptz,
    created_at      timestamptz NOT NULL DEFAULT now()
);

-- Partial dispatch-picker index: only rows that are neither succeeded
-- nor terminally failed. The dispatcher (internal/cloud/webhooks) uses
-- `ORDER BY next_attempt_at FOR UPDATE SKIP LOCKED LIMIT 1` against
-- this exact predicate.
CREATE INDEX webhook_deliveries_due_idx
    ON webhook_deliveries(next_attempt_at)
    WHERE succeeded_at IS NULL AND failed_at IS NULL;

ALTER TABLE webhook_deliveries ENABLE ROW LEVEL SECURITY;
ALTER TABLE webhook_deliveries FORCE  ROW LEVEL SECURITY;

CREATE POLICY wd_tenant_isolation ON webhook_deliveries
    USING (workspace_id = current_setting('app.workspace_id', true)::uuid);

-- ------------------------------------------------------------
-- Integrations
-- ------------------------------------------------------------
CREATE TABLE integrations (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id          uuid NOT NULL,
    workspace_id    uuid NOT NULL,
    kind            text NOT NULL
                    CHECK (kind IN ('slack','discord','teams','jira','github','linear','agentmail','generic_webhook')),
    config          jsonb NOT NULL,
    encrypted_credentials bytea,                  -- KMS-envelope ciphertext
    status          text NOT NULL DEFAULT 'active'
                    CHECK (status IN ('active','needs_reconnect','disabled')),
    created_at      timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE integrations ENABLE ROW LEVEL SECURITY;
ALTER TABLE integrations FORCE  ROW LEVEL SECURITY;

CREATE POLICY integrations_tenant_isolation ON integrations
    USING (workspace_id = current_setting('app.workspace_id', true)::uuid);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP TABLE IF EXISTS integrations;
DROP TABLE IF EXISTS webhook_deliveries;
DROP TABLE IF EXISTS webhooks;
DROP TABLE IF EXISTS api_keys;

-- +goose StatementEnd
