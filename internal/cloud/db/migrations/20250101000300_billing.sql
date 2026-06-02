-- Billing tables for the Xalgorix Cloud_Platform.
--
-- Implements task 1.4 of the `xalgorix-saas` spec. Mirrors the
-- "Billing" block of design.md → "Data Models" verbatim, with the
-- explicit additions called out by the task description:
--
--   * CHECK constraint on `subscriptions.status` covering the full
--     subscription state machine (trialing → active → past_due →
--     grace → downgraded → canceled) so the database refuses to
--     persist any state outside what the billing package can produce.
--   * CHECK constraint on `subscriptions.period` so callers cannot
--     accidentally persist a billing cadence other than monthly /
--     annual.
--   * CHECK constraint on `invoices.status` covering the Dodo invoice
--     lifecycle the dunning cron consults (see design.md → "Trial and
--     Dunning"): `open`, `paid`, `unpaid`, `void`, `uncollectible`.
--   * UNIQUE / PRIMARY KEY guarantee on `dodo_webhook_events.event_id`
--     so the `INSERT … ON CONFLICT DO NOTHING` ledger stays idempotent
--     across retries (design.md → "Dodo webhook ingestion").
--
-- RLS follows the canonical `<table>_tenant_isolation` pattern from
-- design.md → "Data Models". `subscriptions` and `invoices` are
-- org-scoped (one Subscription per Organization, invoices belong to
-- an Organization), so their policies match the
-- `app.organization_id` GUC. `dodo_webhook_events` is a
-- platform-global idempotency ledger with no `org_id` column and is
-- therefore intentionally not tenant-isolated; only the privileged
-- `app_admin` role / webhook handler writes to it.
--
-- Requirements: 5.1, 5.3, 5.9, 5.12.

-- +goose Up
-- +goose StatementBegin
CREATE TABLE subscriptions (
    id                   uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id               uuid UNIQUE NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    dodo_customer_id     text NOT NULL,
    dodo_subscription_id text UNIQUE,
    plan                 text NOT NULL,
    period               text NOT NULL CHECK (period IN ('monthly','annual')),
    status               text NOT NULL CHECK (status IN (
                             'trialing',
                             'active',
                             'past_due',
                             'grace',
                             'downgraded',
                             'canceled'
                         )),
    seats                int  NOT NULL DEFAULT 1,
    current_period_start timestamptz,
    current_period_end   timestamptz,
    trial_ends_at        timestamptz,
    created_at           timestamptz NOT NULL DEFAULT now(),
    updated_at           timestamptz NOT NULL DEFAULT now()
);
-- +goose StatementEnd

-- +goose StatementBegin
ALTER TABLE subscriptions ENABLE ROW LEVEL SECURITY;
-- +goose StatementEnd

-- +goose StatementBegin
ALTER TABLE subscriptions FORCE  ROW LEVEL SECURITY;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE POLICY subscriptions_tenant_isolation ON subscriptions
    USING (org_id = current_setting('app.organization_id', true)::uuid);
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TABLE invoices (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id          uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    dodo_invoice_id text UNIQUE NOT NULL,
    amount_cents    bigint NOT NULL,
    currency        text NOT NULL DEFAULT 'usd',
    status          text NOT NULL CHECK (status IN (
                        'open',
                        'paid',
                        'unpaid',
                        'void',
                        'uncollectible'
                    )),
    issued_at       timestamptz NOT NULL,
    paid_at         timestamptz,
    pdf_url         text
);
-- +goose StatementEnd

-- +goose StatementBegin
CREATE INDEX invoices_org_issued_idx ON invoices(org_id, issued_at DESC);
-- +goose StatementEnd

-- +goose StatementBegin
ALTER TABLE invoices ENABLE ROW LEVEL SECURITY;
-- +goose StatementEnd

-- +goose StatementBegin
ALTER TABLE invoices FORCE  ROW LEVEL SECURITY;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE POLICY invoices_tenant_isolation ON invoices
    USING (org_id = current_setting('app.organization_id', true)::uuid);
-- +goose StatementEnd

-- +goose StatementBegin
-- Idempotency ledger for inbound Dodo webhooks. event_id is the
-- Dodo-assigned `event.id` — declaring it PRIMARY KEY both enforces
-- uniqueness (so `INSERT … ON CONFLICT DO NOTHING` is a no-op on
-- retry) and gives us the lookup index the webhook handler uses.
CREATE TABLE dodo_webhook_events (
    event_id     text PRIMARY KEY,
    event_type   text NOT NULL,
    received_at  timestamptz NOT NULL DEFAULT now(),
    processed_at timestamptz,
    payload      jsonb NOT NULL
);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS dodo_webhook_events;
-- +goose StatementEnd

-- +goose StatementBegin
DROP POLICY IF EXISTS invoices_tenant_isolation ON invoices;
-- +goose StatementEnd

-- +goose StatementBegin
DROP TABLE IF EXISTS invoices;
-- +goose StatementEnd

-- +goose StatementBegin
DROP POLICY IF EXISTS subscriptions_tenant_isolation ON subscriptions;
-- +goose StatementEnd

-- +goose StatementBegin
DROP TABLE IF EXISTS subscriptions;
-- +goose StatementEnd
