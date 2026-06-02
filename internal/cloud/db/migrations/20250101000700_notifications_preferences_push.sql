-- xalgorix-saas spec — task 1.8
-- Notifications, per-Account preferences, and Web Push subscriptions.
--
-- DDL is reproduced verbatim from `design.md → Data Models →
-- Notifications and push`. The unread partial index
-- `notifications_account_unread_idx` is the hot-path lookup that powers
-- the unread badge and the SSE counter feed described in
-- `internal/cloud/notifications` (design.md), and is enumerated in the
-- "Critical indexes summary" table.
--
-- Tenant-isolation RLS is applied to `notifications` because rows carry
-- an `org_id` that locates the notification within a single tenant; the
-- policy keys on the `app.organization_id` GUC the way every other
-- tenant-scoped table in the schema does (matching the convention
-- introduced in `20250101000200_organizations_workspaces_members_invites.sql`).
-- `notification_preferences` and `push_subscriptions` are keyed on
-- `account_id` only and therefore inherit isolation from the account
-- relationship; design.md does not list RLS for them, so none is added
-- here.
--
-- Depends on the accounts migration (task 1.2) for the `accounts(id)`
-- foreign keys and the `pgcrypto` extension that supplies
-- `gen_random_uuid()`.
--
-- Requirements: 10.1, 10.2, 10.4.

-- +goose Up
-- +goose StatementBegin
CREATE EXTENSION IF NOT EXISTS pgcrypto;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TABLE notifications (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    account_id      uuid NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    org_id          uuid NOT NULL,
    event_type      text NOT NULL,
    payload         jsonb NOT NULL,
    read_at         timestamptz,
    created_at      timestamptz NOT NULL DEFAULT now()
);
-- +goose StatementEnd

-- +goose StatementBegin
CREATE INDEX notifications_account_unread_idx
    ON notifications(account_id, created_at DESC)
    WHERE read_at IS NULL;
-- +goose StatementEnd

-- +goose StatementBegin
ALTER TABLE notifications ENABLE ROW LEVEL SECURITY;
-- +goose StatementEnd

-- +goose StatementBegin
ALTER TABLE notifications FORCE  ROW LEVEL SECURITY;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE POLICY notifications_tenant_isolation ON notifications
    USING (org_id = current_setting('app.organization_id', true)::uuid);
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TABLE notification_preferences (
    account_id      uuid NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    event_type      text NOT NULL,
    channel         text NOT NULL CHECK (channel IN ('inapp','email','push')),
    enabled         boolean NOT NULL DEFAULT true,
    PRIMARY KEY (account_id, event_type, channel)
);
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TABLE push_subscriptions (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    account_id      uuid NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    endpoint        text NOT NULL,
    p256dh          text NOT NULL,
    auth            text NOT NULL,
    user_agent      text,
    created_at      timestamptz NOT NULL DEFAULT now(),
    UNIQUE (account_id, endpoint)
);
-- +goose StatementEnd


-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS push_subscriptions;
-- +goose StatementEnd

-- +goose StatementBegin
DROP TABLE IF EXISTS notification_preferences;
-- +goose StatementEnd

-- +goose StatementBegin
DROP POLICY IF EXISTS notifications_tenant_isolation ON notifications;
-- +goose StatementEnd

-- +goose StatementBegin
DROP INDEX IF EXISTS notifications_account_unread_idx;
-- +goose StatementEnd

-- +goose StatementBegin
DROP TABLE IF EXISTS notifications;
-- +goose StatementEnd
