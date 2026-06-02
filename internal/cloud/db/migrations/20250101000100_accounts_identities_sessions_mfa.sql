-- Accounts, identities, sessions, and MFA.
--
-- Implements task 1.2 of the xalgorix-saas spec. The DDL mirrors the
-- "Accounts and identities" block in design.md verbatim. Extensions are
-- created up-front because the schema relies on `citext` (case-insensitive
-- email column) and `pgcrypto` (`gen_random_uuid()` defaults).
--
-- Requirements: 3.1, 3.2, 3.6, 3.7, 3.10.

-- +goose Up
-- +goose StatementBegin
CREATE EXTENSION IF NOT EXISTS citext;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE EXTENSION IF NOT EXISTS pgcrypto;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TABLE accounts (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    email           citext UNIQUE NOT NULL,
    password_hash   text,
    status          text NOT NULL CHECK (status IN ('pending_verification','active','suspended','deleted')),
    is_admin_operator boolean NOT NULL DEFAULT false,
    locale          text NOT NULL DEFAULT 'en',
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    last_signin_at  timestamptz
);
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TABLE account_identities (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    account_id      uuid NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    provider        text NOT NULL CHECK (provider IN ('google','github','saml','oidc')),
    subject         text NOT NULL,
    email_verified  boolean NOT NULL DEFAULT false,
    created_at      timestamptz NOT NULL DEFAULT now(),
    UNIQUE (provider, subject)
);
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TABLE account_mfa (
    account_id      uuid PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,
    totp_secret_enc bytea NOT NULL,
    recovery_codes  text[] NOT NULL,
    enabled_at      timestamptz NOT NULL DEFAULT now()
);
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TABLE sessions (
    id              text PRIMARY KEY,           -- opaque session id
    account_id      uuid NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    issued_at       timestamptz NOT NULL DEFAULT now(),
    last_seen_at    timestamptz NOT NULL DEFAULT now(),
    expires_at      timestamptz NOT NULL,
    user_agent      text,
    ip              inet
);
-- +goose StatementEnd

-- +goose StatementBegin
CREATE INDEX sessions_account_idx ON sessions(account_id);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS sessions_account_idx;
-- +goose StatementEnd

-- +goose StatementBegin
DROP TABLE IF EXISTS sessions;
-- +goose StatementEnd

-- +goose StatementBegin
DROP TABLE IF EXISTS account_mfa;
-- +goose StatementEnd

-- +goose StatementBegin
DROP TABLE IF EXISTS account_identities;
-- +goose StatementEnd

-- +goose StatementBegin
DROP TABLE IF EXISTS accounts;
-- +goose StatementEnd
