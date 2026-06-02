-- Placeholder initial migration.
--
-- This file exists so that `//go:embed migrations/*.sql` (see ../migrations.go)
-- has at least one match at compile time. The real schema is added by
-- xalgorix-saas spec tasks 1.2 through 1.10, each of which contributes a
-- versioned `NNNNNNNNNNNNNN_<name>.sql` file alongside this one.
--
-- Convention: timestamp-prefixed names sort lexicographically and let goose
-- run them in deterministic order regardless of filesystem ordering.

-- +goose Up
-- +goose StatementBegin
SELECT 1;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
SELECT 1;
-- +goose StatementEnd
