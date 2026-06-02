// Embedded `goose` migration loader for the Xalgorix Cloud_Platform.
//
// This file implements task 1.1 from the `xalgorix-saas` spec:
//
//   - `migrations/` is embedded via `//go:embed` so the cloud binary can
//     run schema migrations without shipping loose .sql files.
//   - [Migrations] returns the embedded filesystem rooted at
//     `migrations/` so callers (the `make migrate-up`/`make migrate-down`
//     targets and any future test harness) can drive `goose` without
//     reaching into package internals.
//   - [MigrateUp] and [MigrateDown] wrap the goose v3 API against the
//     embedded FS and a caller-provided *sql.DB.
//
// Subsequent tasks (1.2 through 1.10) populate `migrations/` with the
// real schema described in design.md → "Data Models".
//
// Requirements: 13.1, 13.2.

package db

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"io/fs"

	"github.com/pressly/goose/v3"
)

// migrationsFS embeds every SQL file under `migrations/`. The pattern
// must match at least one file at compile time — `migrations/00000000000000_init.sql`
// is committed for that reason and is replaced by the real initial
// schema in task 1.2.
//
//go:embed migrations/*.sql
var migrationsFS embed.FS

// migrationsDir is the embedded subdirectory that goose treats as its
// migration source root. It is exported as a constant so tests and
// migration command-line tooling can stay in sync.
const migrationsDir = "migrations"

// Migrations returns the embedded migrations filesystem rooted at
// `migrations/`. Callers typically pass it to goose via
// [goose.SetBaseFS] or read it directly to drive their own runners.
func Migrations() fs.FS {
	sub, err := fs.Sub(migrationsFS, migrationsDir)
	if err != nil {
		// fs.Sub only fails when the path does not exist or is invalid;
		// since `migrationsDir` is a compile-time constant matching the
		// embed pattern, this branch is unreachable in practice.
		panic(fmt.Errorf("cloud/db: embedded migrations FS missing %q: %w", migrationsDir, err))
	}
	return sub
}

// MigrateUp applies every pending migration to db using the embedded
// filesystem. It is safe to call repeatedly; goose tracks state in the
// `goose_db_version` table.
func MigrateUp(ctx context.Context, db *sql.DB) error {
	if db == nil {
		return fmt.Errorf("cloud/db: MigrateUp requires a non-nil *sql.DB")
	}
	provider, err := newGooseProvider(db)
	if err != nil {
		return err
	}
	if err := provider.UpContext(ctx, db, migrationsDir); err != nil {
		return fmt.Errorf("cloud/db: migrate up: %w", err)
	}
	return nil
}

// MigrateDown rolls back the most recently applied migration. The
// matching `make migrate-down` target invokes the goose CLI directly
// for parity with operator tooling; this helper exists so tests and
// embedded callers do not need to shell out.
func MigrateDown(ctx context.Context, db *sql.DB) error {
	if db == nil {
		return fmt.Errorf("cloud/db: MigrateDown requires a non-nil *sql.DB")
	}
	provider, err := newGooseProvider(db)
	if err != nil {
		return err
	}
	if err := provider.DownContext(ctx, db, migrationsDir); err != nil {
		return fmt.Errorf("cloud/db: migrate down: %w", err)
	}
	return nil
}

// gooseProvider is the small subset of the goose package surface we
// rely on. Wrapping it behind an interface keeps tests free of network
// or database fixtures while still exercising the embed wiring.
type gooseProvider interface {
	UpContext(ctx context.Context, db *sql.DB, dir string, opts ...goose.OptionsFunc) error
	DownContext(ctx context.Context, db *sql.DB, dir string, opts ...goose.OptionsFunc) error
}

// gooseGlobal is the default provider backed by goose's package-level
// state. It is overridable in tests.
type gooseGlobal struct{}

func (gooseGlobal) UpContext(ctx context.Context, db *sql.DB, dir string, opts ...goose.OptionsFunc) error {
	return goose.UpContext(ctx, db, dir, opts...)
}

func (gooseGlobal) DownContext(ctx context.Context, db *sql.DB, dir string, opts ...goose.OptionsFunc) error {
	return goose.DownContext(ctx, db, dir, opts...)
}

// newGooseProvider configures the global goose package to read from the
// embedded migrations FS and returns a thin wrapper that exposes the
// up/down operations.
func newGooseProvider(_ *sql.DB) (gooseProvider, error) {
	goose.SetBaseFS(migrationsFS)
	if err := goose.SetDialect("postgres"); err != nil {
		return nil, fmt.Errorf("cloud/db: set goose dialect: %w", err)
	}
	return gooseGlobal{}, nil
}
