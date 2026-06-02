package db

import (
	"errors"
	"io/fs"
	"strings"
	"testing"
)

// TestMigrationsEmbedFS asserts that the `//go:embed migrations/*.sql`
// directive in migrations.go actually wired the filesystem at compile
// time. If the directory is renamed or the embed pattern stops matching
// any file, this test fails before the cloud binary tries to run a
// migration in production.
//
// Validates: requirements 13.1, 13.2 (xalgorix-saas spec, task 1.1).
func TestMigrationsEmbedFS(t *testing.T) {
	t.Parallel()

	mfs := Migrations()
	if mfs == nil {
		t.Fatal("Migrations() returned nil filesystem")
	}

	entries, err := fs.ReadDir(mfs, ".")
	if err != nil {
		t.Fatalf("read root of embedded migrations FS: %v", err)
	}

	var sqlFiles int
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		if strings.HasSuffix(entry.Name(), ".sql") {
			sqlFiles++
		}
	}
	if sqlFiles == 0 {
		t.Fatalf("no .sql files were embedded under migrations/ (entries=%d)", len(entries))
	}
}

// TestMigrationsContainPlaceholderInit ensures the placeholder initial
// migration committed alongside this task survives until task 1.2 lands
// the real initial schema. Once 1.2 introduces a versioned filename, it
// is expected to replace the placeholder, at which point this test
// should be updated to look for the real schema.
func TestMigrationsContainPlaceholderInit(t *testing.T) {
	t.Parallel()

	mfs := Migrations()
	data, err := fs.ReadFile(mfs, "00000000000000_init.sql")
	if err != nil {
		// If the placeholder has been removed but other migrations
		// exist, surface a clearer message than fs.ErrNotExist.
		if errors.Is(err, fs.ErrNotExist) {
			t.Skip("placeholder init migration replaced; update this test alongside task 1.2")
		}
		t.Fatalf("read placeholder init migration: %v", err)
	}
	if !strings.Contains(string(data), "+goose Up") {
		t.Fatalf("placeholder init migration missing goose Up directive: %q", string(data))
	}
}

// TestMigrateUpRequiresDB documents the contract that MigrateUp refuses
// a nil database handle rather than panicking inside the goose package.
func TestMigrateUpRequiresDB(t *testing.T) {
	t.Parallel()

	if err := MigrateUp(t.Context(), nil); err == nil {
		t.Fatal("MigrateUp(nil) must return an error")
	}
}

// TestMigrateDownRequiresDB mirrors TestMigrateUpRequiresDB for the
// reverse direction.
func TestMigrateDownRequiresDB(t *testing.T) {
	t.Parallel()

	if err := MigrateDown(t.Context(), nil); err == nil {
		t.Fatal("MigrateDown(nil) must return an error")
	}
}
