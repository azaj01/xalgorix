package reports

import (
	"context"
	"errors"
	"io"
	"sync"
	"time"

	"github.com/xalgord/xalgorix/v4/internal/cloud/storage"
)

// testOrgID and testWorkspaceID are the canonical tenancy identifiers
// reused across the test files in this package. They are the (org,
// workspace) pair the [fakeStorage] fixture is implicitly bound to —
// every Put assertion expects the upload key to start with the
// `KeyPrefix(testOrgID, testWorkspaceID)` prefix.
const (
	testOrgID       = "00000000-0000-4000-8000-0000000000aa"
	testWorkspaceID = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
)

// fakeStorage is the in-memory [storage.Storage] used by every test in
// this package (logo upload + worker-wrapper PDF generation). It
// records every Put so assertions can inspect the metadata, key, and
// body, and can be programmed to return a custom error (e.g.
// [storage.ErrInfected], [storage.ErrTenantIsolationViolation]) to
// exercise the rejection paths.
//
// The struct is intentionally tiny — Get/Presign/Delete return a
// not-implemented sentinel so any test that accidentally takes a
// dependency on them fails loudly rather than silently passing.
type fakeStorage struct {
	mu       sync.Mutex
	puts     []fakePut
	putError error
}

// fakePut is the recorded shape of a single [fakeStorage.Put]
// invocation. Tests assert against Key, Body, and Meta to verify the
// per-tenant key shape, the rendered PDF bytes, and the user metadata
// (sha256, scan_id, plan).
type fakePut struct {
	Key  string
	Body []byte
	Meta storage.Meta
}

// Put implements [storage.Storage]. The fake buffers the body so test
// assertions can compare the bytes the handler ultimately persisted
// against the expected (post-sanitization) payload.
func (f *fakeStorage) Put(_ context.Context, key string, body io.Reader, meta storage.Meta) error {
	if f.putError != nil {
		return f.putError
	}
	buf, err := io.ReadAll(body)
	if err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.puts = append(f.puts, fakePut{Key: key, Body: buf, Meta: meta})
	return nil
}

// Get / Presign / Delete are not exercised by the tests in this
// package — surfacing them as not-implemented makes any future test
// that accidentally takes a dependency on them fail loudly.
func (f *fakeStorage) Get(_ context.Context, _ string) (io.ReadCloser, error) {
	return nil, errors.New("fakeStorage: Get not implemented in tests")
}

func (f *fakeStorage) Presign(_ context.Context, _ string, _ time.Duration) (string, error) {
	return "", errors.New("fakeStorage: Presign not implemented in tests")
}

func (f *fakeStorage) Delete(_ context.Context, _ string) error {
	return errors.New("fakeStorage: Delete not implemented in tests")
}

// snapshot returns a copy of the recorded Put log under the lock so
// callers can range over it safely even if a parallel test has already
// queued additional uploads.
func (f *fakeStorage) snapshot() []fakePut {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]fakePut, len(f.puts))
	copy(out, f.puts)
	return out
}

// Compile-time check that fakeStorage satisfies the storage.Storage
// interface so the production type and the test fake stay in lock-step.
var _ storage.Storage = (*fakeStorage)(nil)
