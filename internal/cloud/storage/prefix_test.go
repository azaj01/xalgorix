package storage

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/s3"
)

const (
	testOrgA = "11111111-1111-1111-1111-111111111111"
	testOrgB = "22222222-2222-2222-2222-222222222222"
	testWsA  = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
	testWsB  = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
)

// TestValidateKey_HappyPath asserts a key under the canonical prefix is
// accepted.
//
// Validates: Requirements 1.5, 1.6.
func TestValidateKey_HappyPath(t *testing.T) {
	key := "org/" + testOrgA + "/workspace/" + testWsA + "/scan/abc/report.pdf"
	if err := ValidateKey(testOrgA, testWsA, key); err != nil {
		t.Fatalf("expected nil, got %v", err)
	}
}

// TestValidateKey_WrongOrg asserts a key for a different org is rejected
// with [ErrTenantIsolationViolation].
//
// Validates: Requirements 1.5, 1.6.
func TestValidateKey_WrongOrg(t *testing.T) {
	key := "org/" + testOrgB + "/workspace/" + testWsA + "/scan/abc/report.pdf"
	err := ValidateKey(testOrgA, testWsA, key)
	if !errors.Is(err, ErrTenantIsolationViolation) {
		t.Fatalf("expected ErrTenantIsolationViolation, got %v", err)
	}
}

// TestValidateKey_WrongWorkspace asserts a key for a different workspace
// inside the right org is still rejected.
//
// Validates: Requirements 1.5, 1.6.
func TestValidateKey_WrongWorkspace(t *testing.T) {
	key := "org/" + testOrgA + "/workspace/" + testWsB + "/scan/abc/report.pdf"
	err := ValidateKey(testOrgA, testWsA, key)
	if !errors.Is(err, ErrTenantIsolationViolation) {
		t.Fatalf("expected ErrTenantIsolationViolation, got %v", err)
	}
}

// TestValidateKey_RejectsBoundaryCases asserts the small but important
// edge cases (empty inputs, separator-stuffed ids, parent traversal,
// prefix-only keys) all return [ErrTenantIsolationViolation].
//
// Validates: Requirements 1.5, 1.6, 20.7.
func TestValidateKey_RejectsBoundaryCases(t *testing.T) {
	cases := []struct {
		name        string
		orgID       string
		workspaceID string
		key         string
	}{
		{"empty key", testOrgA, testWsA, ""},
		{"empty org", "", testWsA, "org//workspace/" + testWsA + "/x"},
		{"empty workspace", testOrgA, "", "org/" + testOrgA + "/workspace//x"},
		{"prefix only", testOrgA, testWsA, "org/" + testOrgA + "/workspace/" + testWsA + "/"},
		{"parent traversal", testOrgA, testWsA, "org/" + testOrgA + "/workspace/" + testWsA + "/../" + testWsB + "/x"},
		{"unrelated prefix", testOrgA, testWsA, "public/" + testOrgA + "/workspace/" + testWsA + "/x"},
		{"org id with separator", testOrgA + "/sneaky", testWsA, "org/" + testOrgA + "/sneaky/workspace/" + testWsA + "/x"},
		{"workspace id with separator", testOrgA, testWsA + "/sneaky", "org/" + testOrgA + "/workspace/" + testWsA + "/sneaky/x"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateKey(tc.orgID, tc.workspaceID, tc.key)
			if !errors.Is(err, ErrTenantIsolationViolation) {
				t.Fatalf("expected ErrTenantIsolationViolation, got %v", err)
			}
		})
	}
}

// TestKeyPrefix asserts the canonical prefix shape.
//
// Validates: Requirements 1.5, 1.6.
func TestKeyPrefix(t *testing.T) {
	got := KeyPrefix(testOrgA, testWsA)
	want := "org/" + testOrgA + "/workspace/" + testWsA + "/"
	if got != want {
		t.Fatalf("KeyPrefix = %q want %q", got, want)
	}
	if !strings.HasSuffix(got, "/") {
		t.Fatalf("KeyPrefix must end with /, got %q", got)
	}
}

// fakeS3 is a minimal S3API stub used by storage_test to avoid hitting
// the network. Every method is wired so we can detect that an operation
// reached the S3 layer (i.e. the prefix guard let it through).
type fakeS3 struct {
	puts    []*s3.PutObjectInput
	gets    []*s3.GetObjectInput
	deletes []*s3.DeleteObjectInput
}

func (f *fakeS3) PutObject(_ context.Context, in *s3.PutObjectInput, _ ...func(*s3.Options)) (*s3.PutObjectOutput, error) {
	f.puts = append(f.puts, in)
	return &s3.PutObjectOutput{}, nil
}

func (f *fakeS3) GetObject(_ context.Context, in *s3.GetObjectInput, _ ...func(*s3.Options)) (*s3.GetObjectOutput, error) {
	f.gets = append(f.gets, in)
	return &s3.GetObjectOutput{Body: io.NopCloser(strings.NewReader(""))}, nil
}

func (f *fakeS3) DeleteObject(_ context.Context, in *s3.DeleteObjectInput, _ ...func(*s3.Options)) (*s3.DeleteObjectOutput, error) {
	f.deletes = append(f.deletes, in)
	return &s3.DeleteObjectOutput{}, nil
}

// fakePresigner records the requested expiry so we can assert the
// Presign clamp.
type fakePresigner struct {
	lastExpires time.Duration
	url         string
}

func (p *fakePresigner) PresignGetObject(_ context.Context, _ *s3.GetObjectInput, optFns ...func(*s3.PresignOptions)) (*PresignedHTTPRequest, error) {
	opts := s3.PresignOptions{}
	for _, fn := range optFns {
		fn(&opts)
	}
	p.lastExpires = opts.Expires
	if p.url == "" {
		p.url = "https://signed.example/x"
	}
	return &PresignedHTTPRequest{URL: p.url}, nil
}

func newTestStorage(t *testing.T, audit AuditEmitter) (*S3Storage, *fakeS3, *fakePresigner) {
	t.Helper()
	c := &fakeS3{}
	p := &fakePresigner{}
	s, err := New(Config{
		Bucket:      "test-bucket",
		KMSKeyID:    "alias/test",
		OrgID:       testOrgA,
		WorkspaceID: testWsA,
		Client:      c,
		Presigner:   p,
		Audit:       audit,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return s, c, p
}

// TestS3Storage_PutEmitsAuditOnPrefixMismatch confirms that calling Put
// with a foreign-tenant key both returns the sentinel error and emits a
// single `tenant_isolation_violation` event with the right metadata.
//
// Validates: Requirements 1.5, 1.6.
func TestS3Storage_PutEmitsAuditOnPrefixMismatch(t *testing.T) {
	rec := &RecordingEmitter{}
	s, c, _ := newTestStorage(t, rec)

	badKey := "org/" + testOrgB + "/workspace/" + testWsA + "/x"
	err := s.Put(context.Background(), badKey, strings.NewReader("hi"), Meta{})
	if !errors.Is(err, ErrTenantIsolationViolation) {
		t.Fatalf("expected ErrTenantIsolationViolation, got %v", err)
	}
	if len(c.puts) != 0 {
		t.Fatalf("S3 PutObject must not be reached on violation, got %d calls", len(c.puts))
	}
	events := rec.Events()
	if len(events) != 1 {
		t.Fatalf("expected 1 audit event, got %d", len(events))
	}
	ev := events[0]
	if ev.Operation != "Put" {
		t.Errorf("Operation = %q want Put", ev.Operation)
	}
	if ev.OrgID != testOrgA || ev.WorkspaceID != testWsA {
		t.Errorf("bound principal mismatch: %+v", ev)
	}
	if ev.Key != badKey {
		t.Errorf("Key = %q want %q", ev.Key, badKey)
	}
	if ev.Reason == "" {
		t.Errorf("Reason must be populated")
	}
	if ev.At.IsZero() {
		t.Errorf("At must be populated")
	}
}

// TestS3Storage_HappyPathReachesS3 confirms that a well-formed key under
// the bound prefix passes the guard and reaches the underlying S3 client
// without emitting any audit events.
//
// Validates: Requirements 1.5, 1.6, 6.6.
func TestS3Storage_HappyPathReachesS3(t *testing.T) {
	rec := &RecordingEmitter{}
	s, c, p := newTestStorage(t, rec)

	key := "org/" + testOrgA + "/workspace/" + testWsA + "/scan/abc/report.pdf"
	if err := s.Put(context.Background(), key, strings.NewReader("hi"), Meta{ContentType: "application/pdf"}); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if len(c.puts) != 1 {
		t.Fatalf("expected 1 PutObject call, got %d", len(c.puts))
	}
	if got := *c.puts[0].ContentType; got != "application/pdf" {
		t.Errorf("ContentType = %q want application/pdf", got)
	}
	if got := string(c.puts[0].ServerSideEncryption); got != "aws:kms" {
		t.Errorf("ServerSideEncryption = %q want aws:kms", got)
	}
	if got := *c.puts[0].SSEKMSKeyId; got != "alias/test" {
		t.Errorf("SSEKMSKeyId = %q want alias/test", got)
	}

	url, err := s.Presign(context.Background(), key, time.Hour)
	if err != nil {
		t.Fatalf("Presign: %v", err)
	}
	if url == "" {
		t.Fatal("Presign returned empty URL")
	}
	if p.lastExpires != MaxPresignTTL {
		t.Errorf("Presign expires = %v, want clamped to %v", p.lastExpires, MaxPresignTTL)
	}

	if err := s.Delete(context.Background(), key); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if len(c.deletes) != 1 {
		t.Fatalf("expected 1 DeleteObject call, got %d", len(c.deletes))
	}

	if rec.Len() != 0 {
		t.Fatalf("happy path must not emit audit events, got %d", rec.Len())
	}
}

// TestS3Storage_PresignClampedDown confirms that a sub-15m TTL is left
// untouched (we only clamp values that exceed the bound).
//
// Validates: Requirements 6.6, 20.7.
func TestS3Storage_PresignClampedDown(t *testing.T) {
	s, _, p := newTestStorage(t, nil)
	key := "org/" + testOrgA + "/workspace/" + testWsA + "/scan/abc/report.pdf"
	if _, err := s.Presign(context.Background(), key, 5*time.Minute); err != nil {
		t.Fatalf("Presign: %v", err)
	}
	if p.lastExpires != 5*time.Minute {
		t.Errorf("Presign expires = %v, want preserved 5m", p.lastExpires)
	}
}
