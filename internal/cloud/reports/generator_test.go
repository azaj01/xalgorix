package reports

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/cloud/storage"
	"github.com/xalgord/xalgorix/v4/internal/reporting"
)

// testScanID is a deterministic scan id used by the worker-wrapper
// tests so the canonical S3 key shape stays stable across runs. The
// (testOrgID, testWorkspaceID) tenancy pair lives in
// fakestorage_test.go so all test files in this package share a single
// source of truth for per-tenant key assertions.
const testScanID = "scan-001"

// stubPDFGenerator is a deterministic [PDFGenerator] used to assert
// that [Generator.Generate] forwards the right (Scan, Options) pair to
// the renderer. The stub records every invocation, writes a known
// PDF-shaped payload to the supplied scratch dir, and is safe for use
// across goroutines.
type stubPDFGenerator struct {
	mu          sync.Mutex
	scans       []*reporting.Scan
	opts        []reporting.Options
	payload     []byte
	returnErr   error
	returnPath  string
	scratchHits []string
}

func newStubPDFGenerator() *stubPDFGenerator {
	return &stubPDFGenerator{
		payload: []byte("%PDF-1.4\n% xalgorix-cloud-test report\n%%EOF\n"),
	}
}

func (s *stubPDFGenerator) generate(scan *reporting.Scan, opts reporting.Options) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.returnErr != nil {
		return "", s.returnErr
	}
	s.scans = append(s.scans, scan)
	s.opts = append(s.opts, opts)

	dir := opts.ScanDir
	if dir == "" {
		dir = opts.FallbackDir
	}
	s.scratchHits = append(s.scratchHits, dir)

	out := filepath.Join(dir, "xalgorix_report_"+scan.ID+".pdf")
	if err := os.WriteFile(out, s.payload, 0o600); err != nil {
		return "", err
	}
	if s.returnPath != "" {
		return s.returnPath, nil
	}
	return out, nil
}

func newGenerator(t *testing.T, fs *fakeStorage, stub *stubPDFGenerator) *Generator {
	t.Helper()
	return &Generator{
		Storage:      fs,
		PDFGenerator: stub.generate,
		TempDir:      t.TempDir(),
	}
}

func newScan() ReportScan {
	return ReportScan{
		OrgID:       testOrgID,
		WorkspaceID: testWorkspaceID,
		ScanID:      testScanID,
		Plan:        "pro",
		Target:      "https://example.com",
		StartedAt:   "2025-01-01T00:00:00Z",
		FinishedAt:  "2025-01-01T01:00:00Z",
		Status:      "completed",
		CompanyName: "Acme Corp",
		LogoPath:    "/tmp/acme-logo.png",
	}
}

// TestGenerator_Generate_HappyPath asserts the worker wrapper renders
// the PDF, computes the SHA-256 of the rendered file, and uploads it
// under the canonical per-tenant key with content-type `application/pdf`.
//
// Validates: Requirements 6.5, 6.6.
func TestGenerator_Generate_HappyPath(t *testing.T) {
	fs := &fakeStorage{}
	stub := newStubPDFGenerator()
	g := newGenerator(t, fs, stub)

	key, err := g.Generate(context.Background(), newScan())
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	wantKey := "org/" + testOrgID + "/workspace/" + testWorkspaceID + "/scan/" + testScanID + "/report.pdf"
	if key != wantKey {
		t.Errorf("returned key = %q, want %q", key, wantKey)
	}
	puts := fs.snapshot()
	if len(puts) != 1 {
		t.Fatalf("expected 1 storage.Put call, got %d", len(puts))
	}
	put := puts[0]
	if put.Key != wantKey {
		t.Errorf("uploaded key = %q, want %q", put.Key, wantKey)
	}
	if put.Meta.ContentType != "application/pdf" {
		t.Errorf("ContentType = %q, want application/pdf", put.Meta.ContentType)
	}
	if !bytes.Equal(put.Body, stub.payload) {
		t.Errorf("uploaded body did not match generator payload")
	}
	wantSum := sha256.Sum256(stub.payload)
	wantHex := hex.EncodeToString(wantSum[:])
	if got := put.Meta.UserMetadata["sha256"]; got != wantHex {
		t.Errorf("sha256 metadata = %q, want %q", got, wantHex)
	}
	if got := put.Meta.UserMetadata["scan_id"]; got != testScanID {
		t.Errorf("scan_id metadata = %q, want %q", got, testScanID)
	}
	if got := put.Meta.UserMetadata["org_id"]; got != testOrgID {
		t.Errorf("org_id metadata = %q, want %q", got, testOrgID)
	}
	if got := put.Meta.UserMetadata["workspace_id"]; got != testWorkspaceID {
		t.Errorf("workspace_id metadata = %q, want %q", got, testWorkspaceID)
	}
}

// TestGenerator_Generate_FreePlanStripsBranding asserts that Free-plan
// scans never carry the supplied logo into the renderer and that the
// trial watermark prefix lands on the cover-page company name.
//
// Validates: Requirement 6.11.
func TestGenerator_Generate_FreePlanStripsBranding(t *testing.T) {
	fs := &fakeStorage{}
	stub := newStubPDFGenerator()
	g := newGenerator(t, fs, stub)

	scan := newScan()
	scan.Plan = "free"

	if _, err := g.Generate(context.Background(), scan); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if len(stub.opts) != 1 || len(stub.scans) != 1 {
		t.Fatalf("expected 1 PDFGenerator invocation, got opts=%d scans=%d", len(stub.opts), len(stub.scans))
	}
	gotOpts := stub.opts[0]
	if gotOpts.LogoPath != "" {
		t.Errorf("Free-plan opts.LogoPath = %q, want empty", gotOpts.LogoPath)
	}
	gotScan := stub.scans[0]
	if gotScan.LogoPath != "" {
		t.Errorf("Free-plan scan.LogoPath = %q, want empty", gotScan.LogoPath)
	}
	if !strings.HasPrefix(gotScan.CompanyName, FreeWatermarkPrefix) {
		t.Errorf("Free-plan CompanyName = %q, want prefix %q", gotScan.CompanyName, FreeWatermarkPrefix)
	}
	if !strings.Contains(gotScan.CompanyName, "Acme Corp") {
		t.Errorf("Free-plan CompanyName = %q, want preserved original brand", gotScan.CompanyName)
	}
}

// TestGenerator_Generate_FreePlanCaseInsensitive asserts that the Plan
// match is case-insensitive so an upstream caller that passes "Free"
// or "FREE" still gets the watermark.
//
// Validates: Requirement 6.11.
func TestGenerator_Generate_FreePlanCaseInsensitive(t *testing.T) {
	for _, plan := range []string{"Free", "FREE", " free "} {
		t.Run(plan, func(t *testing.T) {
			fs := &fakeStorage{}
			stub := newStubPDFGenerator()
			g := newGenerator(t, fs, stub)

			scan := newScan()
			scan.Plan = plan
			if _, err := g.Generate(context.Background(), scan); err != nil {
				t.Fatalf("Generate: %v", err)
			}
			if stub.opts[0].LogoPath != "" {
				t.Errorf("plan %q: opts.LogoPath = %q, want empty", plan, stub.opts[0].LogoPath)
			}
			if !strings.HasPrefix(stub.scans[0].CompanyName, FreeWatermarkPrefix) {
				t.Errorf("plan %q: missing watermark prefix in %q", plan, stub.scans[0].CompanyName)
			}
		})
	}
}

// TestGenerator_Generate_PaidPlanPreservesBranding asserts that
// non-Free plans pass the supplied logo and unmodified company name to
// the renderer.
//
// Validates: Requirement 6.5.
func TestGenerator_Generate_PaidPlanPreservesBranding(t *testing.T) {
	for _, plan := range []string{"pro", "team", "enterprise"} {
		t.Run(plan, func(t *testing.T) {
			fs := &fakeStorage{}
			stub := newStubPDFGenerator()
			g := newGenerator(t, fs, stub)

			scan := newScan()
			scan.Plan = plan
			if _, err := g.Generate(context.Background(), scan); err != nil {
				t.Fatalf("Generate: %v", err)
			}
			if stub.opts[0].LogoPath != "/tmp/acme-logo.png" {
				t.Errorf("plan %q: opts.LogoPath = %q, want preserved", plan, stub.opts[0].LogoPath)
			}
			if stub.scans[0].CompanyName != "Acme Corp" {
				t.Errorf("plan %q: CompanyName = %q, want unmodified", plan, stub.scans[0].CompanyName)
			}
			if strings.Contains(stub.scans[0].CompanyName, FreeWatermarkPrefix) {
				t.Errorf("plan %q: paid plan got the free watermark", plan)
			}
			meta := fs.snapshot()[0].Meta.UserMetadata
			if meta["plan"] != strings.ToLower(plan) {
				t.Errorf("plan metadata = %q, want %q", meta["plan"], plan)
			}
		})
	}
}

// TestGenerator_Generate_RejectsMissingTenancy asserts that the worker
// wrapper guards every required tenancy field before it ever reaches
// the renderer or the storage backend.
//
// Validates: Requirements 1.5, 6.5.
func TestGenerator_Generate_RejectsMissingTenancy(t *testing.T) {
	cases := []struct {
		name string
		mut  func(*ReportScan)
	}{
		{"empty org id", func(s *ReportScan) { s.OrgID = "" }},
		{"empty workspace id", func(s *ReportScan) { s.WorkspaceID = "" }},
		{"empty scan id", func(s *ReportScan) { s.ScanID = "" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fs := &fakeStorage{}
			stub := newStubPDFGenerator()
			g := newGenerator(t, fs, stub)

			scan := newScan()
			tc.mut(&scan)
			if _, err := g.Generate(context.Background(), scan); err == nil {
				t.Fatal("expected error, got nil")
			}
			if len(fs.snapshot()) != 0 {
				t.Errorf("storage.Put must not be called on validation failure")
			}
			if len(stub.scans) != 0 {
				t.Errorf("renderer must not be invoked on validation failure")
			}
		})
	}
}

// TestGenerator_Generate_PropagatesUploadError confirms that a
// storage.Put error is wrapped so callers can assert it via errors.Is.
//
// Validates: Requirement 1.5 (tenant isolation surface).
func TestGenerator_Generate_PropagatesUploadError(t *testing.T) {
	fs := &fakeStorage{putError: storage.ErrTenantIsolationViolation}
	stub := newStubPDFGenerator()
	g := newGenerator(t, fs, stub)

	_, err := g.Generate(context.Background(), newScan())
	if err == nil {
		t.Fatal("expected error from upload, got nil")
	}
	if !errors.Is(err, storage.ErrTenantIsolationViolation) {
		t.Fatalf("expected wrapped ErrTenantIsolationViolation, got %v", err)
	}
}

// TestGenerator_Generate_CleansScratchDir asserts the per-scan scratch
// dir does not leak past the call (Worker_Pool tmpfs hygiene).
//
// Validates: Requirements 1.5, 6.5.
func TestGenerator_Generate_CleansScratchDir(t *testing.T) {
	fs := &fakeStorage{}
	stub := newStubPDFGenerator()
	g := newGenerator(t, fs, stub)

	if _, err := g.Generate(context.Background(), newScan()); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if len(stub.scratchHits) != 1 {
		t.Fatalf("expected 1 scratch dir, got %d", len(stub.scratchHits))
	}
	if _, err := os.Stat(stub.scratchHits[0]); !os.IsNotExist(err) {
		t.Errorf("scratch dir %q must be removed, stat err = %v", stub.scratchHits[0], err)
	}
}
