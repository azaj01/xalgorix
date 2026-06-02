package reports

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/xalgord/xalgorix/v4/internal/cloud/storage"
	"github.com/xalgord/xalgorix/v4/internal/reporting"
)

// FreeWatermarkPrefix is prepended to the cover-page company name on
// Free-plan reports. It is the documented fallback for the
// "Watermark Free-plan reports" rule from Requirement 6.11 used while
// `reporting.Options` does not (yet) expose a dedicated `Watermark`
// field. Combined with `LogoPath=""` it strips all custom branding from
// the cover page so a Free-plan PDF is unmistakably labelled as a trial
// artifact.
//
// Validates: Requirements 6.5, 6.11.
const FreeWatermarkPrefix = "TRIAL — XALGORIX FREE"

// FreePlan is the canonical Plan identifier that triggers the
// Free-plan watermark + logo-stripping path inside [Generator.Generate].
const FreePlan = "free"

// ReportObjectName is the object suffix every Cloud_Platform PDF report
// is uploaded under, appended to the per-tenant S3 prefix
// `org/{org}/workspace/{ws}/scan/{scan_id}/`. Keeping the suffix as a
// constant makes the canonical key shape testable in isolation and
// guarantees parity between `Generator.Generate` and any future
// `Generator.Presign` implementation.
//
// Validates: Requirements 6.5, 6.6.
const ReportObjectName = "report.pdf"

// PDFGenerator is the function shape implemented by
// [reporting.Generate]. Exposing the indirection lets tests inject a
// deterministic fake generator that writes a placeholder file to disk
// without paying the cost of a full PDF render.
type PDFGenerator func(scan *reporting.Scan, opts reporting.Options) (string, error)

// ReportScan is the cloud-side projection of a persisted scan record
// consumed by [Generator.Generate]. It carries everything the
// Worker_Pool needs to render a branded PDF report and upload it under
// the per-tenant S3 prefix.
//
// Field shapes mirror [reporting.Scan] one-for-one with the addition of
// the tenancy and plan fields the Worker_Pool resolves from the Org
// record before invoking the generator.
type ReportScan struct {
	OrgID       string
	WorkspaceID string
	ScanID      string
	// Plan is the Org's billing plan (`free`, `pro`, `team`,
	// `enterprise`). The Free plan strips custom branding and applies
	// the trial watermark per Requirement 6.11.
	Plan        string
	Name        string
	Target      string
	StartedAt   string
	FinishedAt  string
	Status      string
	CompanyName string
	// LogoPath is an optional pre-validated absolute path to a logo on
	// the worker's local filesystem. Free-plan reports clear this
	// before invoking the renderer.
	LogoPath    string
	Phases      []int
	Iterations  int
	ToolCalls   int
	TotalTokens int
	Vulns       []reporting.Vuln
	Events      []reporting.Event
}

// Generator wraps [reporting.Generate] with the cloud-specific concerns
// the Worker_Pool needs: per-scan scratch directory, SHA-256 content
// hashing, tenant-scoped S3 upload under
// `org/{org}/workspace/{ws}/scan/{scan_id}/report.pdf`, and Free-plan
// branding suppression.
//
// Construction is cheap; a single Generator may be reused across
// scans. Concurrent calls to [Generator.Generate] are safe so long as
// the underlying [storage.Storage] implementation is.
//
// Validates: Requirements 6.5, 6.11.
type Generator struct {
	// Storage uploads the rendered PDF to the per-tenant S3 prefix.
	// Required.
	Storage storage.Storage
	// PDFGenerator overrides [reporting.Generate]. Production callers
	// leave this nil; tests inject a fake that records the supplied
	// options without paying the cost of a real PDF render.
	PDFGenerator PDFGenerator
	// TempDir is the parent directory for the per-scan scratch dir.
	// Empty falls back to [os.TempDir]; production runs let the
	// default tmpfs pod mount take effect.
	TempDir string
}

// Generate renders the branded PDF for scan, computes the SHA-256
// digest of the rendered file, and uploads it to S3 under the canonical
// key
// `org/{scan.OrgID}/workspace/{scan.WorkspaceID}/scan/{scan.ScanID}/report.pdf`
// with content-type `application/pdf`.
//
// Free-plan scans (`scan.Plan == "free"`) have their custom branding
// suppressed before the renderer is invoked: `LogoPath` is cleared and
// the cover-page company name is prefixed with [FreeWatermarkPrefix] so
// the watermark is visible on every page that mentions the brand. This
// satisfies the "Watermark Free-plan reports (no custom branding)"
// requirement without modifying the `internal/reporting` package
// (task 6.1's territory).
//
// The function returns the canonical S3 key on success. Errors from the
// PDF renderer, the SHA-256 hashing step, and the S3 upload are wrapped
// so the call site can `errors.Is(err, ...)` the underlying sentinel
// (e.g. [storage.ErrTenantIsolationViolation]).
//
// Validates: Requirements 6.5, 6.6, 6.11.
func (g *Generator) Generate(ctx context.Context, scan ReportScan) (string, error) {
	if g == nil {
		return "", errors.New("reports: nil generator")
	}
	if g.Storage == nil {
		return "", errors.New("reports: storage is required")
	}
	if scan.OrgID == "" {
		return "", errors.New("reports: org id is required")
	}
	if scan.WorkspaceID == "" {
		return "", errors.New("reports: workspace id is required")
	}
	if scan.ScanID == "" {
		return "", errors.New("reports: scan id is required")
	}

	tempBase := g.TempDir
	if tempBase == "" {
		tempBase = os.TempDir()
	}
	workDir, err := os.MkdirTemp(tempBase, "xal-report-*")
	if err != nil {
		return "", fmt.Errorf("reports: create scratch dir: %w", err)
	}
	defer os.RemoveAll(workDir)

	rs := scan.toReportingScan()
	opts := reporting.Options{
		LogoPath: scan.LogoPath,
		ScanDir:  workDir,
	}

	if isFreePlan(scan.Plan) {
		// Suppress all custom branding for Free-plan reports per
		// Requirement 6.11. The trial watermark survives as a prefix
		// on the brand string so it lands on the cover page and on
		// every header that consults BrandName.
		opts.LogoPath = ""
		rs.LogoPath = ""
		rs.CompanyName = applyFreeWatermark(rs.CompanyName)
	}

	gen := g.PDFGenerator
	if gen == nil {
		gen = reporting.Generate
	}

	pdfPath, err := gen(rs, opts)
	if err != nil {
		return "", fmt.Errorf("reports: generate pdf: %w", err)
	}

	body, digest, err := readAndHash(pdfPath)
	if err != nil {
		return "", err
	}

	key := storage.KeyPrefix(scan.OrgID, scan.WorkspaceID) + "scan/" + scan.ScanID + "/" + ReportObjectName

	meta := storage.Meta{
		ContentType: "application/pdf",
		UserMetadata: map[string]string{
			"scan_id":      scan.ScanID,
			"org_id":       scan.OrgID,
			"workspace_id": scan.WorkspaceID,
			"sha256":       digest,
			"plan":         strings.ToLower(strings.TrimSpace(scan.Plan)),
		},
	}

	if err := g.Storage.Put(ctx, key, bytes.NewReader(body), meta); err != nil {
		return "", fmt.Errorf("reports: upload report: %w", err)
	}
	return key, nil
}

// toReportingScan projects a [ReportScan] into the transport type the
// `internal/reporting` package consumes. The mapping is intentionally a
// 1:1 field copy — every cloud-only concern (Plan, OrgID, WorkspaceID,
// ScanID) is handled inside [Generator.Generate] before it reaches the
// renderer.
func (s ReportScan) toReportingScan() *reporting.Scan {
	return &reporting.Scan{
		ID:          s.ScanID,
		Name:        s.Name,
		Target:      s.Target,
		StartedAt:   s.StartedAt,
		FinishedAt:  s.FinishedAt,
		Status:      s.Status,
		CompanyName: s.CompanyName,
		LogoPath:    s.LogoPath,
		Phases:      s.Phases,
		Iterations:  s.Iterations,
		ToolCalls:   s.ToolCalls,
		TotalTokens: s.TotalTokens,
		Vulns:       s.Vulns,
		Events:      s.Events,
	}
}

// isFreePlan reports whether plan is the canonical `free` identifier.
// The check is intentionally case-insensitive so an upstream caller
// that passes `"Free"` or `"FREE"` still triggers the watermark.
func isFreePlan(plan string) bool {
	return strings.EqualFold(strings.TrimSpace(plan), FreePlan)
}

// applyFreeWatermark returns the trial-prefixed company name. An empty
// input returns the bare prefix; a populated input is joined with
// " — " so the result reads "TRIAL — XALGORIX FREE — Acme Corp".
func applyFreeWatermark(companyName string) string {
	clean := strings.TrimSpace(companyName)
	if clean == "" {
		return FreeWatermarkPrefix
	}
	return FreeWatermarkPrefix + " — " + clean
}

// readAndHash slurps the file at path into memory and returns the raw
// bytes alongside a lowercase hex SHA-256 digest. The bytes are
// buffered in memory so the upload path can present a fresh
// [bytes.Reader] independent of the on-disk file (which is wiped by the
// scratch-dir cleanup defer in [Generator.Generate]).
func readAndHash(path string) ([]byte, string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, "", fmt.Errorf("reports: open pdf: %w", err)
	}
	defer f.Close()

	var buf bytes.Buffer
	h := sha256.New()
	if _, err := io.Copy(io.MultiWriter(&buf, h), f); err != nil {
		return nil, "", fmt.Errorf("reports: hash pdf: %w", err)
	}
	return buf.Bytes(), hex.EncodeToString(h.Sum(nil)), nil
}
