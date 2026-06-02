// Package reporting owns the branded-PDF generation pipeline used by both
// the self-hosted Xalgorix binary and the future cloud Worker_Pool. It
// encapsulates the layout primitives (palette, fonts, page chrome), the
// scan-summary helpers (severity rollups, risk scoring, recon extraction),
// the security-framework mappings (CWE / OWASP / PTES), and the methodology
// phase catalog.
//
// The package is intentionally free of any dependency on the in-process web
// server or its session/storage state. Callers convert their own scan record
// into the package's transport types (Scan, Vuln, Event) and invoke
// Generate. This keeps the package consumable from any execution context
// — the existing self-hosted binary at internal/web, the cloud
// xalgorix-cloud worker (Phase 5/6 of the xalgorix-saas spec), or future
// CLI report exporters.
//
// Behavior is byte-identical to the previous in-package implementation in
// internal/web/report.go. This package is a pure structural move; no new
// features and no behavioral drift are introduced here. Subsequent tasks
// (6.2 Branded PDF generation in worker, 6.3 Logo upload with ClamAV scan,
// etc. in tasks.md) layer cloud-specific behavior on top.
package reporting
