# Security Policy

## Reporting a vulnerability

Please email security@xalgorix.com with details. We acknowledge reports
within two business days and aim to ship a fix or mitigation on a
severity-driven schedule. Do not file public GitHub issues for
suspected vulnerabilities.

## Daily scan policy

Per Requirement 20.11 of the `xalgorix-saas` spec, the
[`security-daily`](.github/workflows/security-daily.yml) GitHub Actions
workflow runs every day at 07:00 UTC (and on `workflow_dispatch`). It
executes `govulncheck ./...` against the Go module pinned to Go 1.24.13
and `pnpm audit --audit-level=high` against the web monorepo using
Node 20 and pnpm 9. When either job reports a high or critical advisory
it fails the run and opens a GitHub Issue labelled `security` and
`automated` with the failing report attached as a workflow artifact.
The workflow skips a job (and logs a notice) when its lockfile is
absent so the schedule keeps running while the corresponding module is
still being scaffolded.
