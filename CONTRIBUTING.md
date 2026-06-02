# Contributing to Xalgorix

Thanks for your interest in contributing. This document covers the local
development workflow for both the self-hosted **Scan_Engine** binary and the
multi-tenant **Cloud_Platform** SaaS layer (`xalgorix-saas` spec under
`.kiro/specs/xalgorix-saas/`).

## Prerequisites

Install the following on your workstation:

- **Go 1.24+** — building the `xalgorix` and `xalgorix-cloud` binaries.
- **Node.js 20+** and **pnpm 9+** — building the `webui` and the planned
  `web/marketing`, `web/app`, `web/admin` Next.js apps.
- **Docker 24+** with the **Compose v2** plugin (`docker compose ...`) — running
  the local development stack.
- **GNU Make** — the entry point for every common task.

Optional but recommended:

- `golangci-lint`, `staticcheck`, `gosec`, `govulncheck` (used by `make lint`
  and `make sec` once the SaaS quality tooling lands in task 0.3).
- `goose` for running database migrations against the local Postgres.

## Local development stack (`make dev-up` / `make dev-down`)

The Cloud_Platform depends on Postgres, Redis, NATS JetStream, S3-compatible
object storage, virus scanning, and a transactional email sink. To keep getting
started friction-free, all of these run as containers via
`docker-compose.dev.yml`. The Makefile wraps the common operations.

### Starting the stack

```bash
make dev-up
```

This runs `docker compose -f docker-compose.dev.yml up -d --wait` so the
command only returns once every service reports a healthy status. On first run
it pulls images and creates named volumes; subsequent runs reuse them.

When the command finishes you'll see the local connection details printed to
the terminal:

| Service  | Endpoint                                                                 | Notes                                                                  |
| -------- | ------------------------------------------------------------------------ | ---------------------------------------------------------------------- |
| Postgres | `postgres://xalgorix:xalgorix@localhost:5432/xalgorix`                   | Single database `xalgorix`; superuser is `xalgorix`.                   |
| Redis    | `redis://localhost:6379`                                                 | Used for sessions, rate limits, and live telemetry pub/sub.            |
| NATS     | `nats://localhost:4222` (monitoring at `http://localhost:8222`)          | JetStream is enabled; streams are created by the API_Server on boot.   |
| MinIO    | `http://localhost:9000` (console `http://localhost:9001`)                | Credentials: `xalgorix` / `xalgorix-dev-secret`. Bucket `xalgorix-dev` is auto-created. |
| ClamAV   | `tcp://localhost:3310`                                                   | First boot downloads signatures and may take ~2 minutes to go healthy. |
| Mailpit  | SMTP `localhost:1025`, web UI `http://localhost:8025`                    | Captures every outbound transactional email locally.                   |

These match the dependencies described in
`.kiro/specs/xalgorix-saas/design.md` and satisfy the
`docker-compose.dev.yml` task in `tasks.md` (task 0.5).

### Stopping the stack

```bash
make dev-down
```

This stops the containers but **preserves the named volumes**, so your
Postgres, Redis, NATS, MinIO, and ClamAV state survives restarts.

### Viewing logs

```bash
make dev-logs
```

Streams logs from every service. Useful when ClamAV is downloading signatures
on first boot or when debugging NATS JetStream stream creation.

### Wiping all local state

```bash
make dev-reset
```

Equivalent to `docker compose -f docker-compose.dev.yml down -v`. Use this when
you want a clean slate (for example, to re-run migrations from scratch or to
reset the local MinIO bucket).

### Suggested environment variables

When you run `cmd/xalgorix-cloud` or any of the web apps locally, point them at
the stack with values like:

```bash
export DATABASE_URL=postgres://xalgorix:xalgorix@localhost:5432/xalgorix?sslmode=disable
export REDIS_URL=redis://localhost:6379
export NATS_URL=nats://localhost:4222
export S3_ENDPOINT=http://localhost:9000
export S3_REGION=us-east-1
export S3_BUCKET=xalgorix-dev
export S3_ACCESS_KEY=xalgorix
export S3_SECRET_KEY=xalgorix-dev-secret
export S3_FORCE_PATH_STYLE=true
export CLAMAV_ADDR=tcp://localhost:3310
export SMTP_HOST=localhost
export SMTP_PORT=1025
```

These are local defaults only. Production secrets live in AWS Secrets Manager
and are surfaced through the External Secrets Operator (see Phase 14 of the
`xalgorix-saas` task list).

## Building and testing

```bash
make build          # builds the self-hosted binary in ./build/xalgorix
make test           # runs the Go test suite
make lint           # gofmt + go vet (extended in task 0.3)
make webui          # builds the embedded webui bundle into internal/web/static
```

## Spec-driven workflow

Feature work happens through specs under `.kiro/specs/`. Before opening a PR
that touches a spec area, please read the relevant `requirements.md`,
`design.md`, and `tasks.md` and make sure your change either implements an
open task or proposes a clearly scoped addition.

## Reporting issues

Open a GitHub issue with reproduction steps, expected vs. actual behavior, and
any relevant logs. For security-sensitive reports, follow the disclosure
process documented at `https://xalgorix.com/security`.
