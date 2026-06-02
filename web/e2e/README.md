# `@xalgorix/e2e`

Playwright end-to-end suite for the Xalgorix SaaS web apps. Task 0.4 set up the runner
skeleton; task 15.9 added the marketing visual regression suite; the full
signup-to-invoice journey lands in Phase 20.2.

## Layout

```
web/e2e/
├── playwright.config.ts        # runner configuration
├── tests/                      # *.spec.ts files (added in Phase 20.2)
├── marketing/                  # task 15.9 visual regression specs
├── snapshots/                  # committed visual baselines
└── playwright-report/          # CI artifact, gitignored
```

## Running locally

```bash
pnpm --filter @xalgorix/e2e exec playwright install --with-deps
pnpm --filter @xalgorix/e2e test
```

The runner spins up `web/marketing`, `web/app`, and `web/admin` automatically when running
locally. CI sets `PLAYWRIGHT_BASE_URL` to a deployed staging URL and skips the local
dashboard/admin servers; the marketing dev server is always booted by the runner so the
visual suite has a stable target.

## Marketing visual regression (task 15.9)

The `marketing-mobile` (360×800) and `marketing-desktop` (1280×800) projects diff full-page
screenshots of every route landed in tasks 15.2 and 15.3 against committed baselines. The
suite enforces `expect.toHaveScreenshot.maxDiffPixelRatio: 0.01` and forces
`prefers-reduced-motion: reduce` so Framer Motion entrances do not jitter captures.

```bash
# Run the visual diff (fails on any baseline regression > 1 %).
pnpm --filter @xalgorix/e2e test:visual

# Refresh baselines after an intentional design change.
pnpm --filter @xalgorix/e2e test:visual:update
```

Baselines are committed under `web/e2e/marketing-*-snapshots/` (created on first CI run).

## Targets covered

| App        | URL                        | Default port (dev) |
| ---------- | -------------------------- | ------------------ |
| Marketing  | https://xalgorix.com       | 3000               |
| Dashboard  | https://app.xalgorix.com   | 3001               |
| Admin      | https://admin.xalgorix.com | 3002               |

Browsers: chromium, firefox, webkit, and a mobile chromium profile (Pixel 7) so Requirement 17
(mobile-responsive PWA) and Requirement 2.8 (mobile layout) are exercisable. The visual
suite pins Chromium so font rasterisation matches across operating systems.

## Phase 20.2 plan

Specs to add when the journey is wired:

- `tests/auth.spec.ts` — signup → verify → MFA enrollment.
- `tests/onboarding.spec.ts` — org/workspace creation.
- `tests/targets.spec.ts` — DNS TXT verification.
- `tests/scans.spec.ts` — scan dispatch → live telemetry → completion.
- `tests/findings.spec.ts` — finding triage and status changes.
- `tests/reports.spec.ts` — branded PDF download.
- `tests/billing.spec.ts` — Dodo checkout, invoice listing.
