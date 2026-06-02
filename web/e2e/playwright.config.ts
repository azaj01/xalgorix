/**
 * Playwright configuration for the Xalgorix SaaS web E2E suite.
 *
 * Apps under test:
 *   - Marketing (xalgorix.com)              -> http://localhost:3000
 *   - Dashboard (app.xalgorix.com)          -> http://localhost:3001
 *   - Admin    (admin.xalgorix.com)         -> http://localhost:3002
 *
 * The full journey suite (signup -> verify -> MFA -> org/workspace -> target
 * verify -> scan -> finding -> report -> invoice) lands in Phase 20.2. This
 * file establishes the runner so apps can land their specs without churn.
 *
 * Implements task 0.4 in `xalgorix-saas/tasks.md` and supports Requirements
 * 18.1 (a11y in CI) and 19.1/19.2 (perf budgets measured against running apps).
 *
 * Task 15.9 adds the `marketing-mobile` and `marketing-desktop` projects that
 * back the visual regression suite under `./marketing/*.spec.ts`. Both
 * projects pin Chromium, force `prefers-reduced-motion: reduce`, and disable
 * animations during screenshot capture so baselines stay deterministic
 * (Requirement 2.8).
 */
import { defineConfig, devices } from "@playwright/test";

const isCI = !!process.env.CI;

const baseURL =
  process.env.PLAYWRIGHT_BASE_URL ?? "http://localhost:3001"; // Dashboard by default

const marketingURL =
  process.env.PLAYWRIGHT_MARKETING_URL ?? "http://localhost:3000";

export default defineConfig({
  testDir: "./tests",
  outputDir: "./test-results",
  snapshotDir: "./snapshots",

  fullyParallel: true,
  forbidOnly: isCI,
  retries: isCI ? 2 : 0,
  workers: isCI ? 2 : undefined,
  timeout: 60_000,
  expect: {
    timeout: 10_000,
    // Visual regression budget for Requirement 2.8 — at most 1% of pixels may
    // differ between the captured screenshot and the committed baseline.
    toHaveScreenshot: {
      maxDiffPixelRatio: 0.01,
      animations: "disabled",
      caret: "hide",
      scale: "css",
    },
  },

  reporter: isCI
    ? [
        ["github"],
        ["junit", { outputFile: "playwright-report/junit.xml" }],
        ["html", { outputFolder: "playwright-report", open: "never" }],
      ]
    : [["list"], ["html", { outputFolder: "playwright-report", open: "never" }]],

  use: {
    baseURL,
    trace: "on-first-retry",
    screenshot: "only-on-failure",
    video: "retain-on-failure",
    actionTimeout: 15_000,
    navigationTimeout: 30_000,
    locale: "en-US",
    timezoneId: "UTC",
    colorScheme: "dark",
    ignoreHTTPSErrors: false,
    headless: true,
  },

  projects: [
    {
      name: "setup",
      testMatch: /.*\.setup\.ts/,
    },
    {
      name: "chromium",
      use: { ...devices["Desktop Chrome"] },
      dependencies: ["setup"],
    },
    {
      name: "firefox",
      use: { ...devices["Desktop Firefox"] },
      dependencies: ["setup"],
    },
    {
      name: "webkit",
      use: { ...devices["Desktop Safari"] },
      dependencies: ["setup"],
    },
    {
      name: "mobile-chromium",
      use: { ...devices["Pixel 7"] },
      dependencies: ["setup"],
    },

    // ---------------------------------------------------------------------
    // Marketing visual regression projects (task 15.9 / Requirement 2.8).
    //
    // Both projects exclusively run the screenshot-diff specs under
    // `./marketing/*.spec.ts`, point at the local Marketing dev server, and
    // disable motion so Framer Motion entrances (Requirement 2.2) do not
    // leak frame-by-frame jitter into the captured baselines. They do *not*
    // depend on `setup` because the Marketing site is unauthenticated.
    // ---------------------------------------------------------------------
    {
      name: "marketing-mobile",
      testDir: "./marketing",
      use: {
        ...devices["Desktop Chrome"],
        viewport: { width: 360, height: 800 },
        deviceScaleFactor: 1,
        isMobile: false,
        hasTouch: true,
        baseURL: marketingURL,
        contextOptions: { reducedMotion: "reduce" },
      },
    },
    {
      name: "marketing-desktop",
      testDir: "./marketing",
      use: {
        ...devices["Desktop Chrome"],
        viewport: { width: 1280, height: 800 },
        deviceScaleFactor: 1,
        baseURL: marketingURL,
        contextOptions: { reducedMotion: "reduce" },
      },
    },
  ],

  // Local dev only: spin up Marketing, Dashboard, Admin before tests run.
  // CI reuses already-deployed staging URLs via PLAYWRIGHT_BASE_URL. The
  // marketing visual suite specifically depends on the Marketing dev server
  // at http://localhost:3000 (task 15.9 step 4); on CI we let the runner
  // boot the server fresh, locally we reuse whatever is already listening.
  webServer: isCI
    ? [
        {
          command: "pnpm --filter @xalgorix/marketing dev",
          url: marketingURL,
          timeout: 120_000,
          reuseExistingServer: false,
        },
      ]
    : [
        {
          command: "pnpm --filter @xalgorix/marketing dev",
          url: marketingURL,
          timeout: 120_000,
          reuseExistingServer: true,
        },
        {
          command: "pnpm --filter @xalgorix/app dev",
          url: "http://localhost:3001",
          timeout: 120_000,
          reuseExistingServer: true,
        },
        {
          command: "pnpm --filter @xalgorix/admin dev",
          url: "http://localhost:3002",
          timeout: 120_000,
          reuseExistingServer: true,
        },
      ],
});
