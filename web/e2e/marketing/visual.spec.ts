/**
 * Marketing visual regression suite (task 15.9, Requirement 2.8).
 *
 * Captures full-page screenshots of every public marketing route landed in
 * tasks 15.2 and 15.3 at two viewports — 360x800 (`marketing-mobile`) and
 * 1280x800 (`marketing-desktop`) — and diffs them against the committed
 * baselines under `./snapshots`. The pixel-diff budget
 * (`maxDiffPixelRatio: 0.01`) is enforced project-wide via
 * `playwright.config.ts`.
 *
 * Determinism notes (kept in lockstep with task 15.4 / Requirement 2.2):
 *
 *   - The browser context emulates `prefers-reduced-motion: reduce` (set on
 *     the project), which collapses Framer Motion variants to their final
 *     state immediately.
 *   - Playwright's `animations: "disabled"` screenshot option (also set on
 *     the project) freezes any remaining CSS transitions and hides the
 *     caret.
 *   - We `waitForLoadState("networkidle")` after each navigation so font
 *     and image fetches have settled before the diff is taken.
 *
 * Baselines are intentionally not committed by this task — the first CI run
 * with `--update-snapshots` produces them. Subsequent runs fail-closed on
 * any pixel-level regression beyond the 1 % budget.
 */
import { expect, test } from "@playwright/test";

/**
 * The complete published marketing URL set (tasks 15.2 + 15.3). Each entry
 * becomes one test per project (mobile + desktop), giving us 12 routes ×
 * 2 viewports = 24 total screenshot diffs.
 *
 * Order is stable so the generated snapshot file names stay stable across
 * runs; do not sort alphabetically.
 */
const MARKETING_ROUTES = [
  { name: "home", path: "/" },
  { name: "features", path: "/features" },
  { name: "pricing", path: "/pricing" },
  { name: "docs", path: "/docs" },
  { name: "blog", path: "/blog" },
  { name: "changelog", path: "/changelog" },
  { name: "security", path: "/security" },
  { name: "about", path: "/about" },
  { name: "contact", path: "/contact" },
  { name: "legal-privacy", path: "/legal/privacy" },
  { name: "legal-terms", path: "/legal/terms" },
  { name: "legal-dpa", path: "/legal/dpa" },
] as const;

test.describe("marketing visual regression", () => {
  // Belt-and-braces: even though both `marketing-*` projects already set
  // `reducedMotion: "reduce"` in the config, force it again at the context
  // level so an ad-hoc `pnpm exec playwright test web/e2e/marketing` from a
  // misconfigured project still produces deterministic captures.
  test.use({ contextOptions: { reducedMotion: "reduce" } });

  for (const route of MARKETING_ROUTES) {
    test(`${route.name} (${route.path}) matches snapshot`, async ({ page }) => {
      await page.goto(route.path, { waitUntil: "domcontentloaded" });
      await page.waitForLoadState("networkidle");

      // Defensive: stamp the reduced-motion preference into the page context
      // a second time. `emulateMedia` is a no-op when the project already
      // sets `reducedMotion` but it makes the spec self-contained for ad-hoc
      // invocations and documents the contract we depend on.
      await page.emulateMedia({ reducedMotion: "reduce" });

      await expect(page).toHaveScreenshot(`${route.name}.png`, {
        fullPage: true,
        animations: "disabled",
        caret: "hide",
      });
    });
  }
});
