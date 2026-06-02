/**
 * Theme persistence verification — task 15.5, Requirement 2.6.
 *
 * `web/marketing` does not yet have a JavaScript test runner wired
 * (see `package.json` — the `test` script is currently a placeholder).
 * Once vitest + @testing-library/react are added to the workspace, the
 * `describe.skip` block below can be flipped to `describe` and will
 * exercise the same protocol that this document defines for manual
 * verification.
 *
 * --------------------------------------------------------------------
 * Manual verification protocol
 * --------------------------------------------------------------------
 *
 * Pre-requisites:
 *   - `pnpm install` at the repo root
 *   - `pnpm --filter @xalgorix/marketing dev` (port 3000)
 *
 * Verification steps:
 *
 *   1. Open http://localhost:3000 in a fresh browser profile (no
 *      `xalgorix-theme` key present in localStorage).
 *
 *      Expected:
 *        - The page renders in dark theme (background near `#020617`).
 *        - `document.documentElement.classList` contains `"dark"`.
 *        - DevTools → Application → Local Storage → `xalgorix-theme`
 *          may be absent OR equal to `"dark"` after first mount.
 *
 *   2. Click the theme toggle button (sun/moon icon in the header).
 *
 *      Expected:
 *        - Theme flips to light immediately, no full-page reload.
 *        - `document.documentElement.classList` contains `"light"`.
 *        - `localStorage.getItem("xalgorix-theme") === "light"`.
 *
 *   3. Hard-refresh the page (Cmd/Ctrl-Shift-R).
 *
 *      Expected:
 *        - The page paints in light theme on the FIRST frame — no dark
 *          flash before React mounts. This validates the inline
 *          `beforeInteractive` bootstrap script in
 *          `src/app/layout.tsx` is reading `localStorage` synchronously
 *          and applying `class="light"` on `<html>` before hydration.
 *        - `localStorage.getItem("xalgorix-theme")` is still `"light"`.
 *
 *   4. Click the toggle again to flip back to dark, then hard-refresh.
 *
 *      Expected:
 *        - The page paints in dark theme on the first frame.
 *        - `localStorage.getItem("xalgorix-theme") === "dark"`.
 *
 *   5. Manually corrupt the value:
 *
 *        > localStorage.setItem("xalgorix-theme", "neon");
 *        > location.reload();
 *
 *      Expected:
 *        - The page falls back to the dark default. The bootstrap
 *          script only honours the literal `"light"` value; anything
 *          else resolves to `"dark"`.
 *
 *   6. Disable localStorage (DevTools → Application → "Clear storage"
 *      and block third-party storage, or use a strict-privacy browser).
 *
 *      Expected:
 *        - The page still renders the dark default. The bootstrap
 *          script swallows the `SecurityError` and falls through to
 *          `next-themes`, which also defaults to `"dark"`.
 * --------------------------------------------------------------------
 */

// eslint-disable-next-line @typescript-eslint/no-unused-vars
const _vitestExample = () => {
  /*
  // Activate when vitest + @testing-library/react land in the workspace.
  import { describe, expect, it, beforeEach } from "vitest";
  import { render, screen, fireEvent } from "@testing-library/react";
  import { ThemeProvider } from "@/components/theme-provider";
  import { ThemeToggle } from "@/components/theme-toggle";

  describe("theme persistence (Requirement 2.6)", () => {
    beforeEach(() => {
      window.localStorage.clear();
      document.documentElement.classList.remove("light", "dark");
    });

    it("persists toggled theme under xalgorix-theme", () => {
      render(
        <ThemeProvider
          attribute="class"
          defaultTheme="dark"
          enableSystem={false}
          storageKey="xalgorix-theme"
        >
          <ThemeToggle />
        </ThemeProvider>,
      );

      const button = screen.getByRole("button", { name: /switch to/i });
      fireEvent.click(button);

      expect(window.localStorage.getItem("xalgorix-theme")).toBe("light");

      fireEvent.click(button);
      expect(window.localStorage.getItem("xalgorix-theme")).toBe("dark");
    });
  });
  */
};

export {};
