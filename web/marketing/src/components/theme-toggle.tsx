"use client";

/**
 * Theme toggle button for the Marketing_Site.
 *
 * Implements Requirement 2.6:
 *   - Dark theme by default.
 *   - User-selectable light theme.
 *   - Selection persisted in `localStorage` under the key `xalgorix-theme`
 *     (configured by `<ThemeProvider storageKey="xalgorix-theme" />` in
 *     `app/layout.tsx`).
 *
 * Uses `next-themes`' `useTheme` hook and flips between the explicit
 * `"dark"` and `"light"` values (we do not expose `system` on the
 * marketing surface — Requirement 2.6 mandates a deterministic default
 * of dark with a user-selectable light theme).
 */
import { useEffect, useState } from "react";
import { useTheme } from "next-themes";

import { Button } from "@xalgorix/ui";

export function ThemeToggle() {
  const { resolvedTheme, setTheme } = useTheme();

  // Avoid a hydration mismatch: until the client has mounted we cannot
  // know what the persisted theme is, so render a stable placeholder.
  const [mounted, setMounted] = useState(false);
  useEffect(() => {
    setMounted(true);
  }, []);

  const isDark = mounted ? resolvedTheme === "dark" : true;
  const nextTheme = isDark ? "light" : "dark";
  const label = `Switch to ${nextTheme} theme`;

  return (
    <Button
      type="button"
      variant="outline"
      size="icon"
      aria-label={label}
      title={label}
      onClick={() => setTheme(nextTheme)}
      suppressHydrationWarning
    >
      {mounted ? (
        isDark ? (
          <SunIcon className="h-4 w-4" aria-hidden="true" />
        ) : (
          <MoonIcon className="h-4 w-4" aria-hidden="true" />
        )
      ) : (
        // Render the dark-default icon during SSR so the static HTML
        // matches the dark default applied to <html class="dark">.
        <SunIcon className="h-4 w-4" aria-hidden="true" />
      )}
      <span className="sr-only">{label}</span>
    </Button>
  );
}

function SunIcon({ className }: { className?: string }) {
  return (
    <svg
      className={className}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      focusable="false"
    >
      <circle cx="12" cy="12" r="4" />
      <path d="M12 2v2" />
      <path d="M12 20v2" />
      <path d="m4.93 4.93 1.41 1.41" />
      <path d="m17.66 17.66 1.41 1.41" />
      <path d="M2 12h2" />
      <path d="M20 12h2" />
      <path d="m4.93 19.07 1.41-1.41" />
      <path d="m17.66 6.34 1.41-1.41" />
    </svg>
  );
}

function MoonIcon({ className }: { className?: string }) {
  return (
    <svg
      className={className}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      focusable="false"
    >
      <path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z" />
    </svg>
  );
}
