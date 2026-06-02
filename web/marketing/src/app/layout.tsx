import "@xalgorix/ui/globals.css";

import type { Metadata, Viewport } from "next";
import Script from "next/script";
import type { ReactNode } from "react";

import { ThemeProvider } from "@/components/theme-provider";

export const metadata: Metadata = {
  title: {
    default: "Xalgorix — AI security testing for modern web apps",
    template: "%s · Xalgorix",
  },
  description:
    "Xalgorix is the cloud platform for AI-driven security testing of web applications, APIs, and infrastructure.",
  metadataBase: new URL(
    process.env.NEXT_PUBLIC_MARKETING_URL ?? "https://xalgorix.com",
  ),
};

export const viewport: Viewport = {
  // Dark by default per Requirement 2.6; resolved theme on the client
  // overrides this once `next-themes` mounts.
  themeColor: [
    { media: "(prefers-color-scheme: dark)", color: "#020617" },
    { media: "(prefers-color-scheme: light)", color: "#ffffff" },
  ],
  width: "device-width",
  initialScale: 1,
};

/**
 * Inline SSR-safe theme bootstrap.
 *
 * Implements Requirement 2.6 and task 15.5: read the persisted theme
 * preference from `localStorage["xalgorix-theme"]` and apply the
 * matching class on `<html>` BEFORE React mounts so the page does not
 * flash the wrong colour scheme on reload (FOUC). `next-themes` will
 * subsequently take over via the `<ThemeProvider>` below; this script
 * is the deterministic pre-hydration guard.
 *
 * Defaults to "dark" when the key is absent or the value is invalid,
 * matching `<ThemeProvider defaultTheme="dark" />`.
 *
 * NOTE: this snippet must remain dependency-free and synchronous. It
 * is loaded with `strategy="beforeInteractive"` so Next.js inlines it
 * into the initial HTML before any client bundle executes.
 */
const themeBootstrapScript = `(function () {
  try {
    var stored = window.localStorage.getItem('xalgorix-theme');
    var theme = stored === 'light' ? 'light' : 'dark';
    var root = document.documentElement;
    root.classList.remove('light', 'dark');
    root.classList.add(theme);
    root.style.colorScheme = theme;
  } catch (_) {
    // localStorage may be unavailable (SSR, privacy mode, sandboxed
    // iframe). Fall through; the SSR default class plus next-themes
    // hydration will recover.
  }
})();`;

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    // `suppressHydrationWarning` is required by `next-themes` because the
    // provider mutates `<html class>` on mount based on `localStorage`.
    <html lang="en" suppressHydrationWarning>
      <head>
        <Script
          id="xalgorix-theme-bootstrap"
          strategy="beforeInteractive"
        >
          {themeBootstrapScript}
        </Script>
      </head>
      <body className="min-h-screen bg-background text-foreground antialiased">
        <ThemeProvider
          attribute="class"
          defaultTheme="dark"
          enableSystem={false}
          // Requirement 2.6: persist theme selection under this key.
          storageKey="xalgorix-theme"
          disableTransitionOnChange
        >
          {children}
        </ThemeProvider>
      </body>
    </html>
  );
}
