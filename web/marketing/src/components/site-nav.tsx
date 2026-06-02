import Link from "next/link";

import { buttonVariants } from "@xalgorix/ui";

import { ThemeToggle } from "@/components/theme-toggle";

/**
 * Shared site header for the Marketing_Site.
 *
 * Implements Requirement 2.4 (a primary CTA that links to `/signup` on
 * every Marketing_Site page) by rendering the `Start free trial` link in
 * the nav. The brand mark links back to `/` and a `Pricing` shortcut is
 * always one click away. The `ThemeToggle` (built in task 15.1) is
 * reused unchanged so the dark/light selection persisted in
 * `localStorage[xalgorix-theme]` (Requirement 2.6) follows visitors as
 * they navigate between pages.
 *
 * Kept as a server component — it has no interactive state of its own;
 * `ThemeToggle` is the only client island.
 */
export function SiteNav() {
  return (
    <header className="container flex items-center justify-between py-6">
      <Link
        href="/"
        className="text-lg font-semibold tracking-tight"
        aria-label="Xalgorix home"
      >
        Xalgorix
      </Link>
      <nav className="flex items-center gap-2" aria-label="Primary">
        <Link
          href="/features"
          className={buttonVariants({ variant: "ghost", size: "sm" })}
        >
          Features
        </Link>
        <Link
          href="/pricing"
          className={buttonVariants({ variant: "ghost", size: "sm" })}
        >
          Pricing
        </Link>
        <Link
          href="/docs"
          className={buttonVariants({ variant: "ghost", size: "sm" })}
        >
          Docs
        </Link>
        <Link
          href="/blog"
          className={buttonVariants({ variant: "ghost", size: "sm" })}
        >
          Blog
        </Link>
        <ThemeToggle />
        <Link
          href="/signup"
          className={buttonVariants({ size: "sm" })}
        >
          Start free trial
        </Link>
      </nav>
    </header>
  );
}
