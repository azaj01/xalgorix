import type { Metadata } from "next";
import Link from "next/link";

import { buttonVariants } from "@xalgorix/ui";

import {
  changelogEntries,
  type ChangelogCategory,
} from "@/content/changelog";

/**
 * Public changelog (Requirement 16.1, Task 15.3).
 *
 * Reads entries from a static module (`src/content/changelog.ts`) so
 * publishing a release note is a single-file change. The page is
 * statically generated and re-rendered every hour:
 *   - `dynamic = "force-static"` keeps the page on the static cache.
 *   - `revalidate = 3600` lets ISR refresh once an hour so a new
 *     deploy isn't strictly required to surface freshly added entries.
 */
export const dynamic = "force-static";
export const revalidate = 3600;

export const metadata: Metadata = {
  title: "Changelog",
  description:
    "Customer-visible releases for the Xalgorix Cloud platform — new features, improvements, fixes, and security updates.",
  alternates: { canonical: "/changelog" },
};

const CATEGORY_LABEL: Record<ChangelogCategory, string> = {
  new: "New",
  improved: "Improved",
  fixed: "Fixed",
  security: "Security",
};

const CATEGORY_CLASS: Record<ChangelogCategory, string> = {
  new: "bg-primary/10 text-primary",
  improved: "bg-secondary text-secondary-foreground",
  fixed: "bg-muted text-muted-foreground",
  security: "bg-destructive/10 text-destructive",
};

function formatDate(iso: string): string {
  // Render ISO dates as `Jan 1, 2026` in en-US for consistency across
  // the marketing site regardless of the visitor's locale (the
  // marketing surface is en-only at this stage).
  const date = new Date(`${iso}T00:00:00Z`);
  return date.toLocaleDateString("en-US", {
    year: "numeric",
    month: "short",
    day: "numeric",
    timeZone: "UTC",
  });
}

export default function ChangelogPage() {
  return (
    <main id="main" className="container py-16">
      <header className="mx-auto max-w-2xl text-center">
        <p className="text-sm font-medium uppercase tracking-wide text-muted-foreground">
          Product updates
        </p>
        <h1 className="mt-2 text-balance text-4xl font-semibold tracking-tight sm:text-5xl">
          Changelog
        </h1>
        <p className="mt-4 text-pretty text-lg text-muted-foreground">
          Every customer-visible Xalgorix release, newest first.
        </p>
        <div className="mt-6 flex justify-center">
          <Link href="/" className={buttonVariants({ variant: "ghost" })}>
            ← Back to home
          </Link>
        </div>
      </header>

      <ol className="mx-auto mt-16 max-w-3xl space-y-10">
        {changelogEntries.map((entry) => (
          <li
            key={`${entry.date}-${entry.title}`}
            className="rounded-lg border border-border bg-card p-6 text-card-foreground shadow-sm"
          >
            <div className="flex flex-wrap items-center gap-3 text-sm">
              <time
                dateTime={entry.date}
                className="font-medium text-muted-foreground"
              >
                {formatDate(entry.date)}
              </time>
              <span
                className={`inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-medium ${CATEGORY_CLASS[entry.category]}`}
              >
                {CATEGORY_LABEL[entry.category]}
              </span>
            </div>
            <h2 className="mt-3 text-2xl font-semibold tracking-tight">
              {entry.title}
            </h2>
            <p className="mt-3 text-pretty text-muted-foreground">
              {entry.summary}
            </p>
          </li>
        ))}
      </ol>
    </main>
  );
}
