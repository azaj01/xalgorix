import Link from "next/link";
import type { Metadata } from "next";

import { buttonVariants } from "@xalgorix/ui";

import { SiteNav } from "@/components/site-nav";

/**
 * `/docs` — Marketing_Site documentation index.
 *
 * Implements Requirement 2.1: the `/docs` page is part of the
 * enumerated Marketing_Site URL set. Real documentation entries land in
 * a later task — for now the index renders a "Coming soon" placeholder
 * so the route resolves with HTTP 200 and the SEO/sitemap pipeline
 * (task 15.7) has a real page to link to.
 *
 * ISR: revalidate every hour. The doc index will eventually be sourced
 * from a content directory and we want updates to roll out without a
 * redeploy.
 */

export const metadata: Metadata = {
  title: "Docs",
  description:
    "Guides, API references, and runbooks for Xalgorix. New documentation lands here as the platform expands.",
  alternates: { canonical: "/docs" },
};

export const revalidate = 3600;

export default function DocsIndexPage() {
  return (
    <div className="flex min-h-screen flex-col">
      <SiteNav />
      <main className="container flex flex-1 flex-col gap-12 py-16">
        <section className="flex flex-col items-center gap-4 text-center">
          <h1 className="text-balance text-4xl font-semibold tracking-tight sm:text-5xl">
            Docs
          </h1>
          <p className="max-w-2xl text-pretty text-lg text-muted-foreground">
            Guides, API references, and runbooks for Xalgorix. We are
            actively writing — check back soon, or jump straight in and
            start a free trial.
          </p>
          <Link
            href="/signup"
            className={buttonVariants({ size: "lg" })}
          >
            Start free trial
          </Link>
        </section>

        <section
          aria-labelledby="docs-coming-soon-heading"
          className="rounded-lg border border-border bg-card p-8 text-card-foreground"
        >
          <h2
            id="docs-coming-soon-heading"
            className="text-xl font-semibold tracking-tight"
          >
            Coming soon
          </h2>
          <p className="mt-2 text-sm text-muted-foreground">
            The first wave of guides covers signup, target verification,
            running your first scan, and configuring webhooks. We will
            publish them here as they land.
          </p>
        </section>
      </main>
    </div>
  );
}
