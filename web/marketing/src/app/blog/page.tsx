import Link from "next/link";
import type { Metadata } from "next";

import { buttonVariants } from "@xalgorix/ui";

import { SiteNav } from "@/components/site-nav";

/**
 * `/blog` — Marketing_Site blog index.
 *
 * Implements Requirement 2.1: the `/blog` page is part of the
 * enumerated Marketing_Site URL set. Real posts land in a later task —
 * for now the index renders a "Coming soon" placeholder so the route
 * resolves with HTTP 200 and the SEO/sitemap pipeline (task 15.7) has a
 * real page to link to.
 *
 * ISR: revalidate every hour.
 */

export const metadata: Metadata = {
  title: "Blog",
  description:
    "News, deep dives, and engineering posts from the Xalgorix team.",
  alternates: { canonical: "/blog" },
};

export const revalidate = 3600;

export default function BlogIndexPage() {
  return (
    <div className="flex min-h-screen flex-col">
      <SiteNav />
      <main className="container flex flex-1 flex-col gap-12 py-16">
        <section className="flex flex-col items-center gap-4 text-center">
          <h1 className="text-balance text-4xl font-semibold tracking-tight sm:text-5xl">
            Blog
          </h1>
          <p className="max-w-2xl text-pretty text-lg text-muted-foreground">
            News, deep dives, and engineering posts from the Xalgorix
            team. Our first posts will land here soon.
          </p>
          <Link
            href="/signup"
            className={buttonVariants({ size: "lg" })}
          >
            Start free trial
          </Link>
        </section>

        <section
          aria-labelledby="blog-coming-soon-heading"
          className="rounded-lg border border-border bg-card p-8 text-card-foreground"
        >
          <h2
            id="blog-coming-soon-heading"
            className="text-xl font-semibold tracking-tight"
          >
            Coming soon
          </h2>
          <p className="mt-2 text-sm text-muted-foreground">
            We are kicking things off with posts on agentic security
            testing, deterministic exploit verification, and how we
            built the Xalgorix Scan_Engine. Subscribe to be notified.
          </p>
        </section>
      </main>
    </div>
  );
}
