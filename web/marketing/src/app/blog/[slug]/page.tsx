import Link from "next/link";
import type { Metadata } from "next";

import { buttonVariants } from "@xalgorix/ui";

import { SiteNav } from "@/components/site-nav";

/**
 * `/blog/[slug]` — Marketing_Site per-post page (placeholder).
 *
 * Implements Requirement 2.1: keeps the `/blog/...` URL space resolving
 * with HTTP 200 once the first real posts land. `generateStaticParams`
 * returns an empty array so no slugs are pre-rendered at build time —
 * `dynamicParams = true` (the App Router default) lets any visited
 * slug fall through to ISR with the "Coming soon" placeholder.
 *
 * Real content sourcing (MDX / a CMS) will replace this scaffold in a
 * later task.
 */

export const revalidate = 3600;

export async function generateStaticParams(): Promise<{ slug: string }[]> {
  // No published posts yet; real slugs will land in a later task.
  return [];
}

type Params = { params: { slug: string } };

export function generateMetadata({ params }: Params): Metadata {
  const slugLabel = humanize(params.slug);
  return {
    title: `${slugLabel} · Blog`,
    description: `${slugLabel} — a post from the Xalgorix blog. Coming soon.`,
    alternates: { canonical: `/blog/${params.slug}` },
  };
}

export default function BlogPostPage({ params }: Params) {
  const slugLabel = humanize(params.slug);

  return (
    <div className="flex min-h-screen flex-col">
      <SiteNav />
      <main className="container flex flex-1 flex-col gap-8 py-16">
        <nav aria-label="Breadcrumb" className="text-sm text-muted-foreground">
          <Link
            href="/blog"
            className="underline-offset-4 hover:underline"
          >
            ← Back to blog
          </Link>
        </nav>

        <header className="flex flex-col gap-2">
          <p className="text-sm uppercase tracking-wide text-muted-foreground">
            Blog
          </p>
          <h1 className="text-balance text-4xl font-semibold tracking-tight sm:text-5xl">
            {slugLabel}
          </h1>
        </header>

        <section
          aria-labelledby="post-coming-soon-heading"
          className="rounded-lg border border-border bg-card p-8 text-card-foreground"
        >
          <h2
            id="post-coming-soon-heading"
            className="text-xl font-semibold tracking-tight"
          >
            Coming soon
          </h2>
          <p className="mt-2 text-sm text-muted-foreground">
            This post is still being written. In the meantime, you can
            try Xalgorix yourself.
          </p>
          <div className="mt-4">
            <Link
              href="/signup"
              className={buttonVariants({ size: "sm" })}
            >
              Start free trial
            </Link>
          </div>
        </section>
      </main>
    </div>
  );
}

function humanize(slug: string): string {
  if (!slug) return "Post";
  return slug
    .split("-")
    .filter(Boolean)
    .map((word) => word.charAt(0).toUpperCase() + word.slice(1))
    .join(" ");
}
