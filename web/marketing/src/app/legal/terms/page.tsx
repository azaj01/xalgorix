import type { Metadata } from "next";
import Link from "next/link";

import { buttonVariants } from "@xalgorix/ui";

/**
 * `/legal/terms` — Terms of Service placeholder (Task 15.3).
 */
export const dynamic = "force-static";

export const metadata: Metadata = {
  title: "Terms of Service",
  description:
    "Placeholder Xalgorix Terms of Service. The final terms will be published before general availability.",
  alternates: { canonical: "/legal/terms" },
  robots: { index: false, follow: true },
};

export default function TermsOfServicePage() {
  return (
    <main id="main" className="container py-16">
      <article className="mx-auto max-w-3xl">
        <p className="text-sm font-medium uppercase tracking-wide text-muted-foreground">
          Legal
        </p>
        <h1 className="mt-2 text-balance text-4xl font-semibold tracking-tight sm:text-5xl">
          Terms of Service
        </h1>
        <p className="mt-4 text-sm text-muted-foreground">
          Placeholder · Last updated when this page is replaced with the
          finalized terms.
        </p>

        <div className="prose prose-neutral mt-10 max-w-none dark:prose-invert">
          <p>
            This page is a placeholder for the Xalgorix Terms of
            Service. The final document will describe the agreement
            between Xalgorix and customers, including acceptable use,
            availability commitments, billing terms, intellectual
            property ownership, limitation of liability, and dispute
            resolution.
          </p>
          <p>
            Until the final terms are published, all use of the Xalgorix
            preview is subject to these interim commitments:
          </p>
          <ul>
            <li>
              You may only run scans against systems you own or are
              expressly authorized to test.
            </li>
            <li>
              Customer data and findings remain your property; Xalgorix
              processes them on your behalf.
            </li>
            <li>
              The preview service is provided as-is during the preview
              window; production SLAs take effect at general
              availability.
            </li>
          </ul>
          <p>
            Questions about these placeholder terms? Reach out and we
            will respond promptly.
          </p>
        </div>

        <div className="mt-10">
          <Link href="/contact" className={buttonVariants({ variant: "outline" })}>
            Contact us about terms
          </Link>
        </div>
      </article>
    </main>
  );
}
