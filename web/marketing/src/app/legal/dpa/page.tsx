import type { Metadata } from "next";
import Link from "next/link";

import { buttonVariants } from "@xalgorix/ui";

/**
 * `/legal/dpa` — Data Processing Addendum placeholder (Task 15.3).
 */
export const dynamic = "force-static";

export const metadata: Metadata = {
  title: "Data Processing Addendum",
  description:
    "Placeholder Xalgorix Data Processing Addendum. The final DPA will be published and made signable before general availability.",
  alternates: { canonical: "/legal/dpa" },
  robots: { index: false, follow: true },
};

export default function DataProcessingAddendumPage() {
  return (
    <main id="main" className="container py-16">
      <article className="mx-auto max-w-3xl">
        <p className="text-sm font-medium uppercase tracking-wide text-muted-foreground">
          Legal
        </p>
        <h1 className="mt-2 text-balance text-4xl font-semibold tracking-tight sm:text-5xl">
          Data Processing Addendum
        </h1>
        <p className="mt-4 text-sm text-muted-foreground">
          Placeholder · Last updated when this page is replaced with the
          finalized DPA.
        </p>

        <div className="prose prose-neutral mt-10 max-w-none dark:prose-invert">
          <p>
            This page is a placeholder for the Xalgorix Data Processing
            Addendum (DPA). The final DPA will describe the roles of
            Xalgorix and the customer under GDPR and equivalent data
            protection laws, the categories of personal data processed,
            sub-processor obligations, the security measures applied,
            and the Standard Contractual Clauses incorporated by
            reference for international transfers.
          </p>
          <p>
            Until the final DPA is signable, our processing commitments
            include:
          </p>
          <ul>
            <li>
              Xalgorix acts as a processor for customer-submitted data
              and only processes it on documented customer instructions.
            </li>
            <li>
              All sub-processors are listed publicly; customers will be
              notified before any new sub-processor is engaged.
            </li>
            <li>
              Personal data is encrypted at rest with AES-256-GCM and in
              transit with TLS 1.3, with KMS keys rotated every 90
              days.
            </li>
            <li>
              We support data subject access, deletion, and portability
              requests via the contact channels below.
            </li>
          </ul>
          <p>
            Need a signed DPA for procurement or compliance review?
            Reach out and we will share the current draft for review.
          </p>
        </div>

        <div className="mt-10">
          <Link href="/contact" className={buttonVariants({ variant: "outline" })}>
            Request a DPA review
          </Link>
        </div>
      </article>
    </main>
  );
}
