import type { Metadata } from "next";
import Link from "next/link";

import { buttonVariants } from "@xalgorix/ui";

/**
 * `/legal/privacy` — Privacy Policy placeholder (Task 15.3).
 *
 * The marketing site requires a stable URL even before the production
 * legal copy is finalized; this page renders a plain-language
 * placeholder linking to the contact form for questions.
 */
export const dynamic = "force-static";

export const metadata: Metadata = {
  title: "Privacy Policy",
  description:
    "Placeholder Xalgorix privacy policy. The final policy will be published before general availability.",
  alternates: { canonical: "/legal/privacy" },
  robots: { index: false, follow: true },
};

export default function PrivacyPolicyPage() {
  return (
    <main id="main" className="container py-16">
      <article className="mx-auto max-w-3xl">
        <p className="text-sm font-medium uppercase tracking-wide text-muted-foreground">
          Legal
        </p>
        <h1 className="mt-2 text-balance text-4xl font-semibold tracking-tight sm:text-5xl">
          Privacy Policy
        </h1>
        <p className="mt-4 text-sm text-muted-foreground">
          Placeholder · Last updated when this page is replaced with the
          finalized policy.
        </p>

        <div className="prose prose-neutral mt-10 max-w-none dark:prose-invert">
          <p>
            This page is a placeholder for the Xalgorix Privacy Policy.
            The finalized policy will describe what personal data we
            collect, how we use it, the legal bases under GDPR and the
            CCPA, our retention schedules, and the rights available to
            data subjects.
          </p>
          <p>
            Until the final policy is published, we operate under the
            following commitments:
          </p>
          <ul>
            <li>
              We collect only the personal data needed to provide the
              service (account email, billing details, and audit logs).
            </li>
            <li>
              We do not sell personal data and we do not use customer
              data to train shared machine-learning models.
            </li>
            <li>
              All data at rest is encrypted with AES-256-GCM and all
              data in transit uses TLS 1.3 — see our{" "}
              <Link href="/security">Security overview</Link>.
            </li>
            <li>
              You can request export or deletion of your organization's
              data at any time via{" "}
              <Link href="/contact">our contact form</Link>.
            </li>
          </ul>
          <p>
            Questions about this placeholder policy or how we handle
            personal data? Reach out and we will respond promptly.
          </p>
        </div>

        <div className="mt-10">
          <Link href="/contact" className={buttonVariants({ variant: "outline" })}>
            Contact us about privacy
          </Link>
        </div>
      </article>
    </main>
  );
}
