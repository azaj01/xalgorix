import type { Metadata } from "next";
import Link from "next/link";

import { buttonVariants } from "@xalgorix/ui";

/**
 * `/about` — company / about page (Task 15.3).
 *
 * The marketing site is dark-by-default per Requirement 2.6, so the
 * page leans on the shared theme tokens from `@xalgorix/ui` instead of
 * hard-coding background colors. Buttons use `buttonVariants` from the
 * shared UI package so the visual language matches the rest of the
 * marketing surface.
 */
export const dynamic = "force-static";

export const metadata: Metadata = {
  title: "About",
  description:
    "Xalgorix is the cloud platform for AI-driven security testing of web applications, APIs, and infrastructure.",
  alternates: { canonical: "/about" },
};

const VALUES = [
  {
    title: "Security as a default",
    body: "We ship secure-by-default tooling so every team — not just teams with a dedicated AppSec function — can find and fix vulnerabilities quickly.",
  },
  {
    title: "Transparent by design",
    body: "Findings come with clear reproduction steps, the raw evidence we collected, and a confidence score. No black-box scoring, no buried context.",
  },
  {
    title: "Customer data, not training data",
    body: "Customer data is never used to train shared models. Tenant isolation is enforced at the database, storage, and process level.",
  },
] as const;

export default function AboutPage() {
  return (
    <main id="main" className="container py-16">
      <header className="mx-auto max-w-2xl text-center">
        <p className="text-sm font-medium uppercase tracking-wide text-muted-foreground">
          About Xalgorix
        </p>
        <h1 className="mt-2 text-balance text-4xl font-semibold tracking-tight sm:text-5xl">
          We're building security testing on autopilot.
        </h1>
        <p className="mt-4 text-pretty text-lg text-muted-foreground">
          Xalgorix runs continuous, agentic security scans against modern
          web apps, APIs, and infrastructure — so engineering teams can
          ship faster without sacrificing safety.
        </p>
      </header>

      <section
        aria-labelledby="mission-heading"
        className="mx-auto mt-16 max-w-3xl"
      >
        <h2
          id="mission-heading"
          className="text-2xl font-semibold tracking-tight"
        >
          Our mission
        </h2>
        <p className="mt-3 text-pretty text-muted-foreground">
          Modern application security is too important to be a quarterly
          audit and too noisy to be left to humans alone. We're building
          a platform where AI agents do the heavy lifting — exploring,
          probing, and reproducing — and humans focus on the decisions
          that actually matter: what to fix, in what order, and how.
        </p>
      </section>

      <section
        aria-labelledby="values-heading"
        className="mx-auto mt-16 max-w-3xl"
      >
        <h2
          id="values-heading"
          className="text-2xl font-semibold tracking-tight"
        >
          What we value
        </h2>
        <ul className="mt-6 grid gap-6 sm:grid-cols-3">
          {VALUES.map((value) => (
            <li
              key={value.title}
              className="rounded-lg border border-border bg-card p-6 text-card-foreground"
            >
              <h3 className="text-lg font-semibold tracking-tight">
                {value.title}
              </h3>
              <p className="mt-2 text-sm text-muted-foreground">
                {value.body}
              </p>
            </li>
          ))}
        </ul>
      </section>

      <section
        aria-labelledby="cta-heading"
        className="mx-auto mt-16 max-w-3xl text-center"
      >
        <h2
          id="cta-heading"
          className="text-2xl font-semibold tracking-tight"
        >
          Want to talk?
        </h2>
        <p className="mt-3 text-pretty text-muted-foreground">
          We'd love to hear from teams of every size — from a solo
          founder shipping their first SaaS to a security org rolling
          out continuous testing across hundreds of services.
        </p>
        <div className="mt-6 flex flex-wrap justify-center gap-3">
          <Link href="/contact" className={buttonVariants({ size: "lg" })}>
            Contact us
          </Link>
          <Link
            href="/security"
            className={buttonVariants({ variant: "outline", size: "lg" })}
          >
            How we secure your data
          </Link>
        </div>
      </section>
    </main>
  );
}
