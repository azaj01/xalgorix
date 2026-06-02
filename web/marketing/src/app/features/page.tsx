import Link from "next/link";
import type { Metadata } from "next";

import { buttonVariants } from "@xalgorix/ui";

import { SiteNav } from "@/components/site-nav";

/**
 * `/features` — Marketing_Site features overview.
 *
 * Implements:
 *   - Requirement 2.1: the `/features` page is part of the enumerated
 *     Marketing_Site URL set.
 *   - Requirement 2.2: feature grid on the Marketing_Site (entrance
 *     animation lands in task 15.4 — this task scaffolds the static
 *     grid only).
 *   - Requirement 2.4: each Marketing_Site page links to `/signup`
 *     through a primary CTA (rendered in `SiteNav` and again in the
 *     hero CTA below).
 *
 * Static — eligible for full SSG. The four feature cards mirror the
 * top-level capabilities promised across `requirements.md`:
 * continuous scanning, AI-driven exploit verification, compliance
 * reports, and integrations.
 */

export const metadata: Metadata = {
  title: "Features",
  description:
    "Continuous scanning, AI-driven exploit verification, compliance-ready reports, and first-party integrations — everything Xalgorix ships out of the box.",
  alternates: { canonical: "/features" },
};

type Feature = {
  title: string;
  description: string;
};

const FEATURES: Feature[] = [
  {
    title: "Continuous scanning",
    description:
      "Scan_Engine workers run on a per-workspace schedule against verified targets, with concurrent-scan limits and findings retention sized to your plan.",
  },
  {
    title: "AI-driven exploit verification",
    description:
      "Each finding is replayed by an AI verifier that produces a deterministic proof-of-exploit and a remediation-ready summary, cutting false positives.",
  },
  {
    title: "Compliance-ready reports",
    description:
      "Branded PDF reports with executive summaries, CVSS scoring, and SOC 2 / ISO 27001-friendly evidence — generated on demand or on every scan.",
  },
  {
    title: "Integrations",
    description:
      "First-party connectors for Slack, Discord, Microsoft Teams, Jira, GitHub Issues, Linear, AgentMail, and signed webhooks for everything else.",
  },
];

export default function FeaturesPage() {
  return (
    <div className="flex min-h-screen flex-col">
      <SiteNav />
      <main className="container flex flex-1 flex-col gap-16 py-16">
        <section className="flex flex-col items-center gap-4 text-center">
          <h1 className="text-balance text-4xl font-semibold tracking-tight sm:text-5xl">
            Everything you need to ship secure software.
          </h1>
          <p className="max-w-2xl text-pretty text-lg text-muted-foreground">
            Xalgorix combines an autonomous Scan_Engine with AI-driven
            verification, branded reporting, and an integration surface
            that fits the way your team already works.
          </p>
          <Link
            href="/signup"
            className={buttonVariants({ size: "lg" })}
          >
            Start free trial
          </Link>
        </section>

        <section
          aria-labelledby="features-heading"
          className="flex flex-col gap-8"
        >
          <h2
            id="features-heading"
            className="text-2xl font-semibold tracking-tight"
          >
            What you get
          </h2>
          <ul
            role="list"
            className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4"
          >
            {FEATURES.map((feature) => (
              <li
                key={feature.title}
                className="flex flex-col gap-2 rounded-lg border border-border bg-card p-6 text-card-foreground"
              >
                <h3 className="text-lg font-semibold tracking-tight">
                  {feature.title}
                </h3>
                <p className="text-sm text-muted-foreground">
                  {feature.description}
                </p>
              </li>
            ))}
          </ul>
        </section>
      </main>
    </div>
  );
}
