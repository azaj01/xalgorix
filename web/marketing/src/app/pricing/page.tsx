import type { Metadata } from "next";
import Link from "next/link";

import { buttonVariants } from "@xalgorix/ui";

import { SiteNav } from "@/components/site-nav";

import { PricingTiers } from "./pricing-tiers";

/**
 * `/pricing` — Marketing_Site pricing comparison.
 *
 * Implements:
 *   - Requirement 2.1: the `/pricing` page is part of the enumerated
 *     Marketing_Site URL set.
 *   - Requirement 2.3: Monthly / Annual toggle without a full page
 *     reload (handled by the client `<PricingTiers>` island below).
 *   - Requirement 2.4: primary CTA on the page links to `/signup`.
 *
 * ISR: revalidate every hour. The pricing card values themselves are
 * fixed in `requirements.md`'s Decisions and Defaults section, but the
 * surrounding hero copy and feature lists are expected to evolve and
 * we want changes to roll out without a redeploy. The actual pricing
 * math (proration, currency switching) lands in task 15.8.
 */

export const metadata: Metadata = {
  title: "Pricing",
  description:
    "Free, Pro, Team, and Enterprise plans for Xalgorix. Switch between monthly and annual billing — annual saves 20 percent.",
  alternates: { canonical: "/pricing" },
};

export const revalidate = 3600;

export default function PricingPage() {
  return (
    <div className="flex min-h-screen flex-col">
      <SiteNav />
      <main className="container flex flex-1 flex-col gap-16 py-16">
        <section className="flex flex-col items-center gap-4 text-center">
          <h1 className="text-balance text-4xl font-semibold tracking-tight sm:text-5xl">
            Pricing that scales with your scans.
          </h1>
          <p className="max-w-2xl text-pretty text-lg text-muted-foreground">
            Start free, upgrade when you need more targets, scans, or
            seats. Every paid plan includes a 14-day Pro trial — no
            payment method required.
          </p>
          <Link
            href="/signup"
            className={buttonVariants({ size: "lg" })}
          >
            Start free trial
          </Link>
        </section>

        <PricingTiers />
      </main>
    </div>
  );
}
