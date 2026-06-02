"use client";

/**
 * Client-side pricing toggle for `/pricing`.
 *
 * Implements the toggle hook portion of Requirement 2.3 (Monthly /
 * Annual switch updates displayed prices without a full page reload).
 * The actual pricing math (tier values from Decisions and Defaults,
 * proration display) lands in task 15.8 — this scaffold only flips the
 * displayed period label while leaving the per-tier price strings
 * untouched.
 *
 * This component lives in its own file so the parent server segment
 * (`page.tsx`) can keep `export const revalidate = 3600` for ISR
 * (segment config is server-only).
 */

import Link from "next/link";
import { useState } from "react";

import { buttonVariants } from "@xalgorix/ui";

type BillingPeriod = "monthly" | "annual";

type Tier = {
  name: string;
  /** Short value-prop displayed under the tier name. */
  tagline: string;
  /** ~5 features for the card — final values come in 15.8. */
  features: string[];
  cta: { label: string; href: string };
  /** Per-period price label. Real numbers wired up in 15.8. */
  prices: Record<BillingPeriod, string>;
  highlight?: boolean;
};

const TIERS: Tier[] = [
  {
    name: "Free",
    tagline: "Try Xalgorix on a single target.",
    prices: { monthly: "$0", annual: "$0" },
    features: [
      "1 verified target",
      "5 scans per month",
      "30-day findings retention",
      "Discord and Slack alerts",
      "Watermarked PDF reports",
    ],
    cta: { label: "Get started", href: "/signup" },
  },
  {
    name: "Pro",
    tagline: "For solo developers and small teams.",
    prices: { monthly: "$49", annual: "$39.20" },
    features: [
      "10 verified targets",
      "50 scans per month",
      "90-day findings retention",
      "Read-only API access",
      "Branded PDF reports",
    ],
    cta: { label: "Start 14-day trial", href: "/signup?plan=pro" },
    highlight: true,
  },
  {
    name: "Team",
    tagline: "Collaboration and full API access.",
    prices: { monthly: "$199", annual: "$159.20" },
    features: [
      "5 included seats",
      "50 verified targets",
      "250 scans per month",
      "180-day findings retention",
      "Full read/write API access",
    ],
    cta: { label: "Start 14-day trial", href: "/signup?plan=team" },
  },
  {
    name: "Enterprise",
    tagline: "SAML SSO, custom branding, dedicated support.",
    prices: { monthly: "$999", annual: "$799.20" },
    features: [
      "25 included seats",
      "500 verified targets",
      "SAML and OIDC SSO",
      "365-day findings retention",
      "Custom-branded reports",
    ],
    cta: { label: "Contact sales", href: "/contact" },
  },
];

export function PricingTiers() {
  const [period, setPeriod] = useState<BillingPeriod>("monthly");

  return (
    <section
      aria-labelledby="pricing-heading"
      className="flex flex-col gap-8"
    >
      <div className="flex flex-col items-center gap-4 text-center">
        <h2
          id="pricing-heading"
          className="text-2xl font-semibold tracking-tight"
        >
          Pick the plan that fits your team
        </h2>
        <PeriodToggle period={period} onChange={setPeriod} />
      </div>

      <ul
        role="list"
        className="grid gap-4 lg:grid-cols-4"
      >
        {TIERS.map((tier) => (
          <li
            key={tier.name}
            className={
              tier.highlight
                ? "flex flex-col gap-4 rounded-lg border border-primary bg-card p-6 text-card-foreground shadow-sm"
                : "flex flex-col gap-4 rounded-lg border border-border bg-card p-6 text-card-foreground"
            }
          >
            <header className="flex flex-col gap-1">
              <h3 className="text-lg font-semibold tracking-tight">
                {tier.name}
              </h3>
              <p className="text-sm text-muted-foreground">
                {tier.tagline}
              </p>
            </header>
            <p className="flex items-baseline gap-1">
              <span className="text-3xl font-semibold tracking-tight">
                {tier.prices[period]}
              </span>
              <span className="text-sm text-muted-foreground">
                {period === "monthly" ? "/ month" : "/ month, billed annually"}
              </span>
            </p>
            <ul role="list" className="flex flex-1 flex-col gap-2 text-sm">
              {tier.features.map((feature) => (
                <li key={feature} className="text-muted-foreground">
                  • {feature}
                </li>
              ))}
            </ul>
            <Link
              href={tier.cta.href}
              className={buttonVariants({
                variant: tier.highlight ? "default" : "outline",
              })}
            >
              {tier.cta.label}
            </Link>
          </li>
        ))}
      </ul>
    </section>
  );
}

function PeriodToggle({
  period,
  onChange,
}: {
  period: BillingPeriod;
  onChange: (next: BillingPeriod) => void;
}) {
  return (
    <div
      role="radiogroup"
      aria-label="Billing period"
      className="inline-flex items-center gap-1 rounded-md border border-border bg-card p-1"
    >
      <PeriodOption
        value="monthly"
        label="Monthly"
        selected={period === "monthly"}
        onSelect={onChange}
      />
      <PeriodOption
        value="annual"
        label="Annual"
        selected={period === "annual"}
        onSelect={onChange}
      />
    </div>
  );
}

function PeriodOption({
  value,
  label,
  selected,
  onSelect,
}: {
  value: BillingPeriod;
  label: string;
  selected: boolean;
  onSelect: (next: BillingPeriod) => void;
}) {
  return (
    <button
      type="button"
      role="radio"
      aria-checked={selected}
      onClick={() => onSelect(value)}
      className={
        selected
          ? "rounded-sm bg-primary px-3 py-1 text-sm font-medium text-primary-foreground"
          : "rounded-sm px-3 py-1 text-sm font-medium text-muted-foreground hover:text-foreground"
      }
    >
      {label}
    </button>
  );
}
