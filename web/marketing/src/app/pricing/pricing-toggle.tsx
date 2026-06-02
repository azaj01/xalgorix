"use client";

/**
 * Marketing_Site pricing toggle (Monthly / Annual) with no full-page reload.
 *
 * Implements Requirement 2.3:
 *   "WHEN a visitor toggles between `Monthly` and `Annual` on the pricing
 *    page, THE Marketing_Site SHALL update the displayed prices to the
 *    values defined in the Decisions and Defaults section without a full
 *    page reload."
 *
 * Also satisfies Requirement 2.4 by surfacing a primary CTA per plan that
 * deep-links to `/signup` (and `/contact` for Enterprise).
 *
 * Pricing rule (per task 15.8):
 *   - Free always shows "$0".
 *   - Annual prices are 80% of (monthly * 12), i.e. a flat 20% discount.
 *   - Enterprise renders "Contact us" instead of a numeric price.
 *
 * The amounts encoded below are placeholders — the live values live in
 * `requirements.md` § "Decisions and Defaults" and are wired in later
 * billing tasks. The point of this component is the client-side toggle
 * behaviour, not the actual numbers.
 */

import { useId, useState } from "react";

import { buttonVariants, cn } from "@xalgorix/ui";

type Period = "monthly" | "annual";

interface Plan {
  /** Stable identifier used as a React key. */
  id: "free" | "pro" | "team" | "enterprise";
  name: string;
  description: string;
  /**
   * Monthly price in whole USD. `null` means the plan is custom-priced and
   * should render `Contact us` regardless of the selected period.
   */
  monthlyUsd: number | null;
  /** Bullet list of plan-defining features. */
  features: string[];
  /** Primary call-to-action label. */
  ctaLabel: string;
  /** Primary call-to-action href. */
  ctaHref: string;
  /** Highlights the featured plan with an accent border + badge. */
  featured?: boolean;
}

const PLANS: Plan[] = [
  {
    id: "free",
    name: "Free",
    description: "Try the engine on a single Target.",
    monthlyUsd: 0,
    features: [
      "1 seat, 1 workspace",
      "1 active target",
      "5 scans / month",
      "Watermarked PDF reports",
    ],
    ctaLabel: "Start free",
    ctaHref: "/signup",
  },
  {
    id: "pro",
    name: "Pro",
    description: "For solo operators running continuous tests.",
    monthlyUsd: 29,
    features: [
      "1 seat, 3 workspaces",
      "10 active targets",
      "50 scans / month",
      "Branded PDF reports",
      "REST API (read)",
    ],
    ctaLabel: "Start 14-day trial",
    ctaHref: "/signup?plan=pro",
    featured: true,
  },
  {
    id: "team",
    name: "Team",
    description: "Built for security teams shipping every week.",
    monthlyUsd: 99,
    features: [
      "5 seats included",
      "10 workspaces",
      "50 active targets",
      "250 scans / month",
      "Slack, Discord, Jira, GitHub, Linear",
    ],
    ctaLabel: "Start 14-day trial",
    ctaHref: "/signup?plan=team",
  },
  {
    id: "enterprise",
    name: "Enterprise",
    description: "SSO, custom branding, and a regional deployment.",
    monthlyUsd: null,
    features: [
      "25+ seats with custom pricing",
      "SAML 2.0 / OIDC SSO",
      "Custom data residency",
      "Priority support and SLA",
    ],
    ctaLabel: "Contact sales",
    ctaHref: "/contact?topic=enterprise",
  },
];

/**
 * Formats the price string + cadence suffix for a given plan + period.
 * Pulled out of the component so it stays trivially unit-testable if a
 * dedicated test file is added later.
 */
export function formatPrice(
  plan: Pick<Plan, "monthlyUsd">,
  period: Period,
): { amount: string; suffix: string } {
  // Custom-priced plans render the same copy regardless of period.
  if (plan.monthlyUsd === null) {
    return { amount: "Contact us", suffix: "" };
  }

  // Free tier: always "$0" — only the cadence label changes with period.
  if (plan.monthlyUsd === 0) {
    return { amount: "$0", suffix: period === "monthly" ? "/mo" : "/yr" };
  }

  if (period === "monthly") {
    return { amount: `$${plan.monthlyUsd}`, suffix: "/mo" };
  }

  // Annual = 20% discount applied to (monthly * 12).
  const annual = Math.round(plan.monthlyUsd * 12 * 0.8);
  return { amount: `$${annual}`, suffix: "/yr" };
}

export function PricingToggle() {
  const [period, setPeriod] = useState<Period>("monthly");
  // The two toggle buttons share an ARIA group so screen readers announce
  // them as a related pair.
  const groupLabelId = useId();

  return (
    <div className="flex flex-col items-center gap-12">
      <PeriodSwitch
        period={period}
        onChange={setPeriod}
        labelId={groupLabelId}
      />

      <div
        // Uses a 4-column grid on `lg` so all plans line up; collapses to
        // 2 columns on tablet and 1 column on mobile.
        className="grid w-full grid-cols-1 gap-6 sm:grid-cols-2 lg:grid-cols-4"
        // Re-key on period change so screen readers re-announce updated
        // prices via the per-card `aria-live` regions below.
        role="list"
      >
        {PLANS.map((plan) => (
          <PlanCard key={plan.id} plan={plan} period={period} />
        ))}
      </div>

      <p className="text-center text-sm text-muted-foreground">
        All paid plans include a 14-day Pro trial. Annual billing saves 20%.
      </p>
    </div>
  );
}

interface PeriodSwitchProps {
  period: Period;
  onChange: (next: Period) => void;
  labelId: string;
}

function PeriodSwitch({ period, onChange, labelId }: PeriodSwitchProps) {
  return (
    <div className="flex flex-col items-center gap-3">
      <span id={labelId} className="sr-only">
        Billing period
      </span>
      <div
        role="group"
        aria-labelledby={labelId}
        className="inline-flex items-center rounded-full border border-border bg-muted/40 p-1"
      >
        <PeriodButton
          isActive={period === "monthly"}
          onClick={() => onChange("monthly")}
        >
          Monthly
        </PeriodButton>
        <PeriodButton
          isActive={period === "annual"}
          onClick={() => onChange("annual")}
        >
          Annual
          <span
            className={cn(
              "ml-2 rounded-full px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide",
              period === "annual"
                ? "bg-primary-foreground/15 text-primary-foreground"
                : "bg-primary/10 text-primary",
            )}
          >
            -20%
          </span>
        </PeriodButton>
      </div>
    </div>
  );
}

interface PeriodButtonProps {
  isActive: boolean;
  onClick: () => void;
  children: React.ReactNode;
}

function PeriodButton({ isActive, onClick, children }: PeriodButtonProps) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={isActive}
      onClick={onClick}
      className={cn(
        "inline-flex h-9 items-center rounded-full px-4 text-sm font-medium transition-colors",
        "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2",
        isActive
          ? "bg-primary text-primary-foreground shadow-sm"
          : "text-muted-foreground hover:text-foreground",
      )}
    >
      {children}
    </button>
  );
}

interface PlanCardProps {
  plan: Plan;
  period: Period;
}

function PlanCard({ plan, period }: PlanCardProps) {
  const { amount, suffix } = formatPrice(plan, period);

  return (
    <article
      role="listitem"
      aria-label={`${plan.name} plan`}
      className={cn(
        "relative flex h-full flex-col rounded-2xl border bg-card p-6 text-card-foreground shadow-sm",
        plan.featured
          ? "border-primary ring-1 ring-primary/40"
          : "border-border",
      )}
    >
      {plan.featured ? (
        <span className="absolute -top-3 right-6 rounded-full bg-primary px-3 py-1 text-xs font-semibold text-primary-foreground shadow">
          Most popular
        </span>
      ) : null}

      <header className="flex flex-col gap-2">
        <h3 className="text-lg font-semibold">{plan.name}</h3>
        <p className="text-sm text-muted-foreground">{plan.description}</p>
      </header>

      {/*
        `aria-live="polite"` so AT users hear the new amount as soon as the
        period switch changes state without forcing a page reload.
      */}
      <div
        className="mt-6 flex min-h-[3.5rem] items-baseline gap-1"
        aria-live="polite"
      >
        <span className="text-4xl font-semibold tracking-tight">{amount}</span>
        {suffix ? (
          <span className="text-sm text-muted-foreground">{suffix}</span>
        ) : null}
      </div>

      <ul className="mt-6 flex flex-1 flex-col gap-2 text-sm">
        {plan.features.map((feature) => (
          <li key={feature} className="flex items-start gap-2">
            <CheckIcon
              className="mt-0.5 h-4 w-4 flex-none text-primary"
              aria-hidden="true"
            />
            <span>{feature}</span>
          </li>
        ))}
      </ul>

      <a
        href={plan.ctaHref}
        className={cn(
          buttonVariants({
            variant: plan.featured ? "default" : "outline",
            size: "default",
          }),
          "mt-6 w-full",
        )}
      >
        {plan.ctaLabel}
      </a>
    </article>
  );
}

function CheckIcon({ className }: { className?: string }) {
  return (
    <svg
      className={className}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2.5"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      focusable="false"
    >
      <polyline points="20 6 9 17 4 12" />
    </svg>
  );
}
