import Link from "next/link";

import { buttonVariants } from "@xalgorix/ui";
import {
  MotionFadeRise,
  MotionStagger,
} from "@xalgorix/ui/motion/MotionProvider";

import { ThemeToggle } from "@/components/theme-toggle";

/**
 * Marketing landing page.
 *
 * Implements Requirement 2.1 (the `/` page must be served), Requirement
 * 2.2 (Framer Motion entrance animations on the hero complete within
 * 600 ms), and provides the dark-by-default theme + theme toggle entry
 * point required by 2.6. Subsequent pages (`/features`, `/pricing`,
 * `/docs`, `/blog`, `/changelog`, `/security`, `/about`, `/contact`,
 * `/legal/*`) land in tasks 15.2 and 15.3.
 *
 * The hero CTAs are navigational, so they are rendered as `<Link>`
 * elements styled with `buttonVariants` from `@xalgorix/ui` (the same
 * styling source the `Button` component itself uses). The `ThemeToggle`
 * component renders a real `Button` for the icon control.
 *
 * The `<h1>`, `<p>`, and CTA group are wrapped in `MotionFadeRise`
 * children inside a `MotionStagger` so each element fades up
 * sequentially. Both components honour `prefers-reduced-motion` and
 * collapse to an instant transition when the user opts out.
 */
export default function HomePage() {
  return (
    <div className="flex min-h-screen flex-col">
      <header className="container flex items-center justify-between py-6">
        <Link
          href="/"
          className="text-lg font-semibold tracking-tight"
          aria-label="Xalgorix home"
        >
          Xalgorix
        </Link>
        <nav className="flex items-center gap-2">
          <ThemeToggle />
          <Link
            href="/pricing"
            className={buttonVariants({ variant: "ghost", size: "sm" })}
          >
            Pricing
          </Link>
          <Link
            href="/signup"
            className={buttonVariants({ size: "sm" })}
          >
            Start free trial
          </Link>
        </nav>
      </header>

      <main className="container flex flex-1 flex-col items-center justify-center py-24 text-center">
        <MotionStagger className="flex flex-col items-center gap-6">
          <MotionFadeRise>
            <h1 className="text-balance text-5xl font-semibold tracking-tight sm:text-6xl">
              Security testing, on autopilot.
            </h1>
          </MotionFadeRise>
          <MotionFadeRise>
            <p className="max-w-2xl text-pretty text-lg text-muted-foreground">
              Xalgorix runs continuous, agentic security scans against your web
              apps, APIs, and infrastructure. Sign up to start a 14-day Pro
              trial.
            </p>
          </MotionFadeRise>
          <MotionFadeRise className="flex flex-wrap justify-center gap-3">
            <Link
              href="/signup"
              className={buttonVariants({ size: "lg" })}
            >
              Start free trial
            </Link>
            <Link
              href="/pricing"
              className={buttonVariants({ variant: "outline", size: "lg" })}
            >
              View pricing
            </Link>
          </MotionFadeRise>
        </MotionStagger>
      </main>
    </div>
  );
}
