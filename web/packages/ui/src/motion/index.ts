/**
 * Framer Motion primitives wrapped to honour `useReducedMotion()` per
 * design.md § "Animations" and Requirement 2.2:
 *
 *   "THE Marketing_Site SHALL render the landing page hero, feature
 *    grid, and pricing comparison with Framer Motion entrance
 *    animations that complete within 600 ms."
 *
 * Apps should import variants and helpers from `@xalgorix/ui/motion`
 * (and the client wrappers from `@xalgorix/ui/motion/MotionProvider`)
 * rather than `framer-motion` directly so the reduced-motion contract
 * is enforced uniformly across marketing, dashboard, and admin shells.
 *
 * Total entrance budget (Requirement 2.2):
 *   - per-child:        duration 0.40s + delay 0.05s = 0.45s
 *   - stagger gap:      0.06s between children
 *   - 3 children worst-case: 0.05 + 2 × 0.06 + 0.40 = 0.57s ≤ 0.60s ✓
 *
 * When `prefers-reduced-motion: reduce` is honoured (Requirement 18.1
 * accessibility budget) every variant collapses to an instant
 * `duration: 0` transition so users see the final state without
 * animation.
 */
export { useReducedMotion, motion, AnimatePresence } from "framer-motion";

import type { Transition, Variants } from "framer-motion";

/**
 * Maximum animated entrance duration in seconds. Exposed so tests and
 * downstream callers can assert against the 600 ms budget without
 * duplicating the constant.
 */
export const ENTRANCE_BUDGET_MS = 600;

/** Transition applied when `prefers-reduced-motion: reduce` is set. */
export const instantTransition: Transition = { duration: 0 };

/** Default entrance transition (≤ 600 ms total when staggered). */
export const animatedEntranceTransition: Transition = {
  duration: 0.4,
  delay: 0.05,
  ease: "easeOut",
};

/**
 * Standard fade-and-rise entrance used by hero/feature sections.
 *
 * Callers that render `motion.*` directly should prefer
 * {@link resolveFadeRise} so the variant respects
 * `prefers-reduced-motion`. The raw export is kept for the (rare) case
 * where callers want to compose their own variants.
 */
export const fadeRise: Variants = {
  hidden: { opacity: 0, y: 12 },
  visible: {
    opacity: 1,
    y: 0,
    transition: animatedEntranceTransition,
  },
};

/**
 * Reduced-motion-aware fade-rise variant.
 *
 * @param reduced - the value returned by `useReducedMotion()`.
 *   When `true`, the variant snaps to its final state with no
 *   movement and a zero-duration transition.
 */
export function resolveFadeRise(reduced: boolean | null | undefined): Variants {
  if (reduced) {
    return {
      hidden: { opacity: 1, y: 0 },
      visible: { opacity: 1, y: 0, transition: instantTransition },
    };
  }
  return fadeRise;
}

/** Stagger container for grids that fade their children sequentially. */
export const staggerChildren = (delay = 0.06): Variants => ({
  hidden: {},
  visible: {
    transition: {
      staggerChildren: delay,
    },
  },
});

/**
 * Reduced-motion-aware stagger container. Disables the stagger gap so
 * every child resolves at `t=0` when reduced motion is requested.
 */
export function resolveStaggerChildren(
  reduced: boolean | null | undefined,
  delay = 0.06,
): Variants {
  return staggerChildren(reduced ? 0 : delay);
}
