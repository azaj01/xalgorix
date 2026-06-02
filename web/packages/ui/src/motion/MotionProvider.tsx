"use client";

/**
 * Reduced-motion-aware wrappers around `motion.div`.
 *
 * Implements the client side of the design.md "Animations" contract and
 * Requirement 2.2 (entrance ≤ 600 ms) together with the WCAG 2.1
 * `prefers-reduced-motion` requirement folded into Requirement 18.1.
 *
 * Two helpers are exposed:
 *
 *   - {@link MotionFadeRise} — a single fade-and-rise child.
 *   - {@link MotionStagger}  — a container that staggers its
 *     `MotionFadeRise` children at most ~0.06s apart so the worst-case
 *     three-child entrance still completes well within 600 ms.
 *
 * Both honour `useReducedMotion()`; when the user has requested reduced
 * motion the variants collapse to an instant transition with no
 * translation, so the final layout is rendered immediately.
 *
 * Apps should mount these in client components only — the file is
 * marked `"use client"` so it can be imported from a Next.js Server
 * Component without forcing the parent into a client boundary.
 */

import { motion, useReducedMotion } from "framer-motion";
import type { HTMLMotionProps, Variants } from "framer-motion";
import * as React from "react";

import {
  resolveFadeRise,
  resolveStaggerChildren,
} from "./index";

type DivMotionProps = Omit<
  HTMLMotionProps<"div">,
  "variants" | "initial" | "animate"
>;

export interface MotionFadeRiseProps extends DivMotionProps {
  /**
   * Override the resolved variants. Rarely needed; provided as an
   * escape hatch for design experiments.
   */
  variantsOverride?: Variants;
}

/**
 * A `motion.div` that fades up on mount and respects
 * `prefers-reduced-motion`. Drop-in for hero copy, feature cards, and
 * any other entrance animation that should fit inside the 600 ms
 * budget.
 */
export const MotionFadeRise = React.forwardRef<
  HTMLDivElement,
  MotionFadeRiseProps
>(function MotionFadeRise(
  { variantsOverride, children, ...rest },
  ref,
) {
  const reduced = useReducedMotion();
  const variants = variantsOverride ?? resolveFadeRise(reduced);

  return (
    <motion.div
      ref={ref}
      variants={variants}
      initial="hidden"
      animate="visible"
      {...rest}
    >
      {children}
    </motion.div>
  );
});

export interface MotionStaggerProps extends DivMotionProps {
  /**
   * Stagger gap in seconds between children. Defaults to 0.06s so a
   * three-child hero finishes within ~0.57s. Capped at 0 when the user
   * prefers reduced motion.
   */
  staggerDelay?: number;
}

/**
 * A `motion.div` that staggers its `MotionFadeRise` children. Honours
 * `prefers-reduced-motion` by collapsing the stagger gap to zero so all
 * children resolve to their final state immediately.
 */
export const MotionStagger = React.forwardRef<
  HTMLDivElement,
  MotionStaggerProps
>(function MotionStagger(
  { staggerDelay = 0.06, children, ...rest },
  ref,
) {
  const reduced = useReducedMotion();
  const variants = resolveStaggerChildren(reduced, staggerDelay);

  return (
    <motion.div
      ref={ref}
      variants={variants}
      initial="hidden"
      animate="visible"
      {...rest}
    >
      {children}
    </motion.div>
  );
});
