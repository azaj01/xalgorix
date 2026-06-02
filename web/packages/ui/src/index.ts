/**
 * `@xalgorix/ui` — shared design system for the Xalgorix SaaS frontends.
 *
 * Implements design.md § "Frontend modules" / "web/packages/ui":
 *   - shadcn/ui registry (re-exported components live under `./components`)
 *   - Tailwind preset with shared HSL tokens (`./tailwind-preset`)
 *   - Framer Motion primitives that respect `prefers-reduced-motion` (`./motion`)
 *   - Utility helpers (`./lib/cn`)
 */
export { cn } from "./lib/cn";
export * from "./components/button";
