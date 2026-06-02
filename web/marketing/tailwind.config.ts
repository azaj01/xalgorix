import type { Config } from "tailwindcss";
import preset from "@xalgorix/ui/tailwind-preset";

/**
 * Tailwind config for the Marketing_Site (`@xalgorix/marketing`).
 *
 * Inherits design tokens, dark-mode strategy (`['class']`), and
 * `tailwindcss-animate` from `@xalgorix/ui/tailwind-preset`. The
 * `darkMode: ['class']` line below is repeated here so that the
 * Marketing_Site's class-based theme toggle (Requirement 2.6) keeps
 * working even if the preset is ever swapped out.
 */
const config: Config = {
  presets: [preset],
  darkMode: ["class"],
  content: [
    "./src/**/*.{ts,tsx,mdx}",
    "../packages/ui/src/**/*.{ts,tsx}",
  ],
};

export default config;
