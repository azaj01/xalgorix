/**
 * Next.js config for the Marketing_Site.
 *
 * - `transpilePackages`: workspace packages are consumed as TypeScript
 *   source via `pnpm` symlinks, so Next must transpile them.
 * - `experimental.typedRoutes`: enables type-safe `<Link href="...">`
 *   usage; required by Requirement 2.1's enumerated route list.
 * - ISR: enabled implicitly by the App Router. Individual pages opt in
 *   via `export const revalidate = N`. Static pages (the landing page,
 *   pricing, etc.) are pre-rendered at build time (SSG); long-tail
 *   content (blog, changelog, docs) will set `revalidate` in 15.3.
 */
/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  transpilePackages: ["@xalgorix/ui", "@xalgorix/api-client", "@xalgorix/i18n"],
  experimental: {
    typedRoutes: true,
  },
};

export default nextConfig;
