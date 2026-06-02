/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  transpilePackages: ["@xalgorix/ui", "@xalgorix/api-client", "@xalgorix/i18n"],
  experimental: {
    typedRoutes: true,
  },
};

export default nextConfig;
