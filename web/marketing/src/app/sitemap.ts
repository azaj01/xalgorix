import type { MetadataRoute } from "next";

const SITE_URL = "https://xalgorix.com";

type RouteConfig = {
  path: string;
  priority: number;
};

const routes: RouteConfig[] = [
  { path: "/", priority: 1.0 },
  { path: "/features", priority: 0.7 },
  { path: "/pricing", priority: 0.9 },
  { path: "/docs", priority: 0.7 },
  { path: "/blog", priority: 0.7 },
  { path: "/changelog", priority: 0.7 },
  { path: "/security", priority: 0.7 },
  { path: "/about", priority: 0.7 },
  { path: "/contact", priority: 0.7 },
  { path: "/legal/privacy", priority: 0.7 },
  { path: "/legal/terms", priority: 0.7 },
  { path: "/legal/dpa", priority: 0.7 },
];

export default function sitemap(): MetadataRoute.Sitemap {
  const lastModified = new Date();

  return routes.map(({ path, priority }) => ({
    url: `${SITE_URL}${path}`,
    lastModified,
    changeFrequency: "weekly",
    priority,
  }));
}
