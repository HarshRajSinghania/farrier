import type { MetadataRoute } from "next";
import { DOCS_FLAT } from "@/lib/docs-nav";
import { site } from "@/lib/site";
import { SOLUTIONS } from "@/lib/solutions";

export const dynamic = "force-static";

// trailing slashes match the exported files (trailingSlash in next.config.ts)
export default function sitemap(): MetadataRoute.Sitemap {
  return ["/", "/solutions/", ...SOLUTIONS.map((s) => `/solutions/${s.slug}/`), ...DOCS_FLAT.map((d) => `${d.href}/`),
    "/privacy/", "/terms/"].map((path) => ({
    url: `${site.url}${path}`,
    priority: path === "/" ? 1 : path.startsWith("/solutions/") ? 0.9 : 0.7,
  }));
}
