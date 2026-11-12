import type { MetadataRoute } from "next";
import { DOCS_FLAT } from "@/lib/docs-nav";
import { site } from "@/lib/site";

export const dynamic = "force-static";

// trailing slashes match the exported files (trailingSlash in next.config.ts)
export default function sitemap(): MetadataRoute.Sitemap {
  return ["/", ...DOCS_FLAT.map((d) => `${d.href}/`), "/privacy/", "/terms/"].map((path) => ({
    url: `${site.url}${path}`,
    priority: path === "/" ? 1 : 0.7,
  }));
}
