import type { MetadataRoute } from "next";
import { DOCS_FLAT } from "@/lib/docs-nav";
import { site } from "@/lib/site";

export default function sitemap(): MetadataRoute.Sitemap {
  return ["/", ...DOCS_FLAT.map((d) => d.href), "/privacy", "/terms"].map((path) => ({
    url: `${site.url}${path === "/" ? "" : path}`,
    priority: path === "/" ? 1 : 0.7,
  }));
}
