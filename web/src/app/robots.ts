import type { MetadataRoute } from "next";

// A team's own install: never indexed.
export default function robots(): MetadataRoute.Robots {
  return { rules: { userAgent: "*", disallow: "/" } };
}
