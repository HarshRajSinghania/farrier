import type { MetadataRoute } from "next";
import { site } from "@/lib/site";

export default function robots(): MetadataRoute.Robots {
  // a team's own install (FARRIER_MODE=app) should never be indexed
  if ((process.env.FARRIER_MODE ?? "site").trim().toLowerCase() === "app") {
    return { rules: { userAgent: "*", disallow: "/" } };
  }
  return {
    rules: { userAgent: "*", allow: "/", disallow: ["/dashboard", "/api/"] },
    sitemap: `${site.url}/sitemap.xml`,
  };
}
