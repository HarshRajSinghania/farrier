import createMDX from "@next/mdx";
import type { NextConfig } from "next";

// The public address, baked into page metadata, the sitemap and robots.txt at build time. On Vercel the
// production domain is known during the build; anywhere else set NEXT_PUBLIC_SITE_URL. Without either, a
// production build of the public website would advertise localhost, so it says so loudly.
const vercelHost = process.env.VERCEL_ENV === "production" ? process.env.VERCEL_PROJECT_PRODUCTION_URL : process.env.VERCEL_URL;
const siteUrl = process.env.NEXT_PUBLIC_SITE_URL || (vercelHost ? `https://${vercelHost}` : undefined);
if (!siteUrl && process.env.NODE_ENV === "production" && process.env.FARRIER_MODE !== "app" && !process.env.CI) {
  console.warn("⚠ NEXT_PUBLIC_SITE_URL is not set: links, the sitemap and social cards will point to http://localhost:3000.");
}

const nextConfig: NextConfig = {
  env: siteUrl ? { NEXT_PUBLIC_SITE_URL: siteUrl } : {},
  cacheComponents: true,
  partialPrefetching: true,
  pageExtensions: ["ts", "tsx", "md", "mdx"],
  poweredByHeader: false,
  // Lets `next build` produce a minimal server bundle for the Docker image.
  output: "standalone",
  turbopack: {
    rules: {
      "*.css": {
        loaders: ["@tailwindcss/turbopack"],
        as: "*.css",
      },
    },
  },
  async headers() {
    return [
      {
        source: "/:path*",
        headers: [
          { key: "X-Content-Type-Options", value: "nosniff" },
          { key: "X-Frame-Options", value: "DENY" },
          { key: "Referrer-Policy", value: "strict-origin-when-cross-origin" },
          { key: "Permissions-Policy", value: "camera=(), microphone=(), geolocation=()" },
          // HSTS only once the site is served over HTTPS (set NEXT_PUBLIC_SITE_URL to its https:// address)
          ...(siteUrl?.startsWith("https://")
            ? [{ key: "Strict-Transport-Security", value: "max-age=63072000; includeSubDomains" }]
            : []),
        ],
      },
    ];
  },
};

const withMDX = createMDX({
  options: {
    remarkPlugins: ["remark-gfm"],
    rehypePlugins: [
      "rehype-slug",
      // highlighted at build time; both themes ship, CSS picks one (globals.css, .docs-prose)
      ["rehype-pretty-code", { theme: { light: "github-light", dark: "github-dark-dimmed" }, keepBackground: false, defaultLang: { block: "plaintext" } }],
    ],
  },
});

export default withMDX(nextConfig);
