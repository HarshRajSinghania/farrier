import createMDX from "@next/mdx";
import type { NextConfig } from "next";

const nextConfig: NextConfig = {
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
          ...(process.env.NEXT_PUBLIC_SITE_URL?.startsWith("https://")
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
