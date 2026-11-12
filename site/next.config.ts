import createMDX from "@next/mdx";
import type { NextConfig } from "next";

// The public website: landing page, docs and legal pages, exported as plain files (out/) for any static host.
//
// NEXT_PUBLIC_SITE_URL is the public address, baked into metadata, the sitemap and robots.txt at build time.
// On Vercel the production domain is known during the build; anywhere else set it. Without either, a
// production build would advertise localhost, so it says so loudly.
// NEXT_PUBLIC_BASE_PATH serves the site under a sub-path, e.g. "/farrier" for a GitHub project page.
const vercelHost = process.env.VERCEL_ENV === "production" ? process.env.VERCEL_PROJECT_PRODUCTION_URL : process.env.VERCEL_URL;
const siteUrl = process.env.NEXT_PUBLIC_SITE_URL || (vercelHost ? `https://${vercelHost}` : undefined);
if (!siteUrl && process.env.NODE_ENV === "production" && !process.env.CI) {
  console.warn("⚠ NEXT_PUBLIC_SITE_URL is not set: links, the sitemap and social cards will point to http://localhost:3100.");
}
const basePath = (process.env.NEXT_PUBLIC_BASE_PATH ?? "").replace(/\/+$/, "");

const nextConfig: NextConfig = {
  output: "export",
  // /docs/install -> out/docs/install/index.html, which every static host serves without rewrites
  trailingSlash: true,
  basePath: basePath || undefined,
  assetPrefix: basePath || undefined,
  images: { unoptimized: true },
  env: { NEXT_PUBLIC_BASE_PATH: basePath, ...(siteUrl ? { NEXT_PUBLIC_SITE_URL: siteUrl } : {}) },
  pageExtensions: ["ts", "tsx", "md", "mdx"],
  poweredByHeader: false,
  turbopack: {
    root: import.meta.dirname, // this app only; not a parent folder with its own lockfile
    rules: {
      "*.css": {
        loaders: ["@tailwindcss/turbopack"],
        as: "*.css",
      },
    },
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
