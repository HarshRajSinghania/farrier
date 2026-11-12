import type { NextConfig } from "next";

// The dashboard's public address (Helm, Compose and Terraform set it). Used for the sign-in origin
// checks and to turn on HSTS once it is https://. The landing page and docs are a separate app: site/.
const vercelHost = process.env.VERCEL_ENV === "production" ? process.env.VERCEL_PROJECT_PRODUCTION_URL : process.env.VERCEL_URL;
const siteUrl = process.env.NEXT_PUBLIC_SITE_URL || (vercelHost ? `https://${vercelHost}` : undefined);

const nextConfig: NextConfig = {
  env: siteUrl ? { NEXT_PUBLIC_SITE_URL: siteUrl } : {},
  cacheComponents: true,
  partialPrefetching: true,
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
          // HSTS only once the dashboard is served over HTTPS (set NEXT_PUBLIC_SITE_URL to its https:// address)
          ...(siteUrl?.startsWith("https://")
            ? [{ key: "Strict-Transport-Security", value: "max-age=63072000; includeSubDomains" }]
            : []),
        ],
      },
    ];
  },
};

export default nextConfig;
