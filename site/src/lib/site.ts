/** Single source for names and links. Forks change these and nothing else. */
import pkg from "../../package.json";

const basePath = process.env.NEXT_PUBLIC_BASE_PATH ?? "";

export const site = {
  name: "Farrier",
  tagline: "Agentless machine identity automation",
  description:
    "Farrier discovers, manages and secures every machine identity across your infrastructure: TLS certificates, SSH keys, cryptographic assets and post-quantum readiness. No agents. No manual renewals. No missed expirations.",
  // ||, not ??: an empty value must not win. Includes the base path, e.g. https://example.github.io/farrier
  url: (process.env.NEXT_PUBLIC_SITE_URL || `http://localhost:3100${basePath}`).replace(/\/+$/, ""),
  github: "https://github.com/gagankarthik/farrier",
  // the public demo: web/ deployed with no engine (demo mode). Unset, "Live demo" explains how to run it.
  demo: process.env.NEXT_PUBLIC_DEMO_URL || "/docs/install#try-it",
  license: "MIT",
  version: pkg.version, // bumped with farrier/__init__.py and web/package.json; the release workflow checks they match
};

/** site.url without the base path, for metadataBase: Next adds the base path to metadata URLs itself. */
export const siteOrigin = basePath && site.url.endsWith(basePath) ? site.url.slice(0, -basePath.length) : site.url;

/** A file in public/ (raw <img> and CSS urls don't get the base path that next/link adds). */
export const asset = (path: string) => `${basePath}${path}`;
