/**
 * Where the dashboard's documentation links lead. The docs are a separate static site (site/ in the
 * repository). FARRIER_DOCS_URL, read per request, points a private install at its own copy, so one
 * image serves every deployment. Otherwise NEXT_PUBLIC_DOCS_URL from the build, else the public docs site.
 */
export const GITHUB_DOCS_URL = "https://github.com/gagankarthik/farrier/tree/main/site/src/app/docs";
export const PUBLIC_DOCS_URL = "https://farrier-erc1.vercel.app/docs";
export const DEFAULT_DOCS_URL = process.env.NEXT_PUBLIC_DOCS_URL || PUBLIC_DOCS_URL;

const GITHUB_TREE = /^https:\/\/github\.com\/[^/]+\/[^/]+\/tree\//;

/** The docs address for a page path such as "security" or "/docs/security". */
export function docsUrl(path = "", env: Record<string, string | undefined> = process.env): string {
  const configured = env.FARRIER_DOCS_URL?.trim();
  const base = (configured && /^https?:\/\//.test(configured) ? configured : DEFAULT_DOCS_URL).replace(/\/+$/, "");
  const slug = path.replace(/^\/+/, "").replace(/^docs(\/|$)/, "").replace(/\/+$/, "");
  if (!slug || !/^[a-z0-9-]+(\/[a-z0-9-]+)*$/i.test(slug)) return base;
  // on GitHub a page renders (with working #anchors) only when its file is linked directly
  return GITHUB_TREE.test(base) ? `${base.replace("/tree/", "/blob/")}/${slug}/page.mdx` : `${base}/${slug}/`;
}
