import "server-only";
import { readFileSync } from "node:fs";
import path from "node:path";
import GithubSlugger from "github-slugger";
import { DOCS_FLAT } from "./docs-nav";

export type SearchEntry = { href: string; page: string; group: string; heading: string | null; text: string };

const DOCS_DIR = path.join(process.cwd(), "src", "app", "docs");

/** Every docs page and its h2/h3 headings, read from the MDX sources at build time. */
export function buildDocsIndex(): SearchEntry[] {
  const out: SearchEntry[] = [];
  for (const { href, label, group } of DOCS_FLAT) {
    const page: SearchEntry = { href, page: label, group, heading: null, text: "" };
    out.push(page);
    const slug = href.replace(/^\/docs\/?/, "");
    let src = "";
    try {
      src = readFileSync(path.join(DOCS_DIR, slug, "page.mdx"), "utf8");
    } catch {
      continue;
    }
    const slugger = new GithubSlugger(); // same ids rehype-slug gives the headings
    let fenced = false;
    let current = page;
    for (const line of src.split("\n")) {
      if (line.startsWith("```")) fenced = !fenced;
      const m = !fenced && /^(#{2,3})\s+(.+)$/.exec(line);
      if (m) {
        const text = m[2].replace(/`/g, "").trim();
        current = { href: `${href}#${slugger.slug(text)}`, page: label, group, heading: text, text: "" };
        out.push(current);
      } else if (!line.startsWith("export ") && !line.startsWith("# ") && current.text.length < 1500) {
        current.text += " " + plain(line);
      }
    }
  }
  return out;
}

/** Markdown and MDX to plain words for searching. */
function plain(line: string) {
  return line
    .replace(/<[^>]+>/g, " ")
    .replace(/\[([^\]]+)\]\([^)]+\)/g, "$1")
    .replace(/[`*_|#>]/g, " ")
    .replace(/\s+/g, " ")
    .trim();
}
