import assert from "node:assert/strict";
import { test } from "node:test";
import { GITHUB_DOCS_URL, docsUrl } from "./docs.ts";

const blob = GITHUB_DOCS_URL.replace("/tree/", "/blob/");

test("docs links default to the source on GitHub, one page file each", () => {
  assert.equal(docsUrl("", {}), GITHUB_DOCS_URL);
  assert.equal(docsUrl("/docs", {}), GITHUB_DOCS_URL);
  assert.equal(docsUrl("security", {}), `${blob}/security/page.mdx`);
});

test("FARRIER_DOCS_URL points at a private copy", () => {
  const env = { FARRIER_DOCS_URL: "https://docs.example.internal/docs/" };
  assert.equal(docsUrl("", env), "https://docs.example.internal/docs");
  assert.equal(docsUrl("/docs/self-hosting", env), "https://docs.example.internal/docs/self-hosting/");
  assert.equal(docsUrl("../evil", env), "https://docs.example.internal/docs");
  assert.equal(docsUrl("security", { FARRIER_DOCS_URL: "javascript:alert(1)" }), `${blob}/security/page.mdx`);
});
