/**
 * Pure helpers for what a request may be trusted to say about itself. No imports, so they are
 * testable without a server (auth.test.mjs).
 */

interface HeaderBag {
  get(name: string): string | null;
}

type Env = Record<string, string | undefined>;

/** The site's configured public origin: FARRIER_OIDC_REDIRECT_URI's, else NEXT_PUBLIC_SITE_URL's, else null. */
export function configuredOrigin(env: Env): string | null {
  for (const v of [env.FARRIER_OIDC_REDIRECT_URI, env.NEXT_PUBLIC_SITE_URL]) {
    try {
      if (v?.trim()) return new URL(v.trim()).origin;
    } catch {
      /* malformed: try the next one */
    }
  }
  return null;
}

/**
 * Why the OIDC redirect URI can't be trusted, or null. In production it must come from configuration,
 * never from the request's Host / X-Forwarded-Host (which a client or a misconfigured proxy controls).
 */
export function redirectUriProblem(env: Env): string | null {
  if (env.NODE_ENV !== "production" || configuredOrigin(env)) return null;
  return "set FARRIER_OIDC_REDIRECT_URI (or NEXT_PUBLIC_SITE_URL) to the dashboard's public URL";
}

/**
 * The client address for the sign-in lockout. Each of FARRIER_TRUSTED_PROXY_HOPS (default 1) proxies
 * appends one X-Forwarded-For entry, so the client is that many entries from the right; anything further
 * left is whatever the client sent. 0 ignores X-Forwarded-For (no proxy in front): X-Real-IP is used.
 */
export function clientAddress(headers: HeaderBag, env: Env): string {
  const n = Number(env.FARRIER_TRUSTED_PROXY_HOPS ?? "1");
  const trusted = Number.isInteger(n) && n >= 0 ? n : 1;
  const hops = headers.get("x-forwarded-for")?.split(",").map((h) => h.trim()).filter(Boolean) ?? [];
  if (trusted > 0 && hops.length) return hops[Math.max(0, hops.length - trusted)];
  return headers.get("x-real-ip") || "unknown";
}

function sameString(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

/** Paths reachable without FARRIER_REQUIRE_HEADER: platform health probes don't send it. */
const UNGUARDED = new Set(["/api/health"]);

/**
 * FARRIER_REQUIRE_HEADER=Name:value (e.g. X-Azure-FDID:<Front Door id>): requests without that exact
 * header value are refused, so the app is only reachable through the proxy that adds it.
 * Returns null when the request may continue, else the HTTP status to answer with.
 */
export function requiredHeaderStatus(headers: HeaderBag, pathname: string, env: Env): 403 | 500 | null {
  const spec = env.FARRIER_REQUIRE_HEADER?.trim();
  if (!spec || UNGUARDED.has(pathname)) return null;
  const i = spec.indexOf(":");
  const name = i > 0 ? spec.slice(0, i).trim() : "";
  const want = i > 0 ? spec.slice(i + 1).trim() : "";
  if (!name || !want) return 500; // malformed: fail closed
  return sameString(headers.get(name) ?? "", want) ? null : 403;
}
