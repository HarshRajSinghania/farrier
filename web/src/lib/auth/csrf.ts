/**
 * Same-origin check for state-changing requests. Pure, so it is testable without a server.
 *
 * Browsers set Sec-Fetch-Site on every request and pages cannot forge it; older browsers
 * still send Origin on POST/DELETE. A request with neither is not from a browser page and,
 * since the dashboard is the only legitimate caller, is refused.
 */

interface HeaderBag {
  get(name: string): string | null;
}

export function isSameOrigin(headers: HeaderBag, allowedOrigins: string[]): boolean {
  const site = headers.get("sec-fetch-site");
  if (site) return site === "same-origin";
  const origin = headers.get("origin");
  if (!origin || origin === "null") return false;
  const want = new Set(allowedOrigins.map((o) => o.toLowerCase().replace(/\/+$/, "")));
  return want.has(origin.toLowerCase().replace(/\/+$/, ""));
}

export function isSafeMethod(method: string): boolean {
  return method === "GET" || method === "HEAD" || method === "OPTIONS";
}

/** Only same-site dashboard paths may be a post-sign-in destination (no open redirects). */
export function safeReturnTo(value: string | null | undefined, fallback = "/dashboard"): string {
  if (!value || !value.startsWith("/dashboard")) return fallback;
  if (/[\\\r\n\t]/.test(value) || value.startsWith("//")) return fallback;
  return value;
}
