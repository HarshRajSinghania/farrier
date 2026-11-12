/** HTTP Basic credentials for the fallback login (FARRIER_DASHBOARD_PASSWORD). */

export function safeEqual(a: string, b: string): boolean {
  let diff = a.length ^ b.length;
  for (let i = 0; i < Math.max(a.length, b.length); i++) diff |= (a.charCodeAt(i) || 0) ^ (b.charCodeAt(i) || 0);
  return diff === 0;
}

/** [user, password] from an Authorization header, or null when absent or malformed. */
export function parseBasic(header: string | null): [string, string] | null {
  if (!header?.startsWith("Basic ")) return null;
  try {
    const [user, ...rest] = atob(header.slice(6)).split(":");
    return [user, rest.join(":")];
  } catch {
    return null;
  }
}

/** The signed-in user when the header carries the configured credentials. */
export function checkBasic(header: string | null): string | null {
  const password = process.env.FARRIER_DASHBOARD_PASSWORD;
  if (!password) return null;
  const want = process.env.FARRIER_DASHBOARD_USER || "admin";
  const got = parseBasic(header);
  if (!got) return null;
  const ok = safeEqual(got[0], want) && safeEqual(got[1], password);
  return ok ? got[0] : null;
}
