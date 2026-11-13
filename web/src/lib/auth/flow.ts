/** Shared pieces of the /auth routes. */
import "server-only";
import { NextResponse, type NextRequest } from "next/server";
import type { OidcConfig, SamlConfig } from "./config";
import { safeReturnTo } from "./csrf";
import type { Sp } from "./saml";
import { publicOrigin } from "./session";

export function redirectUri(req: NextRequest, cfg: OidcConfig) {
  return cfg.redirectUri ?? `${publicOrigin(req)}/auth/callback`;
}

export function postLogoutUri(req: NextRequest, cfg: OidcConfig) {
  return cfg.postLogoutRedirectUri ?? `${publicOrigin(req)}/auth/signin?signed_out=1`;
}

/** This dashboard as a SAML service provider: entity id (default: the metadata URL) and ACS URL. */
export function samlSp(req: NextRequest, cfg: SamlConfig): Sp {
  const origin = publicOrigin(req);
  return { entityId: cfg.spEntityId ?? `${origin}/auth/saml/metadata`, acsUrl: `${origin}/auth/saml/acs` };
}

/** Back to the sign-in page with an error code the page knows how to explain. */
export function toSignin(req: NextRequest, error?: string, returnTo?: string | null) {
  const u = new URL("/auth/signin", publicOrigin(req));
  if (error) u.searchParams.set("error", error);
  const rt = safeReturnTo(returnTo, "");
  if (rt) u.searchParams.set("returnTo", rt);
  return NextResponse.redirect(u, 303);
}

export function noStore(res: NextResponse) {
  res.headers.set("cache-control", "no-store");
  return res;
}

/**
 * The groups kept in the session cookie for project membership, capped so the cookie stays under 4 KB.
 * A user with more groups than fit loses the rest: they see fewer projects, never more.
 */
const MAX_GROUPS_CHARS = 1500;
export function projectGroups(values: string[]): string[] {
  const out: string[] = [];
  let used = 0;
  for (const v of values) {
    if (v.length > 256 || used + v.length + 3 > MAX_GROUPS_CHARS) continue;
    out.push(v);
    used += v.length + 3;
  }
  if (out.length < values.length) console.warn(`[farrier] kept ${out.length} of ${values.length} groups for project membership`);
  return out;
}
