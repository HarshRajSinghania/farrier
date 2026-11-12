/** Shared pieces of the /auth routes. */
import "server-only";
import { NextResponse, type NextRequest } from "next/server";
import type { OidcConfig } from "./config";
import { safeReturnTo } from "./csrf";
import { publicOrigin } from "./session";

export function redirectUri(req: NextRequest, cfg: OidcConfig) {
  return cfg.redirectUri ?? `${publicOrigin(req)}/auth/callback`;
}

export function postLogoutUri(req: NextRequest, cfg: OidcConfig) {
  return cfg.postLogoutRedirectUri ?? `${publicOrigin(req)}/auth/signin?signed_out=1`;
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
