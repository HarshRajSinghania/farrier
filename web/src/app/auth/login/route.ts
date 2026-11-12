/**
 * GET /auth/login?returnTo=/dashboard/...  Starts single sign-on: stores state, nonce and the
 * PKCE verifier in a short-lived encrypted cookie and sends the browser to the provider.
 */
import { NextResponse, type NextRequest } from "next/server";
import { authMode, oidcConfig } from "@/lib/auth/config";
import { safeReturnTo } from "@/lib/auth/csrf";
import { noStore, redirectUri, toSignin } from "@/lib/auth/flow";
import { authorizeUrl, discover, pkceChallenge, randomToken } from "@/lib/auth/oidc";
import { seal } from "@/lib/auth/seal";
import { isSecure, now, TX_COOKIE, TX_PURPOSE } from "@/lib/auth/session";

const TX_SECONDS = 10 * 60;

export async function GET(req: NextRequest) {
  const returnTo = safeReturnTo(req.nextUrl.searchParams.get("returnTo"));
  if (authMode() !== "oidc") {
    // Basic auth or none: nothing to start; the dashboard itself asks for credentials.
    return noStore(NextResponse.redirect(new URL(returnTo, req.url), 303));
  }
  const cfg = oidcConfig();
  if (!cfg.ok) {
    console.error(`[farrier] SSO misconfigured: ${cfg.error}`);
    return noStore(toSignin(req, "misconfigured"));
  }

  let meta;
  try {
    meta = await discover(cfg.config);
  } catch (e) {
    console.error(`[farrier] OIDC discovery failed: ${(e as Error).message}`);
    return noStore(toSignin(req, "provider", returnTo));
  }

  const state = randomToken();
  const nonce = randomToken();
  const verifier = randomToken(48);
  const uri = redirectUri(req, cfg.config);
  const tx = await seal({ state, nonce, verifier, returnTo, uri }, cfg.config.sessionSecret, TX_PURPOSE, now() + TX_SECONDS);

  const res = NextResponse.redirect(
    authorizeUrl(meta, cfg.config, { redirectUri: uri, state, nonce, challenge: await pkceChallenge(verifier) }),
    303,
  );
  // Lax so the cookie comes back on the provider's top-level redirect to /auth/callback.
  res.cookies.set(TX_COOKIE, tx, {
    httpOnly: true,
    secure: isSecure(req),
    sameSite: "lax",
    path: "/auth",
    maxAge: TX_SECONDS,
  });
  return noStore(res);
}
