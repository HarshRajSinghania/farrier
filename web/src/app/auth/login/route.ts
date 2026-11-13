/**
 * GET /auth/login?returnTo=/dashboard/...  Starts single sign-on.
 *
 * OIDC: stores state, nonce and the PKCE verifier in a short-lived encrypted cookie and sends the
 * browser to the provider. SAML: stores the AuthnRequest ID (for InResponseTo) the same way and
 * sends the browser to the IdP with the request (HTTP-Redirect binding).
 */
import { NextResponse, type NextRequest } from "next/server";
import { authMode, oidcConfig, samlConfig } from "@/lib/auth/config";
import { safeReturnTo } from "@/lib/auth/csrf";
import { noStore, redirectUri, samlSp, toSignin } from "@/lib/auth/flow";
import { authorizeUrl, discover, pkceChallenge, randomToken } from "@/lib/auth/oidc";
import { authnRequestUrl, newRequestId, REQUEST_TTL_MS, resolveIdp, spProblem } from "@/lib/auth/saml";
import { seal } from "@/lib/auth/seal";
import { isSecure, now, SAML_TX_COOKIE, SAML_TX_PURPOSE, TX_COOKIE, TX_PURPOSE } from "@/lib/auth/session";

const TX_SECONDS = 10 * 60;

async function samlLogin(req: NextRequest, returnTo: string) {
  const cfg = samlConfig();
  if (!cfg.ok) {
    console.error(`[farrier] SSO misconfigured: ${cfg.error}`);
    return noStore(toSignin(req, "misconfigured"));
  }
  const sp = samlSp(req, cfg.config);
  const bad = spProblem(sp);
  if (bad) {
    console.error(`[farrier] SSO misconfigured: ${bad}`);
    return noStore(toSignin(req, "misconfigured"));
  }
  const id = newRequestId();
  let url: string;
  try {
    url = await authnRequestUrl(await resolveIdp(cfg.config), sp, id);
  } catch (e) {
    console.error(`[farrier] SAML sign-in could not start: ${(e as Error).message}`);
    return noStore(toSignin(req, "provider", returnTo));
  }
  const seconds = REQUEST_TTL_MS / 1000;
  const tx = await seal({ id, returnTo, sp: sp.entityId, acs: sp.acsUrl }, cfg.config.sessionSecret, SAML_TX_PURPOSE, now() + seconds);
  const res = NextResponse.redirect(url, 303);
  // SameSite=None: the IdP returns the browser with a cross-site POST, which drops Lax cookies.
  // Browsers require Secure with None, so spProblem() allows only https, or http://localhost, where
  // Chrome and Firefox accept Secure cookies (Safari may not: develop in one of those).
  res.cookies.set(SAML_TX_COOKIE, tx, { httpOnly: true, secure: true, sameSite: "none", path: "/auth/saml", maxAge: seconds });
  return noStore(res);
}

export async function GET(req: NextRequest) {
  const returnTo = safeReturnTo(req.nextUrl.searchParams.get("returnTo"));
  if (authMode() === "saml") return samlLogin(req, returnTo);
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
