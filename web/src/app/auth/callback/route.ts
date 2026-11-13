/**
 * GET /auth/callback  The provider sends the browser back here with ?code&state.
 *
 * Checks, in order: the login transaction cookie (sealed, unexpired), state, the RFC 9207
 * `iss` parameter when sent, the code exchange (PKCE verifier + client secret), and the ID
 * token (signature via JWKS, issuer, audience, expiry, nonce, azp). Then maps the user's
 * groups to a role and starts the session.
 */
import { type NextRequest, NextResponse } from "next/server";
import { authMode, oidcConfig } from "@/lib/auth/config";
import { noStore, projectGroups, toSignin } from "@/lib/auth/flow";
import { discover, exchangeCode, OidcError, userInfo, verifyIdToken } from "@/lib/auth/oidc";
import { claimValues, mapRole } from "@/lib/auth/roles";
import { unseal } from "@/lib/auth/seal";
import { clearSession, now, publicOrigin, TX_COOKIE, TX_PURPOSE, writeSession } from "@/lib/auth/session";

interface Tx extends Record<string, unknown> {
  state: string;
  nonce: string;
  verifier: string;
  returnTo: string;
  uri: string;
}

/** Keep the ID token for the logout hint only while the cookie stays well under 4 KB. */
const MAX_HINT = 1500;

const str = (v: unknown) => (typeof v === "string" && v ? v : undefined);

export async function GET(req: NextRequest) {
  const done = (res: NextResponse) => {
    res.cookies.set(TX_COOKIE, "", { path: "/auth", maxAge: 0 });
    return noStore(res);
  };
  if (authMode() !== "oidc") return done(toSignin(req));
  const cfg = oidcConfig();
  if (!cfg.ok) return done(toSignin(req, "misconfigured"));
  const c = cfg.config;
  const q = req.nextUrl.searchParams;

  const tx = await unseal<Tx>(req.cookies.get(TX_COOKIE)?.value, c.sessionSecret, TX_PURPOSE);
  if (!tx) return done(toSignin(req, "stale"));
  if (!q.get("state") || q.get("state") !== tx.state) return done(toSignin(req, "stale", tx.returnTo));

  const idpError = q.get("error");
  if (idpError) {
    console.warn(`[farrier] sign-in refused by the provider: ${idpError} ${q.get("error_description") ?? ""}`);
    return done(toSignin(req, idpError === "access_denied" ? "denied" : "provider", tx.returnTo));
  }
  const code = q.get("code");
  if (!code) return done(toSignin(req, "provider", tx.returnTo));

  try {
    const meta = await discover(c);
    const iss = q.get("iss");
    if (iss && iss !== meta.issuer) throw new OidcError("the iss parameter does not match the provider");

    const tokens = await exchangeCode(meta, c, { code, verifier: tx.verifier, redirectUri: tx.uri });
    const idClaims = await verifyIdToken(meta, c, tokens.id_token, tx.nonce);
    const sub = idClaims.sub!;

    // Okta and others may leave groups out of the ID token; UserInfo usually has them.
    let claims: Record<string, unknown> = idClaims;
    const missing = (cl: Record<string, unknown>) =>
      claimValues(cl, c.roles.claim).length === 0 || claimValues(cl, c.projectClaim).length === 0;
    if (missing(claims) && tokens.access_token) {
      claims = { ...(await userInfo(meta, tokens.access_token, sub)), ...idClaims };
      if (claimValues(claims, c.roles.claim).length === 0 && "_claim_names" in idClaims) {
        console.warn("[farrier] the ID token has a group overage (_claim_names); use app roles (FARRIER_OIDC_ROLE_CLAIM=roles)");
      }
    }

    const role = mapRole(claims, c.roles);
    const email = str(claims.email) ?? str(claims.preferred_username) ?? str(claims.upn);
    if (!role) {
      console.warn(`[farrier] sign-in denied for ${email ?? sub}: in none of FARRIER_OIDC_ALLOWED_GROUPS`);
      return done(toSignin(req, "forbidden"));
    }

    const res = NextResponse.redirect(new URL(tx.returnTo, publicOrigin(req)), 303);
    const t = now();
    clearSession(res);
    await writeSession(res, req, c, {
      sub,
      email,
      name: str(claims.name),
      role,
      grp: projectGroups(claimValues(claims, c.projectClaim)),
      idt: tokens.id_token.length <= MAX_HINT ? tokens.id_token : undefined,
      sat: t,
      lsa: t,
    });
    console.info(`[farrier] signed in: ${email ?? sub} as ${role}`);
    return done(res);
  } catch (e) {
    console.error(`[farrier] sign-in failed: ${(e as Error).message}`);
    return done(toSignin(req, "provider", tx.returnTo));
  }
}
