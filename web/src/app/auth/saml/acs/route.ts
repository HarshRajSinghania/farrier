/**
 * POST /auth/saml/acs  The IdP posts the SAMLResponse here (HTTP-POST binding).
 *
 * Checks the login transaction cookie (sealed, unexpired), then the response (lib/auth/saml.ts:
 * signature, InResponseTo against the cookie, issuer, audience, Destination, Recipient, time
 * window, replay). Then maps the groups attribute to a role and starts the same session as OIDC.
 *
 * A cross-site POST by design, so no same-origin check: only a response the IdP signed for the
 * request in this browser's cookie gets through.
 */
import { NextResponse, type NextRequest } from "next/server";
import { authMode, samlConfig } from "@/lib/auth/config";
import { noStore, projectGroups, toSignin } from "@/lib/auth/flow";
import { claimValues, mapRole } from "@/lib/auth/roles";
import { resolveIdp, SamlStatusError, validateResponse } from "@/lib/auth/saml";
import { unseal } from "@/lib/auth/seal";
import { clearSession, now, publicOrigin, SAML_TX_COOKIE, SAML_TX_PURPOSE, writeSession } from "@/lib/auth/session";

interface Tx extends Record<string, unknown> {
  id: string;
  returnTo: string;
  sp: string;
  acs: string;
}

const EMAIL_FORMAT = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress";
const first = (v: unknown) => claimValues({ v }, "v")[0];

export async function POST(req: NextRequest) {
  const done = (res: NextResponse) => {
    res.cookies.set(SAML_TX_COOKIE, "", { path: "/auth/saml", maxAge: 0, httpOnly: true, secure: true, sameSite: "none" });
    return noStore(res);
  };
  if (authMode() !== "saml") return done(toSignin(req));
  const cfg = samlConfig();
  if (!cfg.ok) return done(toSignin(req, "misconfigured"));
  const c = cfg.config;

  const tx = await unseal<Tx>(req.cookies.get(SAML_TX_COOKIE)?.value, c.sessionSecret, SAML_TX_PURPOSE);
  if (!tx) return done(toSignin(req, "stale"));

  let samlResponse: FormDataEntryValue | null = null;
  try {
    samlResponse = (await req.formData()).get("SAMLResponse");
  } catch {
    /* not a form post */
  }
  if (typeof samlResponse !== "string") return done(toSignin(req, "provider", tx.returnTo));

  try {
    const idp = await resolveIdp(c);
    const user = await validateResponse(idp, { entityId: tx.sp, acsUrl: tx.acs }, { id: tx.id, at: tx.iat * 1000 }, samlResponse);
    const attrs = user.attributes;
    const email = first(attrs[c.emailAttribute]) ?? (user.nameIdFormat === EMAIL_FORMAT ? user.nameId : undefined);
    const role = mapRole(attrs, c.roles);
    if (!role) {
      console.warn(`[farrier] sign-in denied for ${email ?? user.nameId}: in none of FARRIER_SAML_ALLOWED_GROUPS`);
      return done(toSignin(req, "forbidden"));
    }

    const res = NextResponse.redirect(new URL(tx.returnTo, publicOrigin(req)), 303);
    const t = now();
    clearSession(res);
    await writeSession(res, req, c, {
      sub: user.nameId,
      email,
      name: first(attrs[c.nameAttribute]),
      role,
      grp: projectGroups(claimValues(attrs, c.projectClaim)),
      sat: t,
      lsa: t,
    });
    console.info(`[farrier] signed in (SAML): ${email ?? user.nameId} as ${role}`);
    return done(res);
  } catch (e) {
    const denied = e instanceof SamlStatusError;
    console.error(`[farrier] SAML sign-in failed: ${(e as Error).message}`);
    return done(toSignin(req, denied ? "denied" : "provider", tx.returnTo));
  }
}
