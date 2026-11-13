/**
 * The dashboard session: one encrypted cookie (see seal.ts), HttpOnly, SameSite=Lax, Secure
 * and __Host- prefixed when the site is served over https. It expires on whichever comes
 * first: FARRIER_SESSION_IDLE_MINUTES without a request, or FARRIER_SESSION_MAX_HOURS after
 * sign-in. Nothing is stored server-side, so it works across replicas.
 */
import type { NextRequest, NextResponse } from "next/server";
import type { SessionConfig } from "./config";
import { configuredOrigin } from "./request";
import type { Role } from "./roles";
import { seal, unseal } from "./seal";

export const SESSION_PURPOSE = "farrier-session+jwe";
export const TX_PURPOSE = "farrier-oidc-tx+jwe";
const SECURE_NAME = "__Host-farrier_session";
const PLAIN_NAME = "farrier_session";
export const TX_COOKIE = "farrier_oidc_tx";
export const SAML_TX_PURPOSE = "farrier-saml-tx+jwe";
/** SameSite=None (so it comes back on the IdP's cross-site POST), hence always Secure; scoped to /auth/saml. */
export const SAML_TX_COOKIE = "farrier_saml_tx";
/** Refresh the idle clock at most this often, so most requests don't rewrite the cookie. */
const TOUCH_AFTER = 60;

export interface Session {
  sub: string;
  email?: string;
  name?: string;
  role: Role;
  /** values of FARRIER_OIDC_PROJECT_CLAIM / FARRIER_SAML_PROJECT_ATTRIBUTE (project membership is worked out per request from these) */
  grp?: string[];
  /** the ID token, kept only when small enough, as the logout hint */
  idt?: string;
  /** signed in at (unix seconds) */
  sat: number;
  /** last seen at (unix seconds) */
  lsa: number;
}

export const now = () => Math.floor(Date.now() / 1000);

/**
 * The origin users reach this site on. In production, the configured one (FARRIER_OIDC_REDIRECT_URI or
 * NEXT_PUBLIC_SITE_URL); otherwise a reverse proxy's X-Forwarded-* headers, then the Host header.
 */
export function publicOrigin(req: NextRequest): string {
  const fixed = process.env.NODE_ENV === "production" ? configuredOrigin(process.env) : null;
  if (fixed) return fixed;
  const proto = req.headers.get("x-forwarded-proto")?.split(",")[0].trim() || req.nextUrl.protocol.replace(":", "");
  const host = req.headers.get("x-forwarded-host")?.split(",")[0].trim() || req.headers.get("host") || req.nextUrl.host;
  return `${proto}://${host}`;
}

/** Origins a same-origin request may carry: the public origin, the raw host, and any configured URL. */
export function allowedOrigins(req: NextRequest): string[] {
  const out = new Set([publicOrigin(req), req.nextUrl.origin]);
  for (const v of [process.env.FARRIER_OIDC_REDIRECT_URI, process.env.NEXT_PUBLIC_SITE_URL]) {
    try {
      if (v) out.add(new URL(v).origin);
    } catch {
      /* ignore malformed */
    }
  }
  return [...out];
}

export const isSecure = (req: NextRequest) => publicOrigin(req).startsWith("https:");

function cookieName(req: NextRequest) {
  return isSecure(req) ? SECURE_NAME : PLAIN_NAME;
}

export function hasSessionCookie(req: NextRequest) {
  return req.cookies.has(SECURE_NAME) || req.cookies.has(PLAIN_NAME);
}

/** The session if it is intact and inside both timeouts. */
export async function readSession(req: NextRequest, cfg: SessionConfig): Promise<(Session & { exp: number }) | null> {
  const raw = req.cookies.get(cookieName(req))?.value;
  const s = await unseal<Session & Record<string, unknown>>(raw, cfg.sessionSecret, SESSION_PURPOSE);
  if (!s || typeof s.sub !== "string" || typeof s.lsa !== "number" || typeof s.sat !== "number") return null;
  const t = now();
  if (t - s.lsa > cfg.idleSeconds) return null;
  if (t - s.sat > cfg.maxSeconds || s.exp <= t) return null;
  return s;
}

export async function writeSession(res: NextResponse, req: NextRequest, cfg: SessionConfig, s: Session) {
  const exp = s.sat + cfg.maxSeconds;
  const value = await seal({ ...s }, cfg.sessionSecret, SESSION_PURPOSE, exp);
  res.cookies.set(cookieName(req), value, {
    httpOnly: true,
    secure: isSecure(req),
    sameSite: "lax",
    path: "/",
    maxAge: Math.max(0, exp - now()),
  });
}

/** Slide the idle window forward when it is worth a cookie rewrite. */
export async function touchSession(res: NextResponse, req: NextRequest, cfg: SessionConfig, s: Session) {
  if (now() - s.lsa < TOUCH_AFTER) return;
  const { sub, email, name, role, grp, idt, sat } = s;
  await writeSession(res, req, cfg, { sub, email, name, role, grp, idt, sat, lsa: now() });
}

export function clearSession(res: NextResponse) {
  for (const name of [SECURE_NAME, PLAIN_NAME]) {
    res.cookies.set(name, "", { path: "/", maxAge: 0, httpOnly: true, sameSite: "lax", secure: name === SECURE_NAME });
  }
}
