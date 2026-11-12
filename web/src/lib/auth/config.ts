/**
 * Which sign-in the dashboard uses, read from the environment at request time (so one image
 * serves every deployment).
 *
 *   oidc   FARRIER_OIDC_ISSUER is set: single sign-on with per-user roles
 *   basic  FARRIER_DASHBOARD_PASSWORD is set: one shared login, treated as admin
 *   none   neither: local development and demo mode only (see the production guard)
 */
import { redirectUriProblem } from "./request";
import { parseList, type RoleMapping } from "./roles";
import { secretProblem } from "./seal";

export type AuthMode = "oidc" | "basic" | "none";

export function authMode(): AuthMode {
  if (process.env.FARRIER_OIDC_ISSUER) return "oidc";
  if (process.env.FARRIER_DASHBOARD_PASSWORD) return "basic";
  return "none";
}

export interface OidcConfig {
  issuer: string;
  clientId: string;
  clientSecret: string;
  scopes: string;
  sessionSecret: string;
  roles: RoleMapping;
  /** fixed redirect URI; otherwise <public origin>/auth/callback */
  redirectUri: string | null;
  postLogoutRedirectUri: string | null;
  idleSeconds: number;
  maxSeconds: number;
}

const minutes = (v: string | undefined, fallback: number) => {
  const n = Number(v);
  return Number.isFinite(n) && n > 0 ? Math.round(n * 60) : fallback * 60;
};

export type ConfigResult = { ok: true; config: OidcConfig } | { ok: false; error: string };

/** The OIDC settings, or why they are unusable. Misconfiguration fails closed: no fallback to Basic. */
export function oidcConfig(): ConfigResult {
  const env = process.env;
  const issuer = env.FARRIER_OIDC_ISSUER?.trim();
  if (!issuer) return { ok: false, error: "FARRIER_OIDC_ISSUER is not set" };
  if (!env.FARRIER_OIDC_CLIENT_ID) return { ok: false, error: "FARRIER_OIDC_CLIENT_ID is not set" };
  if (!env.FARRIER_OIDC_CLIENT_SECRET) return { ok: false, error: "FARRIER_OIDC_CLIENT_SECRET is not set" };
  const bad = secretProblem(env.FARRIER_SESSION_SECRET);
  if (bad) return { ok: false, error: bad };
  try {
    const u = new URL(issuer);
    if (u.protocol !== "https:" && !["localhost", "127.0.0.1", "[::1]"].includes(u.hostname))
      return { ok: false, error: "FARRIER_OIDC_ISSUER must be an https:// URL" };
  } catch {
    return { ok: false, error: "FARRIER_OIDC_ISSUER is not a valid URL" };
  }
  const redirect = redirectUriProblem(env);
  if (redirect) return { ok: false, error: redirect };
  const scopes = (env.FARRIER_OIDC_SCOPES?.trim() || "openid profile email groups").split(/\s+/);
  if (!scopes.includes("openid")) scopes.unshift("openid");
  return {
    ok: true,
    config: {
      issuer,
      clientId: env.FARRIER_OIDC_CLIENT_ID,
      clientSecret: env.FARRIER_OIDC_CLIENT_SECRET,
      scopes: scopes.join(" "),
      sessionSecret: env.FARRIER_SESSION_SECRET!,
      roles: {
        claim: env.FARRIER_OIDC_ROLE_CLAIM?.trim() || "groups",
        admin: parseList(env.FARRIER_OIDC_ADMIN_GROUPS),
        operator: parseList(env.FARRIER_OIDC_OPERATOR_GROUPS),
        allowed: parseList(env.FARRIER_OIDC_ALLOWED_GROUPS),
      },
      redirectUri: env.FARRIER_OIDC_REDIRECT_URI?.trim() || null,
      postLogoutRedirectUri: env.FARRIER_OIDC_POST_LOGOUT_REDIRECT_URI?.trim() || null,
      idleSeconds: minutes(env.FARRIER_SESSION_IDLE_MINUTES, 60),
      maxSeconds: minutes(env.FARRIER_SESSION_MAX_HOURS ? String(Number(env.FARRIER_SESSION_MAX_HOURS) * 60) : undefined, 12 * 60),
    },
  };
}
