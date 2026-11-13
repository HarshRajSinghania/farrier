/**
 * Which sign-in the dashboard uses, read from the environment at request time (so one image
 * serves every deployment).
 *
 *   oidc   FARRIER_OIDC_ISSUER is set: single sign-on with per-user roles
 *   saml   FARRIER_SAML_IDP_METADATA_URL or FARRIER_SAML_IDP_SSO_URL is set: SAML 2.0 single sign-on, same roles
 *   basic  FARRIER_DASHBOARD_PASSWORD is set: one shared login, treated as admin
 *   none   neither: local development and demo mode only (see the production guard)
 *
 * One single sign-on method at a time: with both OIDC and SAML set, sign-in fails closed.
 */
import { configuredOrigin, redirectUriProblem } from "./request";
import { parseList, type RoleMapping } from "./roles";
import { secretProblem } from "./seal";

export type AuthMode = "oidc" | "saml" | "basic" | "none";

type Env = Record<string, string | undefined>;

const samlSet = (env: Env) => Boolean(env.FARRIER_SAML_IDP_METADATA_URL?.trim() || env.FARRIER_SAML_IDP_SSO_URL?.trim());

export function authMode(): AuthMode {
  if (process.env.FARRIER_OIDC_ISSUER) return "oidc";
  if (samlSet(process.env)) return "saml";
  if (process.env.FARRIER_DASHBOARD_PASSWORD) return "basic";
  return "none";
}

/** What every single sign-on method shares: the session cookie and the group-to-role mapping. */
export interface SessionConfig {
  sessionSecret: string;
  roles: RoleMapping;
  /** claim (OIDC) or attribute (SAML) whose values are matched against each project's member groups */
  projectClaim: string;
  idleSeconds: number;
  maxSeconds: number;
}

export interface OidcConfig extends SessionConfig {
  issuer: string;
  clientId: string;
  clientSecret: string;
  scopes: string;
  /** fixed redirect URI; otherwise <public origin>/auth/callback */
  redirectUri: string | null;
  postLogoutRedirectUri: string | null;
}

export interface SamlConfig extends SessionConfig {
  /** the IdP's metadata document (SSO URL, signing certificates, entity id), fetched over https */
  idpMetadataUrl: string | null;
  /** when set, these win over the metadata */
  idpSsoUrl: string | null;
  idpCerts: string[];
  idpEntityId: string | null;
  /** this dashboard's entity id (default: <public origin>/auth/saml/metadata) */
  spEntityId: string | null;
  emailAttribute: string;
  nameAttribute: string;
}

const minutes = (v: string | undefined, fallback: number) => {
  const n = Number(v);
  return Number.isFinite(n) && n > 0 ? Math.round(n * 60) : fallback * 60;
};

export type ConfigResult<T = OidcConfig> = { ok: true; config: T } | { ok: false; error: string };

/** Role mapping and session timeouts, from FARRIER_<OIDC|SAML>_*_GROUPS and FARRIER_SESSION_*. */
function shared(env: Env, kind: "OIDC" | "SAML", claim: string, projectClaim: string): SessionConfig {
  return {
    sessionSecret: env.FARRIER_SESSION_SECRET!,
    roles: {
      claim,
      admin: parseList(env[`FARRIER_${kind}_ADMIN_GROUPS`]),
      operator: parseList(env[`FARRIER_${kind}_OPERATOR_GROUPS`]),
      allowed: parseList(env[`FARRIER_${kind}_ALLOWED_GROUPS`]),
    },
    projectClaim,
    idleSeconds: minutes(env.FARRIER_SESSION_IDLE_MINUTES, 60),
    maxSeconds: minutes(env.FARRIER_SESSION_MAX_HOURS ? String(Number(env.FARRIER_SESSION_MAX_HOURS) * 60) : undefined, 12 * 60),
  };
}

const BOTH = "FARRIER_OIDC_ISSUER and FARRIER_SAML_IDP_* are both set; configure one single sign-on method";

/** https, or plain http for a provider on this machine (development). */
export function httpsOrLocal(value: string): boolean {
  try {
    const u = new URL(value);
    return u.protocol === "https:" || (u.protocol === "http:" && ["localhost", "127.0.0.1", "[::1]"].includes(u.hostname));
  } catch {
    return false;
  }
}

/** The OIDC settings, or why they are unusable. Misconfiguration fails closed: no fallback to Basic. */
export function oidcConfig(): ConfigResult {
  const env = process.env;
  const issuer = env.FARRIER_OIDC_ISSUER?.trim();
  if (!issuer) return { ok: false, error: "FARRIER_OIDC_ISSUER is not set" };
  if (samlSet(env)) return { ok: false, error: BOTH };
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
  const claim = env.FARRIER_OIDC_ROLE_CLAIM?.trim() || "groups";
  return {
    ok: true,
    config: {
      ...shared(env, "OIDC", claim, env.FARRIER_OIDC_PROJECT_CLAIM?.trim() || claim),
      issuer,
      clientId: env.FARRIER_OIDC_CLIENT_ID,
      clientSecret: env.FARRIER_OIDC_CLIENT_SECRET,
      scopes: scopes.join(" "),
      redirectUri: env.FARRIER_OIDC_REDIRECT_URI?.trim() || null,
      postLogoutRedirectUri: env.FARRIER_OIDC_POST_LOGOUT_REDIRECT_URI?.trim() || null,
    },
  };
}

/** PEM blocks, or bare base64 bodies separated by commas or spaces, as IdP consoles hand them out. */
export function parseCerts(value: string | undefined): string[] {
  const v = (value ?? "").replace(/\\n/g, "\n").trim();
  if (!v) return [];
  return v.match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g) ?? v.split(/[,\s]+/).filter(Boolean);
}

/** The SAML settings, or why they are unusable. Like OIDC, misconfiguration fails closed. */
export function samlConfig(env: Env = process.env): ConfigResult<SamlConfig> {
  if (env.FARRIER_OIDC_ISSUER) return { ok: false, error: BOTH };
  const metadataUrl = env.FARRIER_SAML_IDP_METADATA_URL?.trim() || null;
  const ssoUrl = env.FARRIER_SAML_IDP_SSO_URL?.trim() || null;
  const certs = parseCerts(env.FARRIER_SAML_IDP_CERT);
  if (!metadataUrl && !ssoUrl)
    return { ok: false, error: "set FARRIER_SAML_IDP_METADATA_URL, or FARRIER_SAML_IDP_SSO_URL and FARRIER_SAML_IDP_CERT" };
  if (!metadataUrl && !certs.length) return { ok: false, error: "FARRIER_SAML_IDP_CERT is not set (the IdP's signing certificate)" };
  if (metadataUrl && !httpsOrLocal(metadataUrl)) return { ok: false, error: "FARRIER_SAML_IDP_METADATA_URL must be an https:// URL" };
  if (ssoUrl && !httpsOrLocal(ssoUrl)) return { ok: false, error: "FARRIER_SAML_IDP_SSO_URL must be an https:// URL" };
  const bad = secretProblem(env.FARRIER_SESSION_SECRET);
  if (bad) return { ok: false, error: bad };
  // the ACS URL and audience must come from configuration, never the request's Host header
  if (env.NODE_ENV === "production" && !configuredOrigin(env))
    return { ok: false, error: "set NEXT_PUBLIC_SITE_URL to the dashboard's public URL" };
  const groups = env.FARRIER_SAML_GROUPS_ATTRIBUTE?.trim() || "groups";
  return {
    ok: true,
    config: {
      ...shared(env, "SAML", groups, env.FARRIER_SAML_PROJECT_ATTRIBUTE?.trim() || groups),
      idpMetadataUrl: metadataUrl,
      idpSsoUrl: ssoUrl,
      idpCerts: certs,
      idpEntityId: env.FARRIER_SAML_IDP_ENTITY_ID?.trim() || null,
      spEntityId: env.FARRIER_SAML_SP_ENTITY_ID?.trim() || null,
      emailAttribute: env.FARRIER_SAML_EMAIL_ATTRIBUTE?.trim() || "email",
      nameAttribute: env.FARRIER_SAML_NAME_ATTRIBUTE?.trim() || "displayName",
    },
  };
}

/** The session settings of whichever single sign-on method is on. */
export function ssoConfig(): ConfigResult<SessionConfig> {
  return authMode() === "saml" ? samlConfig() : oidcConfig();
}
