/**
 * OpenID Connect relying party: Authorization Code flow with PKCE (S256) as a confidential
 * client. Works with any provider that publishes /.well-known/openid-configuration
 * (Okta, Entra ID, Google, Auth0, Keycloak, Authentik, JumpCloud, PingFederate, ...).
 *
 * The ID token is checked for signature (against the provider's JWKS, cached and refetched
 * when a new key id appears), issuer, audience, expiry, nonce, and azp when present.
 */
import "server-only";
import { base64url, createRemoteJWKSet, jwtVerify, type JWTPayload } from "jose";
import type { OidcConfig } from "./config";

export interface ProviderMetadata {
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
  jwks_uri: string;
  userinfo_endpoint?: string;
  end_session_endpoint?: string;
  id_token_signing_alg_values_supported?: string[];
  token_endpoint_auth_methods_supported?: string[];
  code_challenge_methods_supported?: string[];
}

export class OidcError extends Error {}

const DISCOVERY_TTL = 60 * 60_000;
const discovered = new Map<string, { at: number; meta: ProviderMetadata }>();
const jwksSets = new Map<string, ReturnType<typeof createRemoteJWKSet>>();

const trimSlash = (s: string) => s.replace(/\/+$/, "");

/** Provider endpoints must be https; plain http is accepted only for a provider on this machine (development). */
function checkUrl(name: string, value: unknown): string {
  if (typeof value !== "string") throw new OidcError(`provider metadata has no ${name}`);
  const u = new URL(value);
  const local = ["localhost", "127.0.0.1", "[::1]"].includes(u.hostname);
  if (u.protocol !== "https:" && !(u.protocol === "http:" && local)) throw new OidcError(`${name} must use https`);
  return value;
}

/** The provider's metadata, cached for an hour (a stale copy is kept if a refresh fails). */
export async function discover(cfg: OidcConfig): Promise<ProviderMetadata> {
  const key = trimSlash(cfg.issuer);
  const hit = discovered.get(key);
  if (hit && Date.now() - hit.at < DISCOVERY_TTL) return hit.meta;
  try {
    const res = await fetch(`${key}/.well-known/openid-configuration`, {
      headers: { accept: "application/json" },
      signal: AbortSignal.timeout(8000),
      cache: "no-store",
    });
    if (!res.ok) throw new OidcError(`discovery returned HTTP ${res.status}`);
    const m = (await res.json()) as ProviderMetadata;
    // OIDC Discovery 1.0 §4.3: the issuer in the document must be the one we asked for.
    if (typeof m.issuer !== "string" || trimSlash(m.issuer) !== key)
      throw new OidcError(`discovery issuer "${m.issuer}" does not match FARRIER_OIDC_ISSUER`);
    checkUrl("authorization_endpoint", m.authorization_endpoint);
    checkUrl("token_endpoint", m.token_endpoint);
    checkUrl("jwks_uri", m.jwks_uri);
    if (m.userinfo_endpoint) checkUrl("userinfo_endpoint", m.userinfo_endpoint);
    if (m.end_session_endpoint) checkUrl("end_session_endpoint", m.end_session_endpoint);
    if (m.code_challenge_methods_supported && !m.code_challenge_methods_supported.includes("S256"))
      throw new OidcError("the provider does not support PKCE with S256");
    discovered.set(key, { at: Date.now(), meta: m });
    return m;
  } catch (e) {
    if (hit) return hit.meta;
    throw e instanceof OidcError ? e : new OidcError(`could not reach the identity provider: ${(e as Error).message}`);
  }
}

function jwks(uri: string) {
  let set = jwksSets.get(uri);
  if (!set) {
    // jose caches the key set and refetches (at most every 30s) when a token names an unknown kid.
    set = createRemoteJWKSet(new URL(uri), { cacheMaxAge: 10 * 60_000, cooldownDuration: 30_000, timeoutDuration: 8000 });
    jwksSets.set(uri, set);
  }
  return set;
}

export function randomToken(bytes = 32): string {
  return base64url.encode(crypto.getRandomValues(new Uint8Array(bytes)));
}

export async function pkceChallenge(verifier: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier));
  return base64url.encode(new Uint8Array(digest));
}

export function authorizeUrl(
  meta: ProviderMetadata,
  cfg: OidcConfig,
  p: { redirectUri: string; state: string; nonce: string; challenge: string },
): string {
  const u = new URL(meta.authorization_endpoint);
  u.searchParams.set("response_type", "code");
  u.searchParams.set("client_id", cfg.clientId);
  u.searchParams.set("redirect_uri", p.redirectUri);
  u.searchParams.set("scope", cfg.scopes);
  u.searchParams.set("state", p.state);
  u.searchParams.set("nonce", p.nonce);
  u.searchParams.set("code_challenge", p.challenge);
  u.searchParams.set("code_challenge_method", "S256");
  return u.toString();
}

export interface TokenSet {
  id_token: string;
  access_token?: string;
  token_type?: string;
}

/** Trade the code for tokens, authenticating with client_secret_basic (or _post if that's all the IdP takes). */
export async function exchangeCode(
  meta: ProviderMetadata,
  cfg: OidcConfig,
  p: { code: string; verifier: string; redirectUri: string },
): Promise<TokenSet> {
  const body = new URLSearchParams({
    grant_type: "authorization_code",
    code: p.code,
    redirect_uri: p.redirectUri,
    code_verifier: p.verifier,
  });
  const headers: Record<string, string> = {
    "content-type": "application/x-www-form-urlencoded",
    accept: "application/json",
  };
  const methods = meta.token_endpoint_auth_methods_supported;
  if (methods && !methods.includes("client_secret_basic") && methods.includes("client_secret_post")) {
    body.set("client_id", cfg.clientId);
    body.set("client_secret", cfg.clientSecret);
  } else {
    // RFC 6749 §2.3.1: form-encode each part before base64.
    const enc = (s: string) => encodeURIComponent(s).replace(/%20/g, "+");
    headers.authorization = `Basic ${btoa(`${enc(cfg.clientId)}:${enc(cfg.clientSecret)}`)}`;
  }
  let res: Response;
  try {
    res = await fetch(meta.token_endpoint, {
      method: "POST",
      headers,
      body,
      signal: AbortSignal.timeout(10_000),
      cache: "no-store",
    });
  } catch (e) {
    throw new OidcError(`token endpoint unreachable: ${(e as Error).message}`);
  }
  const json = (await res.json().catch(() => ({}))) as Record<string, unknown>;
  if (!res.ok) {
    const reason = [json.error, json.error_description].filter(Boolean).join(": ");
    throw new OidcError(`token exchange failed (HTTP ${res.status}${reason ? `, ${reason}` : ""})`);
  }
  if (typeof json.id_token !== "string") throw new OidcError("the provider returned no ID token (is the openid scope allowed?)");
  return json as unknown as TokenSet;
}

const ASYMMETRIC = ["RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512", "EdDSA"];

export async function verifyIdToken(
  meta: ProviderMetadata,
  cfg: OidcConfig,
  idToken: string,
  nonce: string,
): Promise<JWTPayload> {
  const advertised = meta.id_token_signing_alg_values_supported?.filter((a) => ASYMMETRIC.includes(a));
  let payload: JWTPayload;
  try {
    ({ payload } = await jwtVerify(idToken, jwks(meta.jwks_uri), {
      issuer: meta.issuer,
      audience: cfg.clientId,
      algorithms: advertised?.length ? advertised : ["RS256"],
      clockTolerance: 60,
      requiredClaims: ["sub", "iat", "exp"],
    }));
  } catch (e) {
    throw new OidcError(`ID token rejected: ${(e as Error).message}`);
  }
  if (payload.nonce !== nonce) throw new OidcError("ID token nonce does not match this sign-in");
  const aud = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
  if (payload.azp !== undefined && payload.azp !== cfg.clientId) throw new OidcError("ID token azp is not this client");
  if (aud.length > 1 && payload.azp === undefined) throw new OidcError("ID token has several audiences but no azp");
  return payload;
}

/** Claims from the UserInfo endpoint, for providers that leave groups out of the ID token (Okta's default). */
export async function userInfo(meta: ProviderMetadata, accessToken: string, sub: string): Promise<Record<string, unknown>> {
  if (!meta.userinfo_endpoint) return {};
  try {
    const res = await fetch(meta.userinfo_endpoint, {
      headers: { authorization: `Bearer ${accessToken}`, accept: "application/json" },
      signal: AbortSignal.timeout(8000),
      cache: "no-store",
    });
    if (!res.ok || !(res.headers.get("content-type") ?? "").includes("json")) return {};
    const info = (await res.json()) as Record<string, unknown>;
    return info.sub === sub ? info : {}; // OIDC Core §5.3.2: must be the same user
  } catch {
    return {};
  }
}

/** RP-Initiated Logout 1.0 URL, or null when the provider doesn't offer one. */
export function endSessionUrl(
  meta: ProviderMetadata,
  cfg: OidcConfig,
  p: { idToken?: string; postLogoutRedirectUri: string },
): string | null {
  if (!meta.end_session_endpoint) return null;
  const u = new URL(meta.end_session_endpoint);
  if (p.idToken) u.searchParams.set("id_token_hint", p.idToken);
  u.searchParams.set("client_id", cfg.clientId);
  u.searchParams.set("post_logout_redirect_uri", p.postLogoutRedirectUri);
  return u.toString();
}
