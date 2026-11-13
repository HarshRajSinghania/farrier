/**
 * SAML 2.0 service provider, SP-initiated: AuthnRequest over HTTP-Redirect, Response over HTTP-POST
 * to /auth/saml/acs. XML parsing and XML-DSig are @node-saml/node-saml's (xml-crypto underneath);
 * this file only configures it strictly and adds the checks it leaves to the caller.
 *
 * A response is accepted only when:
 *   - the Response or the Assertion carries a valid signature by a configured IdP certificate (KeyInfo
 *     in the message is ignored); exactly one assertion, and the one read is the one that was signed
 *     (the library's defence against signature wrapping)
 *   - InResponseTo names the request this browser started (its ID sits in a sealed cookie, so the
 *     check works across replicas) and IdP-initiated responses are refused
 *   - Issuer is the IdP's entity id (when known), Audience is ours, NotBefore/NotOnOrAfter hold
 *     with 60 seconds of clock skew
 *   - the Response's Destination, when present, is our ACS URL (it must be present on a signed Response)
 *     and a bearer SubjectConfirmation's Recipient is our ACS URL
 *   - the assertion ID was not accepted before while it is still valid (replay; per instance)
 *
 * Imports only the library, so it runs under `node --test` (auth.test.mjs builds an IdP there).
 */
import { generateServiceProviderMetadata, SAML, SamlStatusError, ValidateInResponseTo, type CacheProvider } from "@node-saml/node-saml";
// shortcut: the library's own (xmldom-based) parser, not part of its documented API; pin the version.
import { parseDomFromString, xpath } from "@node-saml/node-saml/lib/xml.js";
import type { SamlConfig } from "./config";

export { SamlStatusError };
export class SamlError extends Error {}

export interface Idp {
  ssoUrl: string;
  certs: string[];
  entityId: string | null;
}

export interface Sp {
  entityId: string;
  /** assertion consumer service: <public origin>/auth/saml/acs */
  acsUrl: string;
}

/** The request this browser started, from its sealed cookie. */
export interface PendingRequest {
  id: string;
  /** when it was sent, ms */
  at: number;
}

export const CLOCK_SKEW_MS = 60_000;
export const REQUEST_TTL_MS = 10 * 60_000;
const MAX_RESPONSE_CHARS = 512 * 1024;
const BEARER = "urn:oasis:names:tc:SAML:2.0:cm:bearer";
const REDIRECT_BINDING = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect";

export const newRequestId = () => `_${Buffer.from(crypto.getRandomValues(new Uint8Array(20))).toString("hex")}`;

// Assertion IDs seen, until they expire. shortcut: per process, so with several replicas an assertion
// could be replayed once per replica within its validity window; move to a shared store if that matters.
const seen = new Map<string, number>();
async function saveIfAbsentAsync(key: string, _value: string, expiresAtMs: number): Promise<boolean> {
  const t = Date.now();
  if (seen.size > 10_000) for (const [k, until] of seen) if (until <= t) seen.delete(k);
  if ((seen.get(key) ?? 0) > t) return false;
  seen.set(key, expiresAtMs);
  return true;
}

/** A cache that knows exactly one request ID, the one from this browser's cookie, and gives it up once. */
function requestCache(request: PendingRequest | null): CacheProvider {
  let pending = request;
  const take = async (key: string | null) => {
    if (!pending || key !== pending.id) return null;
    const at = new Date(pending.at).toISOString();
    pending = null;
    return at;
  };
  return {
    saveAsync: async (_key, value) => ({ value, createdAt: Date.now() }),
    getAsync: async (key) => (pending && key === pending.id ? new Date(pending.at).toISOString() : null),
    removeAsync: take,
    consumeAsync: take,
    saveIfAbsentAsync,
  };
}

function client(idp: Idp, sp: Sp, request: PendingRequest | null) {
  if (!idp.certs.length) throw new SamlError("no IdP signing certificate is configured");
  return new SAML({
    entryPoint: idp.ssoUrl,
    idpCert: idp.certs,
    idpIssuer: idp.entityId ?? undefined,
    issuer: sp.entityId,
    audience: sp.entityId,
    callbackUrl: sp.acsUrl,
    // a signature on the Response or on the Assertion; the library refuses a message with neither
    wantAuthnResponseSigned: false,
    wantAssertionsSigned: false,
    validateInResponseTo: ValidateInResponseTo.always,
    requestIdExpirationPeriodMs: REQUEST_TTL_MS,
    rejectReplayedAssertions: true,
    acceptedClockSkewMs: CLOCK_SKEW_MS,
    cacheProvider: requestCache(request),
    generateUniqueId: () => request?.id ?? newRequestId(),
    // let the IdP pick the NameID format and authentication method (MFA, Kerberos, ...)
    identifierFormat: null,
    disableRequestedAuthnContext: true,
  });
}

/** The IdP URL to send the browser to (HTTP-Redirect binding) for request `id`. */
export async function authnRequestUrl(idp: Idp, sp: Sp, id: string): Promise<string> {
  return client(idp, sp, { id, at: Date.now() }).getAuthorizeUrlAsync("", {});
}

export interface SamlUser {
  nameId: string;
  nameIdFormat: string | null;
  /** attribute name -> value(s), as the role and project mapping reads claims */
  attributes: Record<string, unknown>;
}

/** Validate the POSTed SAMLResponse against the pending request; throws on anything short of a clean sign-in. */
export async function validateResponse(idp: Idp, sp: Sp, request: PendingRequest, samlResponse: string): Promise<SamlUser> {
  if (!samlResponse || samlResponse.length > MAX_RESPONSE_CHARS) throw new SamlError("missing or oversized SAMLResponse");
  const { profile } = await client(idp, sp, request).validatePostResponseAsync({ SAMLResponse: samlResponse });
  if (!profile?.nameID) throw new SamlError("the response carries no signed assertion with a NameID");

  // Destination is optional (SAML core 3.2.2) but must be present on a signed Response (profiles 4.1.4.5).
  // Rejecting on an unsigned Destination is safe: it can only refuse, never admit.
  const response = await parseDomFromString(Buffer.from(samlResponse, "base64").toString("utf8"));
  const root = response.documentElement;
  if (root.hasAttribute("Destination")) {
    const destination = root.getAttribute("Destination");
    if (destination !== sp.acsUrl) throw new SamlError(`Response Destination "${destination}" is not ${sp.acsUrl}`);
  } else if (xpath.selectElements(root, "./*[local-name()='Signature']").length) {
    throw new SamlError("a signed Response must carry a Destination");
  }
  // (with no Response signature the library has verified the Assertion's, so absent is fine here)

  // Recipient comes from the verified assertion only.
  const signedXml = profile.getAssertionXml?.();
  if (!signedXml) throw new SamlError("the library returned no verified assertion");
  const assertion = await parseDomFromString(signedXml);
  const recipients = xpath
    .selectAttributes(
      assertion,
      `/*[local-name()='Assertion']/*[local-name()='Subject']/*[local-name()='SubjectConfirmation'][@Method='${BEARER}']/*[local-name()='SubjectConfirmationData']/@Recipient`,
    )
    .map((a) => a.value);
  if (!recipients.includes(sp.acsUrl)) throw new SamlError(`no bearer SubjectConfirmation has Recipient ${sp.acsUrl}`);

  const attributes = (profile.attributes ?? {}) as Record<string, unknown>;
  return { nameId: profile.nameID, nameIdFormat: profile.nameIDFormat ?? null, attributes };
}

/** This SP's metadata XML for the IdP admin to import. */
export function spMetadata(sp: Sp): string {
  return generateServiceProviderMetadata({
    issuer: sp.entityId,
    callbackUrl: sp.acsUrl,
    identifierFormat: null,
    wantAssertionsSigned: true,
  });
}

const secureUrl = (v: string) => {
  const u = new URL(v);
  return u.protocol === "https:" || (u.protocol === "http:" && ["localhost", "127.0.0.1", "[::1]"].includes(u.hostname));
};

/**
 * Why this SP cannot do SAML sign-in, or null. The request cookie must come back on the IdP's cross-site
 * POST, so it is SameSite=None, which browsers accept only with Secure: hence https, or http on localhost
 * (where Chrome and Firefox accept Secure cookies; Safari may not, so develop in those).
 */
export function spProblem(sp: Sp): string | null {
  return secureUrl(sp.acsUrl)
    ? null
    : `the ACS URL ${sp.acsUrl} is not https: set NEXT_PUBLIC_SITE_URL to the dashboard's https:// URL (plain http works only on localhost)`;
}

/** SSO URL (HTTP-Redirect), signing certificates and entity id from an IdP metadata document. */
export async function parseIdpMetadata(xml: string): Promise<Partial<Idp>> {
  const doc = await parseDomFromString(xml);
  const entity = xpath.selectElements(doc, "//*[local-name()='EntityDescriptor'][*[local-name()='IDPSSODescriptor']]")[0];
  if (!entity) throw new SamlError("the metadata has no IDPSSODescriptor");
  const idp = "./*[local-name()='IDPSSODescriptor']";
  const sso = xpath.selectAttributes(entity, `${idp}/*[local-name()='SingleSignOnService'][@Binding='${REDIRECT_BINDING}']/@Location`)[0];
  const certs = xpath
    .selectElements(entity, `${idp}/*[local-name()='KeyDescriptor'][not(@use) or @use='signing']//*[local-name()='X509Certificate']`)
    .map((n) => (n.textContent ?? "").replace(/\s+/g, ""))
    .filter(Boolean);
  return { ssoUrl: sso?.value, certs, entityId: entity.getAttribute("entityID") };
}

const METADATA_TTL = 60 * 60_000;
const metadataCache = new Map<string, { at: number; idp: Partial<Idp> }>();

/** Metadata over https, cached for an hour (a stale copy is kept if a refresh fails). */
async function fetchMetadata(url: string): Promise<Partial<Idp>> {
  const hit = metadataCache.get(url);
  if (hit && Date.now() - hit.at < METADATA_TTL) return hit.idp;
  try {
    const res = await fetch(url, { signal: AbortSignal.timeout(8000), cache: "no-store", redirect: "error" });
    if (!res.ok) throw new SamlError(`metadata returned HTTP ${res.status}`);
    const text = await res.text();
    if (text.length > 1_000_000) throw new SamlError("metadata is over 1 MB");
    const idp = await parseIdpMetadata(text);
    metadataCache.set(url, { at: Date.now(), idp });
    return idp;
  } catch (e) {
    if (hit) return hit.idp;
    throw e instanceof SamlError ? e : new SamlError(`could not load the IdP metadata: ${(e as Error).message}`);
  }
}

/** The IdP settings: explicit FARRIER_SAML_IDP_* values win over its metadata. */
export async function resolveIdp(cfg: SamlConfig): Promise<Idp> {
  const meta = cfg.idpMetadataUrl ? await fetchMetadata(cfg.idpMetadataUrl) : {};
  const ssoUrl = cfg.idpSsoUrl ?? meta.ssoUrl;
  if (!ssoUrl) throw new SamlError("the IdP has no HTTP-Redirect SingleSignOnService");
  if (!secureUrl(ssoUrl)) throw new SamlError("the IdP SSO URL must use https");
  const certs = cfg.idpCerts.length ? cfg.idpCerts : (meta.certs ?? []);
  return { ssoUrl, certs, entityId: cfg.idpEntityId ?? meta.entityId ?? null };
}
