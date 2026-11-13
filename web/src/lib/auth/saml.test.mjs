// SAML service provider tests: a throwaway IdP (RSA key + self-signed certificate built here) signs
// responses, and validateResponse must accept only the clean one. Run with `npm test`.
import assert from "node:assert/strict";
import { generateKeyPairSync, sign, X509Certificate } from "node:crypto";
import { test } from "node:test";
import { inflateRawSync } from "node:zlib";
import { signXml } from "@node-saml/node-saml/lib/xml.js";
import { claimValues, mapRole } from "./roles.ts";
import { authnRequestUrl, parseIdpMetadata, spMetadata, validateResponse } from "./saml.ts";

// ---- a minimal X.509 v3 certificate in DER (node:crypto reads certificates but cannot make them)
const len = (n) => {
  if (n < 128) return Buffer.from([n]);
  const b = [];
  for (; n; n >>= 8) b.unshift(n & 255);
  return Buffer.from([0x80 | b.length, ...b]);
};
const der = (tag, ...parts) => {
  const body = Buffer.concat(parts);
  return Buffer.concat([Buffer.from([tag]), len(body.length), body]);
};
const seq = (...p) => der(0x30, ...p);
const oid = (hex) => der(0x06, Buffer.from(hex, "hex"));

function makeIdp(cn) {
  const { privateKey, publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const alg = seq(oid("2a864886f70d01010b"), der(0x05)); // sha256WithRSAEncryption
  const name = seq(der(0x31, seq(oid("550403"), der(0x0c, Buffer.from(cn)))));
  const validity = seq(der(0x17, Buffer.from("250101000000Z")), der(0x17, Buffer.from("491231235959Z")));
  const tbs = seq(der(0xa0, der(0x02, Buffer.from([2]))), der(0x02, Buffer.from([1])), alg, name, validity, name,
    publicKey.export({ type: "spki", format: "der" }));
  const cert = seq(tbs, alg, der(0x03, Buffer.from([0]), sign("sha256", tbs, privateKey)));
  const pem = `-----BEGIN CERTIFICATE-----\n${cert.toString("base64").match(/.{1,64}/g).join("\n")}\n-----END CERTIFICATE-----\n`;
  new X509Certificate(pem); // throws if the encoding is wrong
  return { key: privateKey.export({ type: "pkcs8", format: "pem" }), cert: pem };
}

const IDP = makeIdp("test-idp");
const ATTACKER = makeIdp("attacker");
const IDP_ENTITY = "https://idp.example.com/saml";
const SP = { entityId: "https://farrier.example.com/auth/saml/metadata", acsUrl: "https://farrier.example.com/auth/saml/acs" };
const idp = { ssoUrl: "https://idp.example.com/sso", certs: [IDP.cert], entityId: IDP_ENTITY };

let seq_ = 0;
const uid = (p) => `_${p}${Date.now().toString(16)}${++seq_}`;
const iso = (offsetSeconds) => new Date(Date.now() + offsetSeconds * 1000).toISOString();
const pending = (id) => ({ id, at: Date.now() });

function assertionXml(o) {
  const groups = o.groups.map((g) => `<saml:AttributeValue>${g}</saml:AttributeValue>`).join("");
  return `<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="${o.id}" Version="2.0" IssueInstant="${iso(0)}">` +
    `<saml:Issuer>${o.issuer}</saml:Issuer>` +
    `<saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">${o.nameId}</saml:NameID>` +
    `<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData` +
    `${o.inResponseTo ? ` InResponseTo="${o.inResponseTo}"` : ""} NotOnOrAfter="${o.notOnOrAfter}" Recipient="${o.recipient}"/>` +
    `</saml:SubjectConfirmation></saml:Subject>` +
    `<saml:Conditions NotBefore="${o.notBefore}" NotOnOrAfter="${o.notOnOrAfter}"><saml:AudienceRestriction>` +
    `<saml:Audience>${o.audience}</saml:Audience></saml:AudienceRestriction></saml:Conditions>` +
    `<saml:AuthnStatement AuthnInstant="${iso(0)}" SessionIndex="_s1"><saml:AuthnContext><saml:AuthnContextClassRef>` +
    `urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement>` +
    `<saml:AttributeStatement><saml:Attribute Name="groups">${groups}</saml:Attribute>` +
    `<saml:Attribute Name="email"><saml:AttributeValue>${o.nameId}</saml:AttributeValue></saml:Attribute>` +
    `<saml:Attribute Name="displayName"><saml:AttributeValue>Jane Doe</saml:AttributeValue></saml:Attribute></saml:AttributeStatement>` +
    `</saml:Assertion>`;
}

const ASSERTION = "//*[local-name(.)='Assertion']";
const signing = (key) => ({ privateKey: key, signatureAlgorithm: "sha256", digestAlgorithm: "sha256" });
const signAssertion = (xml, key = IDP.key) =>
  signXml(xml, ASSERTION, { reference: `${ASSERTION}/*[local-name(.)='Issuer']`, action: "after" }, signing(key));
const signResponse = (xml, key = IDP.key) =>
  signXml(xml, "/*[local-name(.)='Response']", { reference: "/*[local-name(.)='Response']/*[local-name(.)='Issuer']", action: "after" }, signing(key));

/** A Response for request `requestId`; `opts` override any field, `sign` picks what gets signed. */
function response(requestId, opts = {}) {
  const o = {
    id: uid("a"), issuer: IDP_ENTITY, nameId: "jane@example.com", inResponseTo: requestId, recipient: SP.acsUrl,
    destination: SP.acsUrl, audience: SP.entityId, notBefore: iso(-30), notOnOrAfter: iso(300), groups: ["farrier-ops", "team-pay"],
    sign: "assertion", key: IDP.key, ...opts,
  };
  let assertion = assertionXml(o);
  if (o.sign === "assertion") assertion = signAssertion(assertion, o.key);
  let xml = `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"` +
    ` ID="${uid("r")}" Version="2.0" IssueInstant="${iso(0)}" Destination="${o.destination}"` +
    `${o.inResponseTo ? ` InResponseTo="${o.inResponseTo}"` : ""}><saml:Issuer>${o.issuer}</saml:Issuer>` +
    `<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>${assertion}</samlp:Response>`;
  if (o.sign === "response") xml = signResponse(xml, o.key);
  return o.raw ? xml : b64(xml);
}
const b64 = (xml) => Buffer.from(xml).toString("base64");

const mapping = { claim: "groups", admin: ["farrier-admins"], operator: ["farrier-ops"], allowed: [] };

test("SAML: a signed assertion for this request signs in, with groups mapped to a role", async () => {
  const id = uid("q");
  const user = await validateResponse(idp, SP, pending(id), response(id));
  assert.equal(user.nameId, "jane@example.com");
  assert.equal(user.attributes.email, "jane@example.com");
  assert.equal(user.attributes.displayName, "Jane Doe");
  assert.equal(mapRole(user.attributes, mapping), "operator");
  assert.deepEqual(claimValues(user.attributes, "groups"), ["farrier-ops", "team-pay"]); // project membership
});

test("SAML: a signed Response (assertion unsigned inside it) is accepted too", async () => {
  const id = uid("q");
  const user = await validateResponse(idp, SP, pending(id), response(id, { sign: "response", groups: ["farrier-admins"] }));
  assert.equal(mapRole(user.attributes, mapping), "admin");
});

test("SAML: group mapping matches OIDC (single value, allowed groups, case and Keycloak paths)", async () => {
  const id = uid("q");
  const user = await validateResponse(idp, SP, pending(id), response(id, { groups: ["/Farrier-Admins"] }));
  assert.equal(mapRole(user.attributes, mapping), "admin");
  const id2 = uid("q");
  const other = await validateResponse(idp, SP, pending(id2), response(id2, { groups: ["sales"] }));
  assert.equal(mapRole(other.attributes, mapping), "viewer");
  assert.equal(mapRole(other.attributes, { ...mapping, allowed: ["engineering"] }), null);
});

const rejects = (promise, pattern) => assert.rejects(promise, pattern);

test("SAML: no signature at all is refused", async () => {
  const id = uid("q");
  await rejects(validateResponse(idp, SP, pending(id), response(id, { sign: "none" })), /signature/i);
});

test("SAML: a signature by another key, or a change after signing, is refused", async () => {
  const id = uid("q");
  await rejects(validateResponse(idp, SP, pending(id), response(id, { key: ATTACKER.key })), /signature/i);
  const id2 = uid("q");
  const tampered = response(id2, { raw: true }).replace(">team-pay<", ">farrier-admins<");
  await rejects(validateResponse(idp, SP, pending(id2), b64(tampered)), /signature/i);
});

test("SAML: wrong audience, issuer, recipient or destination is refused", async () => {
  for (const [opts, pattern] of [
    [{ audience: "https://other-sp.example.com" }, /audience/i],
    [{ issuer: "https://evil.example.com" }, /issuer/i],
    [{ recipient: "https://evil.example.com/acs" }, /Recipient/],
    [{ destination: "https://evil.example.com/acs" }, /Destination/],
  ]) {
    const id = uid("q");
    await rejects(validateResponse(idp, SP, pending(id), response(id, opts)), pattern, JSON.stringify(opts));
  }
});

test("SAML: expired or not-yet-valid assertions are refused (60 s skew)", async () => {
  const id = uid("q");
  await rejects(validateResponse(idp, SP, pending(id), response(id, { notBefore: iso(-600), notOnOrAfter: iso(-90) })), /expired|subject confirmation/i);
  const id2 = uid("q");
  await rejects(validateResponse(idp, SP, pending(id2), response(id2, { notBefore: iso(120) })), /not yet valid/i);
  const id3 = uid("q"); // just inside the skew still works
  await validateResponse(idp, SP, pending(id3), response(id3, { notBefore: iso(30) }));
});

test("SAML: InResponseTo must name this browser's request; IdP-initiated responses are refused", async () => {
  const id = uid("q");
  await rejects(validateResponse(idp, SP, pending(uid("other")), response(id)), /InResponseTo/);
  const id2 = uid("q");
  await rejects(validateResponse(idp, SP, pending(id2), response(id2, { inResponseTo: null })), /InResponseTo/);
});

test("SAML: the same assertion is accepted once", async () => {
  const id = uid("q");
  const signed = response(id);
  await validateResponse(idp, SP, pending(id), signed);
  // even with the request cookie captured too
  await rejects(validateResponse(idp, SP, pending(id), signed), /replay|already|presented/i);
});

test("SAML: signature wrapping is refused", async () => {
  // a genuine signed assertion for a viewer...
  const id = uid("q");
  const genuine = signAssertion(assertionXml({
    id: uid("a"), issuer: IDP_ENTITY, nameId: "eve@example.com", inResponseTo: id, recipient: SP.acsUrl, audience: SP.entityId,
    notBefore: iso(-30), notOnOrAfter: iso(300), groups: ["staff"],
  }));
  const evil = (attrs = "") => assertionXml({
    id: uid("evil"), issuer: IDP_ENTITY, nameId: "admin@example.com", inResponseTo: id, recipient: SP.acsUrl, audience: SP.entityId,
    notBefore: iso(-30), notOnOrAfter: iso(300), groups: ["farrier-admins"],
  }).replace("<saml:Assertion ", `<saml:Assertion ${attrs}`);
  const wrap = (body) => b64(`<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"` +
    ` ID="${uid("r")}" Version="2.0" IssueInstant="${iso(0)}" Destination="${SP.acsUrl}" InResponseTo="${id}"><saml:Issuer>${IDP_ENTITY}</saml:Issuer>` +
    `<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>${body}</samlp:Response>`);

  // 1. the signed assertion hidden in Extensions, a forged one where the SP reads
  await rejects(validateResponse(idp, SP, pending(id), wrap(`<samlp:Extensions>${genuine}</samlp:Extensions>${evil()}`)), /signature/i);
  // 2. the forged assertion carrying the genuine one (and its signature) inside it
  await rejects(validateResponse(idp, SP, pending(id), wrap(evil().replace("</saml:Assertion>", `${genuine}</saml:Assertion>`))), /signature/i);
  // 3. both assertions side by side
  await rejects(validateResponse(idp, SP, pending(id), wrap(genuine + evil())), /multiple assertions|signature/i);
  // 4. the genuine signature moved onto the forged assertion, which takes the signed ID
  const genuineId = genuine.match(/ID="([^"]+)"/)[1];
  const sig = genuine.match(/<Signature[\s\S]*<\/Signature>/)[0];
  const forged = evil().replace(/ID="[^"]+"/, `ID="${genuineId}"`).replace(`${IDP_ENTITY}</saml:Issuer>`, `${IDP_ENTITY}</saml:Issuer>${sig}`);
  await rejects(validateResponse(idp, SP, pending(id), wrap(forged)), /signature/i);
});

test("SAML: AuthnRequest goes over HTTP-Redirect with our ID, entity id and ACS URL", async () => {
  const url = new URL(await authnRequestUrl(idp, SP, "_req123"));
  assert.equal(url.origin + url.pathname, idp.ssoUrl);
  const xml = inflateRawSync(Buffer.from(url.searchParams.get("SAMLRequest"), "base64")).toString();
  assert.match(xml, /ID="_req123"/);
  assert.ok(xml.includes(`AssertionConsumerServiceURL="${SP.acsUrl}"`));
  assert.ok(xml.includes(`>${SP.entityId}</saml:Issuer>`));
  assert.ok(!xml.includes("RequestedAuthnContext"));
});

test("SAML: SP metadata and IdP metadata", async () => {
  const md = spMetadata(SP);
  assert.ok(md.includes(`entityID="${SP.entityId}"`));
  assert.ok(md.includes(`Location="${SP.acsUrl}"`));
  assert.match(md, /HTTP-POST/);
  const body = IDP.cert.replace(/-----[A-Z ]+-----|\s/g, "");
  const parsed = await parseIdpMetadata(`<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="${IDP_ENTITY}">
    <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
      <md:KeyDescriptor use="encryption"><ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:X509Data><ds:X509Certificate>ENC</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>
      <md:KeyDescriptor use="signing"><ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:X509Data><ds:X509Certificate>${body}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>
      <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://idp.example.com/post"/>
      <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.com/sso"/>
    </md:IDPSSODescriptor></md:EntityDescriptor>`);
  assert.deepEqual(parsed, { ssoUrl: "https://idp.example.com/sso", certs: [body], entityId: IDP_ENTITY });
  // a bare base64 certificate (as metadata gives it) verifies like the PEM one
  const id = uid("q");
  await validateResponse({ ...idp, certs: parsed.certs }, SP, pending(id), response(id));
});
