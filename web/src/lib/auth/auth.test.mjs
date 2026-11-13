// Unit tests for the pure auth helpers. Run with `npm test` (Node 22.18+ strips the TypeScript types).
import assert from "node:assert/strict";
import { test } from "node:test";
import { isSameOrigin, safeReturnTo } from "./csrf.ts";
import { clientAddress, configuredOrigin, redirectUriProblem, requiredHeaderStatus } from "./request.ts";
import { actorName, claimValues, mapRole, parseList, permits, requiredRole } from "./roles.ts";
import { seal, secretProblem, unseal } from "./seal.ts";

const mapping = { claim: "groups", admin: ["farrier-admins"], operator: ["farrier-ops"], allowed: [] };
const headers = (h) => ({ get: (n) => h[n] ?? null });

test("parseList trims and drops blanks", () => {
  assert.deepEqual(parseList(" a, b ,,c "), ["a", "b", "c"]);
  assert.deepEqual(parseList(undefined), []);
});

test("mapRole: admin wins over operator, others are viewers", () => {
  assert.equal(mapRole({ groups: ["farrier-ops", "farrier-admins"] }, mapping), "admin");
  assert.equal(mapRole({ groups: ["farrier-ops"] }, mapping), "operator");
  assert.equal(mapRole({ groups: ["staff"] }, mapping), "viewer");
  assert.equal(mapRole({}, mapping), "viewer");
});

test("mapRole: case-insensitive, Keycloak paths, single strings", () => {
  assert.equal(mapRole({ groups: ["/Farrier-Admins"] }, mapping), "admin");
  assert.equal(mapRole({ groups: "farrier-ops" }, mapping), "operator");
});

test("mapRole: allowed groups deny everyone else", () => {
  const m = { ...mapping, allowed: ["engineering"] };
  assert.equal(mapRole({ groups: ["sales"] }, m), null);
  assert.equal(mapRole({ groups: ["engineering"] }, m), "viewer");
  assert.equal(mapRole({ groups: ["farrier-admins"] }, m), "admin"); // admin groups are implicitly allowed
});

test("claimValues: nested and URL-named claims", () => {
  assert.deepEqual(claimValues({ realm_access: { roles: ["x"] } }, "realm_access.roles"), ["x"]);
  assert.deepEqual(claimValues({ "https://farrier.dev/roles": ["y"] }, "https://farrier.dev/roles"), ["y"]);
  assert.deepEqual(claimValues({ groups: [1, "a", ""] }, "groups"), ["a"]);
});

test("requiredRole: reads, operator actions, admin-only changes", () => {
  assert.equal(requiredRole("GET", ["endpoints"]), "viewer");
  assert.equal(requiredRole("GET", ["renewals", "4", "pack"]), "operator");
  assert.equal(requiredRole("GET", ["renewals", "4", "runbook"]), "operator");
  for (const p of ["endpoints/3/renew", "renewals/4/advance", "renewals/4/cancel", "tick", "discover"])
    assert.equal(requiredRole("POST", p), "operator", p);
  assert.equal(requiredRole("POST", ["endpoints"]), "admin");
  assert.equal(requiredRole("DELETE", ["endpoints", "3"]), "admin");
  assert.equal(requiredRole("POST", ["notifiers", "test"]), "admin");
  assert.equal(requiredRole("PUT", ["anything"]), "admin");
  assert.equal(permits("viewer", "POST", "tick"), false);
  assert.equal(permits("operator", "POST", "tick"), true);
  assert.equal(permits("operator", "DELETE", "endpoints/1"), false);
});

test("actorName keeps the engine's audit format", () => {
  assert.equal(actorName("jane.doe+ops@example.com"), "jane.doe_ops@example.com");
  assert.equal(actorName(""), "dashboard");
  assert.equal(actorName("x".repeat(80)).length, 64);
});

test("isSameOrigin: Sec-Fetch-Site first, then Origin", () => {
  const ok = ["https://farrier.example.com"];
  assert.equal(isSameOrigin(headers({ "sec-fetch-site": "same-origin" }), ok), true);
  assert.equal(isSameOrigin(headers({ "sec-fetch-site": "cross-site", origin: ok[0] }), ok), false);
  assert.equal(isSameOrigin(headers({ "sec-fetch-site": "same-site" }), ok), false);
  assert.equal(isSameOrigin(headers({ origin: "https://farrier.example.com" }), ok), true);
  assert.equal(isSameOrigin(headers({ origin: "https://evil.example" }), ok), false);
  assert.equal(isSameOrigin(headers({ origin: "null" }), ok), false);
  assert.equal(isSameOrigin(headers({}), ok), false);
});

test("safeReturnTo refuses anything off the dashboard", () => {
  assert.equal(safeReturnTo("/dashboard/renewals?state=failed"), "/dashboard/renewals?state=failed");
  for (const bad of ["https://evil.example", "//evil.example", "/docs", "/dashboard\\@evil", null])
    assert.equal(safeReturnTo(bad), "/dashboard");
});

const SECRET = "0123456789abcdef0123456789abcdef-test";
const later = () => Math.floor(Date.now() / 1000) + 60;

test("seal/unseal round trip", async () => {
  // a probe long enough that random base64url never contains it by chance ("u1" did, ~6% of runs)
  const token = await seal({ sub: "plaintext-subject", role: "admin" }, SECRET, "p1", later());
  assert.ok(!token.includes("plaintext-subject") && !token.includes("cGxhaW50ZXh0"), "the payload is encrypted"); // raw or base64
  const out = await unseal(token, SECRET, "p1");
  assert.equal(out.sub, "plaintext-subject");
  assert.equal(out.role, "admin");
});

test("unseal rejects tampering, other keys, other purposes and expiry", async () => {
  const token = await seal({ sub: "u1" }, SECRET, "p1", later());
  const parts = token.split(".");
  parts[3] = (parts[3][0] === "A" ? "B" : "A") + parts[3].slice(1);
  assert.equal(await unseal(parts.join("."), SECRET, "p1"), null);
  assert.equal(await unseal(token, SECRET + "x", "p1"), null);
  assert.equal(await unseal(token, SECRET, "p2"), null);
  const old = await seal({ sub: "u1" }, SECRET, "p1", Math.floor(Date.now() / 1000) - 10);
  assert.equal(await unseal(old, SECRET, "p1"), null);
  assert.equal(await unseal("garbage", SECRET, "p1"), null);
});

test("secretProblem enforces 32 bytes", () => {
  assert.ok(secretProblem(undefined));
  assert.ok(secretProblem("short"));
  assert.equal(secretProblem(SECRET), null);
});

test("redirect URI: production needs a configured URL, never the request's host headers", () => {
  assert.match(redirectUriProblem({ NODE_ENV: "production" }), /FARRIER_OIDC_REDIRECT_URI/);
  assert.equal(redirectUriProblem({ NODE_ENV: "production", NEXT_PUBLIC_SITE_URL: "https://certs.example.com" }), null);
  assert.equal(redirectUriProblem({ NODE_ENV: "development" }), null); // dev keeps deriving it from the request
  assert.equal(configuredOrigin({ FARRIER_OIDC_REDIRECT_URI: "https://a.example/auth/callback", NEXT_PUBLIC_SITE_URL: "https://b.example" }), "https://a.example");
  assert.equal(configuredOrigin({ NEXT_PUBLIC_SITE_URL: "not a url" }), null);
});

test("clientAddress: FARRIER_TRUSTED_PROXY_HOPS picks the hop that many from the right", () => {
  const h = headers({ "x-forwarded-for": "6.6.6.6, 1.2.3.4, 10.0.0.2", "x-real-ip": "10.0.0.9" });
  assert.equal(clientAddress(h, {}), "10.0.0.2");
  assert.equal(clientAddress(h, { FARRIER_TRUSTED_PROXY_HOPS: "2" }), "1.2.3.4");
  assert.equal(clientAddress(h, { FARRIER_TRUSTED_PROXY_HOPS: "9" }), "6.6.6.6");
  assert.equal(clientAddress(h, { FARRIER_TRUSTED_PROXY_HOPS: "0" }), "10.0.0.9"); // XFF ignored
  assert.equal(clientAddress(headers({}), {}), "unknown");
});

test("requiredHeaderStatus: FARRIER_REQUIRE_HEADER gates every path but /api/health", () => {
  const env = { FARRIER_REQUIRE_HEADER: "X-Azure-FDID:0f6e-guid" };
  const ok = headers({ "X-Azure-FDID": "0f6e-guid" });
  assert.equal(requiredHeaderStatus(ok, "/", env), null);
  assert.equal(requiredHeaderStatus(headers({ "X-Azure-FDID": "other" }), "/docs", env), 403);
  assert.equal(requiredHeaderStatus(headers({}), "/dashboard", env), 403);
  assert.equal(requiredHeaderStatus(headers({}), "/api/health", env), null);
  assert.equal(requiredHeaderStatus(headers({}), "/", {}), null); // unset: no check
  assert.equal(requiredHeaderStatus(ok, "/", { FARRIER_REQUIRE_HEADER: "no-colon" }), 500);
});

// ---- teams and projects ----------------------------------------------------------------------------
import { projectRoles, scopeIds, signScope, topRole } from "./scope.ts";
import { switcherOptions, validPick, withProject } from "../projects.ts";

const none = { groups: [], admin: [], operator: [], viewer: [] };
const PROJECTS = [
  { id: 1, name: "default", title: "Default", members: none },
  { id: 2, name: "payments", title: "Payments", members: { ...none, groups: ["team-pay"], admin: ["pay-leads"] } },
  { id: 3, name: "retail", title: "Retail", members: { ...none, operator: ["/Retail-Oncall"] } },
];

test("projectRoles: project role groups win, members keep their global role, unconfigured default is open", () => {
  const r = projectRoles(["team-pay", "retail-oncall"], PROJECTS, "viewer");
  assert.deepEqual([...r], [[1, "viewer"], [2, "viewer"], [3, "operator"]]);
  assert.equal(projectRoles(["pay-leads"], PROJECTS, "viewer").get(2), "admin");
  assert.equal(projectRoles(["team-pay"], PROJECTS, "operator").get(2), "operator");
  assert.deepEqual([...projectRoles([], PROJECTS, "viewer")], [[1, "viewer"]]);
  // once default has groups, it is no longer open to everyone
  const closed = [{ ...PROJECTS[0], members: { ...none, groups: ["staff"] } }];
  assert.equal(projectRoles(["other"], closed, "operator").size, 0);
  assert.equal(topRole(projectRoles(["team-pay", "retail-oncall"], PROJECTS, "viewer").values()), "operator");
  assert.equal(topRole([]), "viewer");
});

test("scopeIds: only the projects where the role allows the call, narrowed to the pick", () => {
  const roles = projectRoles(["team-pay", "retail-oncall"], PROJECTS, "viewer");
  assert.equal(scopeIds(roles, "viewer"), "1,2,3");
  assert.equal(scopeIds(roles, requiredRole("POST", "endpoints/4/renew")), "3"); // operator only in retail
  assert.equal(scopeIds(roles, requiredRole("DELETE", "endpoints/4")), ""); // admin nowhere: nothing
  assert.equal(scopeIds(roles, "viewer", 2), "2");
  assert.equal(scopeIds(roles, "operator", 2), "");
  assert.equal(scopeIds("all", "admin"), "*");
  assert.equal(scopeIds("all", "viewer", 3), "3");
});

test("signScope matches the engine's test vector (tests/test_projects.py)", async () => {
  assert.equal(
    await signScope("tok", "GET", "/api/endpoints", "1,2", 1700000000),
    "v1;1,2;1700000000;1df0998b35e23e80b2a464350261f2f7ab5ce1f2ddfe9ddbe44774ae358520b2",
  );
  const other = await signScope("tok", "POST", "/api/endpoints", "1,2", 1700000000);
  assert.notEqual(other.split(";")[3], "1df0998b35e23e80b2a464350261f2f7ab5ce1f2ddfe9ddbe44774ae358520b2");
});

test("project switcher: hidden with one project, shown for several", () => {
  assert.equal(switcherOptions([{ name: "default", title: "Default" }], true), null);
  assert.equal(switcherOptions([{ name: "payments", title: "Payments" }], false), null);
  assert.equal(switcherOptions([], true), null);
  assert.equal(switcherOptions(undefined, undefined), null);
  assert.deepEqual(switcherOptions([{ name: "payments", title: "Payments" }], true)?.all, true);
  const two = [{ name: "default", title: "Default" }, { name: "payments", title: "Payments" }];
  assert.equal(switcherOptions(two, false)?.projects.length, 2);
  assert.equal(validPick("payments", two), "payments");
  assert.equal(validPick("retail", two), null);
  assert.equal(withProject("/events?limit=5", "payments"), "/events?limit=5&project=payments");
  assert.equal(withProject("/summary", null), "/summary");
});
