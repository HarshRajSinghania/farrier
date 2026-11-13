/**
 * Server-side bridge between the dashboard and the Farrier API.
 *
 *   browser ──▶ /api/farrier/<path> ──▶ $FARRIER_API_URL/api/<path>  (Bearer $FARRIER_API_TOKEN)
 *
 * The API token never reaches the browser. With no FARRIER_API_URL configured the
 * route answers from an in-memory demo estate instead (see lib/demo.ts).
 *
 * Every call is checked here, whatever proxy.ts did: the caller's identity and role
 * (lib/auth/identity.ts), a same-origin check on changes (CSRF), and the role's
 * permission for the path (lib/auth/roles.ts). Viewers reach the engine with
 * FARRIER_API_READ_TOKEN when it is set, so the engine enforces read-only as well.
 *
 * Teams and projects (lib/auth/scope.ts): every call to the engine carries a signed X-Farrier-Scope
 * header naming the projects the user may make *this* call in (their role there meets the call's
 * required role), narrowed to the project picked in the dashboard (?project=, which is not forwarded).
 * The engine filters and refuses by it, so the scope holds even if this file had a bug elsewhere.
 */
import { NextResponse, type NextRequest } from "next/server";
import { isSafeMethod, isSameOrigin } from "@/lib/auth/csrf";
import { getIdentity, type Identity } from "@/lib/auth/identity";
import { actorName, atLeast, denyMessage, requiredRole, type Role } from "@/lib/auth/roles";
import { projectRoles, scopeIds, signScope, topRole, type ProjectInfo } from "@/lib/auth/scope";
import { allowedOrigins } from "@/lib/auth/session";
import * as demo from "@/lib/demo";

const UPSTREAM = process.env.FARRIER_API_URL?.replace(/\/+$/, "") || null;
const TOKEN = process.env.FARRIER_API_TOKEN;
const READ_TOKEN = process.env.FARRIER_API_READ_TOKEN;
const SEGMENT = /^[A-Za-z0-9_-]+$/;
const LONG = /^(discover|ssh\/(scan|collect)|crypto\/scan)$/;

type Ctx = { params: Promise<{ path: string[] }> };

const json = (body: unknown, init?: ResponseInit) => NextResponse.json(body, init);
const err = (status: number, detail: string) =>
  json({ detail }, { status, headers: { "cache-control": "no-store" } });

/** Refuse to front a real Farrier from a public deployment that has no login. */
function guard(identity: Identity): NextResponse | null {
  if (UPSTREAM && process.env.NODE_ENV === "production" && identity.auth === "none") {
    return err(
      503,
      "No sign-in is configured. Set FARRIER_OIDC_ISSUER or FARRIER_SAML_IDP_METADATA_URL (single sign-on) or FARRIER_DASHBOARD_PASSWORD before pointing a production dashboard at a live Farrier API.",
    );
  }
  return null;
}

/** The engine token for this caller: the read-only one for viewers when it exists. */
function tokenFor(role: Role) {
  return role === "viewer" && READ_TOKEN ? READ_TOKEN : TOKEN;
}

/* ------------------------------------------------------------------ projects */

const PROJECTS_TTL = 10_000;
let projectCache: { at: number; list: ProjectInfo[] } | null = null;

/** Every project with its member groups, from the engine (admin token, no scope), cached briefly. */
async function loadProjects(): Promise<ProjectInfo[]> {
  if (!UPSTREAM) return demo.listProjects();
  if (projectCache && Date.now() - projectCache.at < PROJECTS_TTL) return projectCache.list;
  const res = await fetch(`${UPSTREAM}/api/projects`, {
    headers: TOKEN ? { authorization: `Bearer ${TOKEN}` } : {},
    signal: AbortSignal.timeout(5000),
    cache: "no-store",
  });
  if (!res.ok) throw new Error(`the project list answered HTTP ${res.status}`);
  const list = (await res.json()) as ProjectInfo[];
  projectCache = { at: Date.now(), list };
  return list;
}

/** What this user may do where: "all" for global admins (and Basic / no sign-in), else a role per project id. */
interface Access {
  roles: Map<number, Role> | "all";
  /** the role the dashboard shows and the bridge checks: global, or the best project role */
  role: Role;
}

async function accessFor(identity: Identity): Promise<Access> {
  if (identity.groups === null) return { roles: "all", role: identity.role };
  const roles = projectRoles(identity.groups, await loadProjects(), identity.role);
  return { roles, role: topRole(roles.values()) };
}

async function handle(req: NextRequest, ctx: Ctx) {
  const { path } = await ctx.params;
  if (!path.every((s) => SEGMENT.test(s))) return err(400, "bad path");

  const who = await getIdentity(req, Boolean(UPSTREAM));
  if (!who.ok) return err(who.status, who.detail);
  const identity = who.identity;

  if (!isSafeMethod(req.method) && !isSameOrigin(req.headers, allowedOrigins(req))) {
    return err(403, "Cross-site request refused. Changes can only be made from the Farrier dashboard itself.");
  }

  let access: Access;
  try {
    access = await accessFor(identity);
  } catch (e) {
    return err(502, `Could not load projects from the Farrier API: ${(e as Error).message}`);
  }

  if (path[0] === "_status") return status(identity, access);

  const blocked = guard(identity);
  if (blocked) return blocked;

  const required = requiredRole(req.method, path);
  if (!atLeast(access.role, required)) return err(403, denyMessage(access.role, required));

  // the project picked in the dashboard narrows the call; it must be one of the user's
  const picked = req.nextUrl.searchParams.get("project");
  let selected: number | null = null;
  if (picked) {
    let found: ProjectInfo | undefined;
    try {
      found = (await loadProjects()).find((p) => p.name === picked);
    } catch (e) {
      return err(502, `Could not load projects from the Farrier API: ${(e as Error).message}`);
    }
    if (!found || (access.roles !== "all" && !access.roles.has(found.id))) return err(404, `No project named ${picked} that you can open.`);
    selected = found.id;
  }

  if (!UPSTREAM) return serveDemo(req, path, picked);
  if (access.roles !== "all" && !TOKEN)
    return err(503, "Project access needs FARRIER_API_TOKEN: the dashboard signs each user's project scope with it.");
  return forward(req, path, identity, access, scopeIds(access.roles, required, selected));
}

async function status(identity: Identity, access: Access) {
  const { user, auth } = identity;
  const role = access.role;
  let projects: { name: string; title: string; role: Role }[] = [];
  try {
    const all = await loadProjects();
    projects =
      access.roles === "all"
        ? all.map((p) => ({ name: p.name, title: p.title, role }))
        : all.flatMap((p) => {
            const r = (access.roles as Map<number, Role>).get(p.id);
            return r ? [{ name: p.name, title: p.title, role: r }] : [];
          });
  } catch {
    /* an unreachable engine is reported below; the switcher just stays hidden */
  }
  const base = { user, role, auth, projects, allProjects: access.roles === "all" };
  if (!UPSTREAM) return json({ mode: "demo", upstream: null, reachable: true, ...base });
  const token = tokenFor(role);
  const host = new URL(UPSTREAM).host;
  try {
    const res = await fetch(`${UPSTREAM}/api/connectors`, {
      headers: token ? { authorization: `Bearer ${token}` } : {},
      signal: AbortSignal.timeout(4000),
      cache: "no-store",
    });
    return json({
      mode: "live",
      upstream: host,
      ...base,
      reachable: res.ok,
      error: res.ok ? undefined : res.status === 401 ? "Token rejected (check FARRIER_API_TOKEN)" : `HTTP ${res.status}`,
    });
  } catch (e) {
    return json({ mode: "live", upstream: host, reachable: false, error: (e as Error).message, ...base });
  }
}

async function forward(req: NextRequest, path: string[], identity: Identity, access: Access, ids: string) {
  const enginePath = `/api/${path.join("/")}`;
  const query = new URLSearchParams(req.nextUrl.searchParams);
  query.delete("project"); // the dashboard's pick: already in the signed scope
  const qs = query.toString();
  const url = `${UPSTREAM}${enginePath}${qs ? `?${qs}` : ""}`;
  const headers = new Headers({ accept: req.headers.get("accept") ?? "application/json" });
  const token = tokenFor(access.role);
  if (token) headers.set("authorization", `Bearer ${token}`);
  if (TOKEN) headers.set("x-farrier-scope", await signScope(TOKEN, req.method, enginePath, ids));
  headers.set("x-farrier-actor", actorName(identity.email ?? identity.user));
  const hasBody = req.method !== "GET" && req.method !== "HEAD";
  if (hasBody) headers.set("content-type", req.headers.get("content-type") ?? "application/json");

  let res: Response;
  try {
    res = await fetch(url, {
      method: req.method,
      headers,
      body: hasBody ? await req.text() : undefined,
      cache: "no-store",
      // Discovery and the SSH/crypto scans probe a whole range synchronously; give them room.
      signal: AbortSignal.timeout(LONG.test(path.join("/")) ? 300_000 : 30_000),
    });
  } catch (e) {
    return err(502, `Farrier API unreachable: ${(e as Error).message}`);
  }

  const out = new Headers();
  for (const h of ["content-type", "content-disposition"]) {
    const v = res.headers.get(h);
    if (v) out.set(h, v);
  }
  out.set("cache-control", "no-store");
  return new NextResponse(res.body, { status: res.status, headers: out });
}

async function serveDemo(req: NextRequest, path: string[], project: string | null) {
  const [resource, rawId, action] = path;
  const id = rawId ? Number(rawId) : NaN;
  const q = req.nextUrl.searchParams;
  const body = async () => (await req.json().catch(() => ({}))) as Record<string, unknown>;

  try {
    const res = await (async () => {
      // SSH and crypto routes nest one level deeper (ssh/keys/{id}/remove), so match the whole path
      if (resource === "ssh" || resource === "crypto") {
        const [, sub, item, verb] = path;
        switch (`${req.method} ${resource}/${sub ?? ""}${item ? "/:id" : ""}${verb ? `/${verb}` : ""}`) {
          case "GET ssh/summary":
            return demo.sshSummary(project);
          case "GET ssh/keys":
            return demo.sshKeys(project);
          case "POST ssh/keys/:id/remove":
            return demo.sshRemoveKey(item, await body());
          case "GET ssh/hosts":
            return demo.sshHosts(project);
          case "POST ssh/scan":
            return demo.sshScan(await body());
          case "POST ssh/collect":
            return demo.sshCollect(await body());
          case "GET ssh/access":
            return demo.listSshAccess();
          case "PUT ssh/access/:id":
            return demo.putSshAccess(item, await body());
          case "DELETE ssh/access/:id":
            return demo.deleteSshAccess(item);
          case "POST ssh/access/:id/test":
            return demo.testSshAccess(item);
          case "GET crypto/summary":
            return demo.cryptoSummary(project);
          case "GET crypto/assets":
            return demo.cryptoAssets(project);
          case "POST crypto/scan":
            return demo.cryptoScan(await body());
          case "GET crypto/cbom":
            return new NextResponse(JSON.stringify(demo.cbom(project), null, 2), {
              headers: { "content-type": "application/vnd.cyclonedx+json", "content-disposition": 'attachment; filename="farrier-cbom.json"' },
            });
          default:
            throw new demo.DemoError(404, "Not found");
        }
      }
      switch (`${req.method} ${resource}${rawId ? "/:id" : ""}${action ? `/${action}` : ""}`) {
        case "GET summary":
          return demo.summary(project);
        case "GET endpoints":
          return demo.endpoints(project);
        case "POST endpoints/:id/move":
          return demo.moveEndpoint(id, await body());
        case "GET projects":
          return demo.listProjects();
        case "GET projects/:id": {
          const p = demo.listProjects().find((x) => x.name === rawId);
          if (!p) throw new demo.DemoError(404, `no project named ${rawId}`);
          return p;
        }
        case "PUT projects/:id":
          return demo.putProject(rawId, await body());
        case "DELETE projects/:id":
          return demo.deleteProject(rawId);
        case "POST endpoints":
          return demo.addEndpoint((await body()) as never);
        case "DELETE endpoints/:id":
          return demo.deleteEndpoint(id);
        case "POST endpoints/:id/renew":
          return demo.forceRenewal(id);
        case "GET renewals":
          return demo.renewals(q.get("state")?.split(","), project);
        case "POST renewals/:id/advance":
          return { state: demo.advance(id) };
        case "POST renewals/:id/cancel":
          return demo.cancel(id);
        case "GET renewals/:id/runbook":
          return demo.runbook(id);
        case "GET renewals/:id/pack":
          throw new demo.DemoError(404, "Change packs contain real keys and aren't generated in demo mode.");
        case "GET events":
          return demo.events(Number(q.get("limit") ?? 100), Number(q.get("endpoint_id")) || undefined, project);
        case "POST tick":
          return demo.tick();
        case "POST discover":
          return demo.discover(String((await body()).targets ?? ""));
        case "GET cloud/:id":
          if (rawId !== "certificates") throw new demo.DemoError(404, "Not found");
          return { configured: false, certificates: [], errors: [], listed_at: null };
        case "GET audit/:id":
          if (rawId !== "verify") throw new demo.DemoError(404, "The audit export isn't generated in demo mode.");
          return { ok: true, sealed: 0, unsealed: 0, head: null, first_bad_id: null };
        case "GET reports/:id":
          throw new demo.DemoError(404, "Reports aren't generated in demo mode.");
        case "POST replace":
          throw new demo.DemoError(400, "Replacing certificates isn't available in demo mode.");
        case "GET runners":
          return []; // demo: no remote networks
        case "GET discover/:id":
          if (rawId !== "ct") throw new demo.DemoError(404, "Not found");
          return demo.ctNames(q.get("domain") ?? "");
        case "POST notifiers/:id":
          if (rawId !== "test") throw new demo.DemoError(404, "Not found");
          return { sent: demo.listNotifiers().length }; // demo: pretend every channel's test went out
        // integrations: rawId is the entry's name
        case "GET integrations/:id":
          if (rawId !== "catalog") throw new demo.DemoError(404, "Not found");
          return demo.CATALOG;
        case "GET secrets":
          return demo.listSecrets();
        case "PUT secrets/:id":
          return demo.putSecret(rawId, await body());
        case "DELETE secrets/:id":
          return demo.deleteSecret(rawId);
        case "GET issuers":
          return demo.listIssuers();
        case "PUT issuers/:id":
          return demo.putIssuer(rawId, await body());
        case "DELETE issuers/:id":
          return demo.deleteIssuer(rawId);
        case "POST issuers/:id/test":
          return demo.testIssuer(rawId);
        case "GET dns-accounts":
          return demo.listDns();
        case "PUT dns-accounts/:id":
          return demo.putDns(rawId, await body());
        case "DELETE dns-accounts/:id":
          return demo.deleteDns(rawId);
        case "POST dns-accounts/:id/test":
          return demo.testDns(rawId);
        case "GET notifiers":
          return demo.listNotifiers();
        case "PUT notifiers/:id":
          return demo.putNotifier(rawId, await body());
        case "DELETE notifiers/:id":
          return demo.deleteNotifier(rawId);
        case "POST notifiers/:id/test":
          return demo.testNotifier(rawId);
        case "GET alert-rules":
          return demo.listRules();
        case "PUT alert-rules/:id":
          return demo.putRule(rawId, await body());
        case "DELETE alert-rules/:id":
          return demo.deleteRule(rawId);
        case "POST alert-rules/:id/test":
          return demo.testRule(rawId);
        case "GET config":
          return demo.config();
        case "PUT config/:id":
          return demo.saveSettings(await body());
        case "GET zombies":
          return demo.zombies(project);
        case "GET endpoints/:id/certificate":
          return demo.certificate(id);
        case "GET endpoints/:id/health":
          return demo.health(id);
        case "GET connectors":
          return demo.CONNECTORS;
        case "GET inventory": {
          const rows = demo.endpoints(project).map((e) => ({
            name: e.name, host: e.host, port: e.port, project: e.project, connector: e.connector, owner: e.owner,
            subject_cn: e.subject_cn, cert_issuer: e.cert_issuer, not_before: e.not_before, not_after: e.not_after,
            days_left: e.days_left, fingerprint: e.fingerprint, observed_at: e.observed_at, scan_error: e.scan_error,
          }));
          if (q.get("format") !== "csv") return rows;
          const cols = Object.keys(rows[0] ?? {});
          const cell = (v: unknown) => {
            const t = v == null ? "" : String(v);
            const safe = /^[=+\-@]/.test(t) ? `'${t}` : t; // no spreadsheet formulas
            return /[",\n]/.test(safe) ? `"${safe.replace(/"/g, '""')}"` : safe;
          };
          const csv = [cols.join(","), ...rows.map((r) => cols.map((c) => cell(r[c as keyof typeof r])).join(","))].join("\n");
          return new NextResponse(csv, {
            headers: { "content-type": "text/csv", "content-disposition": 'attachment; filename="farrier-inventory.csv"' },
          });
        }
        default:
          throw new demo.DemoError(404, "Not found");
      }
    })();
    if (res instanceof NextResponse) return res;
    return json(res, { headers: { "x-farrier-mode": "demo", "cache-control": "no-store" } });
  } catch (e) {
    if (e instanceof demo.DemoError) return err(e.status, e.message);
    throw e;
  }
}

export const GET = handle;
export const POST = handle;
export const DELETE = handle;
export const PUT = handle;
