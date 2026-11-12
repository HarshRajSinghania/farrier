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
 */
import { NextResponse, type NextRequest } from "next/server";
import { isSafeMethod, isSameOrigin } from "@/lib/auth/csrf";
import { getIdentity, type Identity } from "@/lib/auth/identity";
import { actorName, atLeast, denyMessage, requiredRole } from "@/lib/auth/roles";
import { allowedOrigins } from "@/lib/auth/session";
import * as demo from "@/lib/demo";

const UPSTREAM = process.env.FARRIER_API_URL?.replace(/\/+$/, "") || null;
const TOKEN = process.env.FARRIER_API_TOKEN;
const READ_TOKEN = process.env.FARRIER_API_READ_TOKEN;
const SEGMENT = /^[A-Za-z0-9_-]+$/;

type Ctx = { params: Promise<{ path: string[] }> };

const json = (body: unknown, init?: ResponseInit) => NextResponse.json(body, init);
const err = (status: number, detail: string) =>
  json({ detail }, { status, headers: { "cache-control": "no-store" } });

/** Refuse to front a real Farrier from a public deployment that has no login. */
function guard(identity: Identity): NextResponse | null {
  if (UPSTREAM && process.env.NODE_ENV === "production" && identity.auth === "none") {
    return err(
      503,
      "No sign-in is configured. Set FARRIER_OIDC_ISSUER (single sign-on) or FARRIER_DASHBOARD_PASSWORD before pointing a production dashboard at a live Farrier API.",
    );
  }
  return null;
}

/** The engine token for this caller: the read-only one for viewers when it exists. */
function tokenFor(identity: Identity) {
  return identity.role === "viewer" && READ_TOKEN ? READ_TOKEN : TOKEN;
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

  if (path[0] === "_status") return status(identity);

  const blocked = guard(identity);
  if (blocked) return blocked;

  const required = requiredRole(req.method, path);
  if (!atLeast(identity.role, required)) return err(403, denyMessage(identity.role, required));

  return UPSTREAM ? forward(req, path, identity) : serveDemo(req, path);
}

async function status(identity: Identity) {
  const { user, role, auth } = identity;
  const base = { user, role, auth };
  if (!UPSTREAM) return json({ mode: "demo", upstream: null, reachable: true, ...base });
  const token = tokenFor(identity);
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

async function forward(req: NextRequest, path: string[], identity: Identity) {
  const url = `${UPSTREAM}/api/${path.join("/")}${req.nextUrl.search}`;
  const headers = new Headers({ accept: req.headers.get("accept") ?? "application/json" });
  const token = tokenFor(identity);
  if (token) headers.set("authorization", `Bearer ${token}`);
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
      // Discovery scans a whole range synchronously; give it room.
      signal: AbortSignal.timeout(path[0] === "discover" ? 300_000 : 30_000),
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

async function serveDemo(req: NextRequest, path: string[]) {
  const [resource, rawId, action] = path;
  const id = rawId ? Number(rawId) : NaN;
  const q = req.nextUrl.searchParams;
  const body = async () => (await req.json().catch(() => ({}))) as Record<string, unknown>;

  try {
    const res = await (async () => {
      switch (`${req.method} ${resource}${rawId ? "/:id" : ""}${action ? `/${action}` : ""}`) {
        case "GET summary":
          return demo.summary();
        case "GET endpoints":
          return demo.endpoints();
        case "POST endpoints":
          return demo.addEndpoint((await body()) as never);
        case "DELETE endpoints/:id":
          return demo.deleteEndpoint(id);
        case "POST endpoints/:id/renew":
          return demo.forceRenewal(id);
        case "GET renewals":
          return demo.renewals(q.get("state")?.split(","));
        case "POST renewals/:id/advance":
          return { state: demo.advance(id) };
        case "POST renewals/:id/cancel":
          return demo.cancel(id);
        case "GET renewals/:id/runbook":
          return demo.runbook(id);
        case "GET renewals/:id/pack":
          throw new demo.DemoError(404, "Change packs contain real keys and aren't generated in demo mode.");
        case "GET events":
          return demo.events(Number(q.get("limit") ?? 100), Number(q.get("endpoint_id")) || undefined);
        case "POST tick":
          return demo.tick();
        case "POST discover":
          return demo.discover(String((await body()).targets ?? ""));
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
          return demo.zombies();
        case "GET endpoints/:id/health":
          return demo.health(id);
        case "GET connectors":
          return demo.CONNECTORS;
        case "GET inventory": {
          const rows = demo.endpoints().map((e) => ({
            name: e.name, host: e.host, port: e.port, connector: e.connector, owner: e.owner,
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
