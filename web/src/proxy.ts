/**
 * Sign-in gate for the dashboard and its API bridge.
 *
 *   FARRIER_OIDC_ISSUER set         single sign-on: pages without a session go to /auth/signin,
 *                                   API calls get 401; each request slides the idle timeout.
 *   FARRIER_SAML_IDP_* set          the same, with a session from SAML 2.0 sign-in.
 *   FARRIER_DASHBOARD_PASSWORD set  HTTP Basic with a lockout on repeated failures (fallback).
 *   neither                         open (demo and local development; see the bridge's guard).
 *
 * This is the first lock. The bridge (app/api/farrier/[...path]/route.ts) checks the session
 * again and enforces roles and the same-origin rule on every call.
 *
 * FARRIER_REQUIRE_HEADER=Name:value runs before all of that on every path (sign-in, dashboard, assets,
 * sign-in, dashboard, API) except /api/health: a request without that exact header value gets 403.
 * FARRIER_TRUSTED_PROXY_HOPS (default 1) says how many proxies append X-Forwarded-For (see clientAddress).
 */
import { NextResponse, type NextRequest } from "next/server";
import { checkBasic } from "@/lib/auth/basic";
import { authMode, ssoConfig } from "@/lib/auth/config";
import { clientAddress, requiredHeaderStatus } from "@/lib/auth/request";
import { clearSession, hasSessionCookie, readSession, touchSession } from "@/lib/auth/session";

const MAX_FAILURES = 10;
const WINDOW_MS = 5 * 60_000;
// Per instance. Behind several replicas each keeps its own count, which still caps guessing.
const failures = new Map<string, { count: number; until: number }>();
// One budget across every address, so rotating addresses can't buy unlimited guesses.
const GLOBAL_MAX_FAILURES = 200;
let globalFailures = { count: 0, until: 0 };

const clientKey = (req: NextRequest) => clientAddress(req.headers, process.env);

const isApi = (req: NextRequest) => req.nextUrl.pathname.startsWith("/api/");

async function ssoGate(req: NextRequest) {
  const cfg = ssoConfig();
  if (!cfg.ok) {
    // fail closed: a half-configured SSO never falls back to an open dashboard
    const detail = `Single sign-on is misconfigured: ${cfg.error}`;
    return isApi(req) ? NextResponse.json({ detail }, { status: 500 }) : new NextResponse(detail, { status: 500 });
  }
  const session = await readSession(req, cfg.config);
  if (!session) {
    const hadCookie = hasSessionCookie(req);
    let res: NextResponse;
    if (isApi(req)) {
      res = NextResponse.json({ detail: "Sign in required" }, { status: 401, headers: { "cache-control": "no-store" } });
    } else {
      const to = new URL("/auth/signin", req.url);
      to.searchParams.set("returnTo", req.nextUrl.pathname + req.nextUrl.search);
      if (hadCookie) to.searchParams.set("error", "expired");
      res = NextResponse.redirect(to);
    }
    if (hadCookie) clearSession(res);
    return res;
  }
  const res = NextResponse.next();
  await touchSession(res, req, cfg.config, session);
  return res;
}

function basicGate(req: NextRequest) {
  const key = clientKey(req);
  const now = Date.now();
  const entry = failures.get(key);
  const globalLocked = globalFailures.until > now && globalFailures.count >= GLOBAL_MAX_FAILURES;
  if (globalLocked || (entry && entry.until > now && entry.count >= MAX_FAILURES)) {
    return new NextResponse("Too many failed sign-ins. Try again in a few minutes.", {
      status: 429,
      headers: { "Retry-After": String(Math.ceil(((globalLocked ? globalFailures.until : entry!.until) - now) / 1000)) },
    });
  }

  const header = req.headers.get("authorization");
  if (header?.startsWith("Basic ")) {
    if (checkBasic(header)) {
      failures.delete(key);
      return NextResponse.next();
    }
    const next = entry && entry.until > now ? entry.count + 1 : 1;
    failures.set(key, { count: next, until: now + WINDOW_MS });
    globalFailures = globalFailures.until > now ? { ...globalFailures, count: globalFailures.count + 1 } : { count: 1, until: now + WINDOW_MS };
    if (failures.size > 10_000) {
      // bound memory: drop expired entries, never live ones (clearing everything would reset every lockout)
      for (const [k, v] of failures) if (v.until <= now) failures.delete(k);
    }
  }
  return new NextResponse("Authentication required", {
    status: 401,
    headers: { "WWW-Authenticate": 'Basic realm="Farrier dashboard", charset="UTF-8"' },
  });
}

// The sign-in gates cover these; FARRIER_REQUIRE_HEADER covers everything the matcher sends here.
const gated = (path: string) =>
  path === "/dashboard" || path.startsWith("/dashboard/") || path.startsWith("/api/farrier/");

export async function proxy(req: NextRequest) {
  const blocked = requiredHeaderStatus(req.headers, req.nextUrl.pathname, process.env);
  if (blocked === 500) return new NextResponse("FARRIER_REQUIRE_HEADER must look like Name:value", { status: 500 });
  if (blocked) return new NextResponse("Forbidden", { status: 403 });
  if (!gated(req.nextUrl.pathname)) return NextResponse.next();
  switch (authMode()) {
    case "oidc":
    case "saml":
      return ssoGate(req);
    case "basic":
      return basicGate(req);
    default:
      return NextResponse.next();
  }
}

export const config = {
  // every path, so FARRIER_REQUIRE_HEADER also guards sign-in, the docs redirect and build assets
  matcher: ["/:path*"],
};
