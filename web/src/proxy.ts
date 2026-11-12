/**
 * Sign-in gate for the dashboard and its API bridge.
 *
 *   FARRIER_OIDC_ISSUER set         single sign-on: pages without a session go to /auth/signin,
 *                                   API calls get 401; each request slides the idle timeout.
 *   FARRIER_DASHBOARD_PASSWORD set  HTTP Basic with a lockout on repeated failures (fallback).
 *   neither                         open (demo and local development; see the bridge's guard).
 *
 * This is the first lock. The bridge (app/api/farrier/[...path]/route.ts) checks the session
 * again and enforces roles and the same-origin rule on every call.
 */
import { NextResponse, type NextRequest } from "next/server";
import { checkBasic } from "@/lib/auth/basic";
import { authMode, oidcConfig } from "@/lib/auth/config";
import { clearSession, hasSessionCookie, readSession, touchSession } from "@/lib/auth/session";

const MAX_FAILURES = 10;
const WINDOW_MS = 5 * 60_000;
// Per instance. Behind several replicas each keeps its own count, which still caps guessing.
const failures = new Map<string, { count: number; until: number }>();

function clientKey(req: NextRequest) {
  // the first hop as the load balancer reports it; falls back to one shared bucket
  return req.headers.get("x-forwarded-for")?.split(",")[0].trim() || req.headers.get("x-real-ip") || "unknown";
}

const isApi = (req: NextRequest) => req.nextUrl.pathname.startsWith("/api/");

async function oidcGate(req: NextRequest) {
  const cfg = oidcConfig();
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
  if (entry && entry.until > now && entry.count >= MAX_FAILURES) {
    return new NextResponse("Too many failed sign-ins. Try again in a few minutes.", {
      status: 429,
      headers: { "Retry-After": String(Math.ceil((entry.until - now) / 1000)) },
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
    if (failures.size > 10_000) failures.clear(); // bound memory under a spray of addresses
  }
  return new NextResponse("Authentication required", {
    status: 401,
    headers: { "WWW-Authenticate": 'Basic realm="Farrier dashboard", charset="UTF-8"' },
  });
}

export async function proxy(req: NextRequest) {
  switch (authMode()) {
    case "oidc":
      return oidcGate(req);
    case "basic":
      return basicGate(req);
    default:
      return NextResponse.next();
  }
}

export const config = {
  matcher: ["/dashboard/:path*", "/api/farrier/:path*"],
};
