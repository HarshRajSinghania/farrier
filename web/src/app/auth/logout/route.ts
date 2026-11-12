/**
 * POST /auth/logout  (the dashboard's Sign out form; GET works when typed or bookmarked)
 *
 * Clears the session cookie, then ends the provider session through its
 * end_session_endpoint when it has one (RP-Initiated Logout), else returns to /auth/signin.
 */
import { NextResponse, type NextRequest } from "next/server";
import { authMode, oidcConfig } from "@/lib/auth/config";
import { isSameOrigin } from "@/lib/auth/csrf";
import { noStore, postLogoutUri, toSignin } from "@/lib/auth/flow";
import { discover, endSessionUrl } from "@/lib/auth/oidc";
import { allowedOrigins, clearSession, readSession } from "@/lib/auth/session";

async function logout(req: NextRequest) {
  if (authMode() !== "oidc") return noStore(NextResponse.redirect(new URL("/", req.url), 303));
  const cfg = oidcConfig();
  if (!cfg.ok) {
    const res = toSignin(req, "misconfigured");
    clearSession(res);
    return noStore(res);
  }
  const session = await readSession(req, cfg.config);
  let target: string | null = null;
  if (session) {
    try {
      const meta = await discover(cfg.config);
      target = endSessionUrl(meta, cfg.config, { idToken: session.idt, postLogoutRedirectUri: postLogoutUri(req, cfg.config) });
    } catch {
      /* provider unreachable: still sign out locally */
    }
  }
  const res = target ? NextResponse.redirect(target, 303) : toSignin(req, "signed_out");
  clearSession(res);
  return noStore(res);
}

export async function POST(req: NextRequest) {
  // a cross-site form must not be able to sign people out
  if (!isSameOrigin(req.headers, allowedOrigins(req))) {
    return NextResponse.json({ detail: "Cross-site request refused" }, { status: 403 });
  }
  return logout(req);
}

export async function GET(req: NextRequest) {
  // Typed in the address bar (Sec-Fetch-Site: none) or a same-origin link. Anything else
  // (an <img> or link on another site) only lands on the dashboard.
  const site = req.headers.get("sec-fetch-site");
  if (site && site !== "same-origin" && site !== "none") {
    return noStore(NextResponse.redirect(new URL("/dashboard", req.url), 303));
  }
  return logout(req);
}
