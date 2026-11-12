/**
 * Who is calling the bridge, whatever the sign-in mode. proxy.ts already turned away anyone
 * without a login; this re-checks it next to the data (defence in depth) and adds the role.
 */
import "server-only";
import type { NextRequest } from "next/server";
import { checkBasic } from "./basic";
import { authMode, oidcConfig, type AuthMode } from "./config";
import type { Role } from "./roles";
import { readSession } from "./session";

export interface Identity {
  /** display name: the email when the IdP gives one */
  user: string;
  email: string | null;
  /** install-wide role: from the SSO role mapping (admin = global admin, sees every project) */
  role: Role;
  auth: AuthMode;
  /** SSO groups for project membership; null = not project-scoped (global admin, Basic, demo) */
  groups: string[] | null;
}

export type IdentityResult = { ok: true; identity: Identity } | { ok: false; status: number; detail: string };

export async function getIdentity(req: NextRequest, live: boolean): Promise<IdentityResult> {
  const mode = authMode();
  if (mode === "oidc") {
    const cfg = oidcConfig();
    if (!cfg.ok) return { ok: false, status: 500, detail: `Single sign-on is misconfigured: ${cfg.error}` };
    const s = await readSession(req, cfg.config);
    if (!s) return { ok: false, status: 401, detail: "Your session has ended. Sign in again." };
    const email = s.email ?? null;
    const groups = s.role === "admin" ? null : Array.isArray(s.grp) ? s.grp.filter((g) => typeof g === "string") : [];
    return { ok: true, identity: { user: email ?? s.name ?? s.sub, email, role: s.role, auth: "oidc", groups } };
  }
  if (mode === "basic") {
    const user = checkBasic(req.headers.get("authorization"));
    if (!user) return { ok: false, status: 401, detail: "Authentication required" };
    // one shared password: whoever has it administers the dashboard
    return { ok: true, identity: { user, email: null, role: "admin", auth: "basic", groups: null } };
  }
  return { ok: true, identity: { user: live ? "operator" : "demo", email: null, role: "admin", auth: "none", groups: null } };
}
