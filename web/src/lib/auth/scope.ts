/**
 * Project scope for the engine. Pure (Web Crypto only), so it runs under `node --test`.
 *
 * Which projects a signed-in user may use comes from their SSO groups and each project's member groups
 * (stored with the project in the engine). For every call the bridge sends only the projects where the
 * user's role allows that call, signed so the engine can trust it (farrier/api/scope.py):
 *
 *   X-Farrier-Scope: v1;<ids>;<ts>;<sig>
 *   ids  "*" (global admin) or comma-separated project ids ("" = none)
 *   sig  hex HMAC-SHA256(key, "v1\n<METHOD>\n<path>\n<ids>\n<ts>"), key = HMAC-SHA256(FARRIER_API_TOKEN, "farrier-scope-v1")
 *
 * The signature binds method and path; the engine accepts it for 60 seconds.
 */
import type { Role } from "./roles"; // type-only: this file stays import-free for node --test

const RANK: Record<Role, number> = { viewer: 0, operator: 1, admin: 2 };
const atLeast = (role: Role, required: Role) => RANK[role] >= RANK[required];

export interface ProjectMembers {
  /** members: see the project with their install-wide role */
  groups: string[];
  admin: string[];
  operator: string[];
  viewer: string[];
}

export interface ProjectInfo {
  id: number;
  name: string;
  title: string;
  members: ProjectMembers;
}

const norm = (s: string) => s.trim().replace(/^\/+/, "").toLowerCase();

/**
 * The user's role in each project they belong to. `globalRole` is what the install-wide group mapping gave
 * them at sign-in (global admins never get here: they see everything). A project role group wins; plain
 * members keep their global role. "default" with no member groups at all is open to every signed-in user,
 * so an install that never configured projects behaves as before.
 */
export function projectRoles(groups: string[], projects: ProjectInfo[], globalRole: Role): Map<number, Role> {
  const mine = new Set(groups.map(norm));
  const inAny = (list: string[] | undefined) => (list ?? []).some((g) => mine.has(norm(g)));
  const out = new Map<number, Role>();
  for (const p of projects) {
    const m = p.members ?? { groups: [], admin: [], operator: [], viewer: [] };
    const unconfigured = !m.groups?.length && !m.admin?.length && !m.operator?.length && !m.viewer?.length;
    let role: Role | null = null;
    if (inAny(m.admin)) role = "admin";
    else if (inAny(m.operator)) role = "operator";
    else if (inAny(m.viewer)) role = "viewer";
    else if (inAny(m.groups) || (p.name === "default" && unconfigured)) role = globalRole;
    if (role) out.set(p.id, role);
  }
  return out;
}

/** The highest of the roles (viewer when there are none). */
export function topRole(roles: Iterable<Role>): Role {
  let best: Role = "viewer";
  for (const r of roles) if (atLeast(r, best)) best = r;
  return best;
}

/**
 * The ids to sign for one call: the projects where the role meets `required`, narrowed to `selected`
 * when the dashboard has one project picked. "*" only for a global admin with nothing selected.
 */
export function scopeIds(roles: Map<number, Role> | "all", required: Role, selected?: number | null): string {
  if (roles === "all") return selected == null ? "*" : String(selected);
  const ids = [...roles].filter(([id, r]) => atLeast(r, required) && (selected == null || id === selected)).map(([id]) => id);
  return ids.sort((a, b) => a - b).join(",");
}

const enc = new TextEncoder();
const hex = (b: ArrayBuffer) => [...new Uint8Array(b)].map((x) => x.toString(16).padStart(2, "0")).join("");

async function hmac(key: BufferSource, msg: string): Promise<ArrayBuffer> {
  const k = await crypto.subtle.importKey("raw", key, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return crypto.subtle.sign("HMAC", k, enc.encode(msg));
}

/** The header value for a call to `path` (e.g. "/api/endpoints", no query string). */
export async function signScope(token: string, method: string, path: string, ids: string, ts = Math.floor(Date.now() / 1000)) {
  const key = await hmac(enc.encode(token), "farrier-scope-v1");
  const sig = hex(await hmac(key, `v1\n${method.toUpperCase()}\n${path}\n${ids}\n${ts}`));
  return `v1;${ids};${ts};${sig}`;
}
