/**
 * Role-based access for the dashboard. Pure functions with no imports, so they run in the
 * browser (to hide actions), on the server (to enforce them) and under `node --test`.
 *
 *   viewer    read everything except change packs and runbooks (they carry key material)
 *   operator  + renew, advance, cancel, run a cycle, discover, download packs and runbooks
 *   admin     + add and delete endpoints, test notifiers, anything not listed here
 */

export type Role = "viewer" | "operator" | "admin";

export const ROLES: readonly Role[] = ["viewer", "operator", "admin"];

const RANK: Record<Role, number> = { viewer: 0, operator: 1, admin: 2 };

export function atLeast(role: Role, required: Role): boolean {
  return RANK[role] >= RANK[required];
}

export interface RoleMapping {
  /** claim holding groups or roles; a top-level key first, then a dotted path (realm_access.roles) */
  claim: string;
  admin: string[];
  operator: string[];
  /** when non-empty, anyone in none of these (nor in admin/operator) is refused */
  allowed: string[];
}

/** "a, b ,c" -> ["a", "b", "c"] */
export function parseList(value: string | undefined | null): string[] {
  return (value ?? "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
}

// Keycloak emits full group paths ("/farrier/admins"); Entra object ids are case-insensitive.
const norm = (s: string) => s.trim().replace(/^\/+/, "").toLowerCase();

/** The values of a claim as strings. Accepts a string, a string array, or nested objects via dots. */
export function claimValues(claims: Record<string, unknown>, path: string): string[] {
  let value: unknown = claims[path];
  if (value === undefined && path.includes(".")) {
    value = path.split(".").reduce<unknown>(
      (node, key) => (node && typeof node === "object" ? (node as Record<string, unknown>)[key] : undefined),
      claims,
    );
  }
  if (typeof value === "string") return value ? [value] : [];
  if (Array.isArray(value)) return value.filter((v): v is string => typeof v === "string" && v !== "");
  return [];
}

/** The role for a signed-in user's claims, or null when they may not use the dashboard at all. */
export function mapRole(claims: Record<string, unknown>, mapping: RoleMapping): Role | null {
  const mine = new Set(claimValues(claims, mapping.claim).map(norm));
  const inAny = (groups: string[]) => groups.some((g) => mine.has(norm(g)));
  if (inAny(mapping.admin)) return "admin";
  if (inAny(mapping.operator)) return "operator";
  if (mapping.allowed.length && !inAny(mapping.allowed)) return null;
  return "viewer";
}

const OPERATOR_POSTS = [
  /^endpoints\/[^/]+\/renew$/,
  /^renewals\/[^/]+\/(advance|cancel)$/,
  /^tick$/,
  /^discover$/,
];
const OPERATOR_GETS = [/^renewals\/[^/]+\/(pack|runbook)$/];

/**
 * The least role allowed to make this call to the bridge (`path` is what follows /api/farrier/).
 * Unknown changes default to admin so a new engine route is never opened by accident.
 */
export function requiredRole(method: string, path: string[] | string): Role {
  const p = (Array.isArray(path) ? path.join("/") : path).replace(/^\/+|\/+$/g, "").split("?")[0];
  const m = method.toUpperCase();
  if (m === "GET" || m === "HEAD") return OPERATOR_GETS.some((r) => r.test(p)) ? "operator" : "viewer";
  if (m === "POST" && OPERATOR_POSTS.some((r) => r.test(p))) return "operator";
  return "admin";
}

export function permits(role: Role, method: string, path: string[] | string): boolean {
  return atLeast(role, requiredRole(method, path));
}

export function denyMessage(role: Role, required: Role): string {
  const what = required === "admin" ? "an admin" : "an operator or admin";
  return `Your role (${role}) can't do this; it needs ${what}. Ask your identity provider admin to add you to the right group.`;
}

/** The engine's audit log accepts [A-Za-z0-9._@-]{1,64}; keep the readable parts of an email. */
export function actorName(name: string | null | undefined, fallback = "dashboard"): string {
  const cleaned = (name ?? "").replace(/[^A-Za-z0-9._@-]/g, "_").slice(0, 64);
  return cleaned || fallback;
}
