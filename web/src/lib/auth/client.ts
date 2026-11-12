"use client";

/**
 * The signed-in user's role in the browser, to hide actions they can't use. Cosmetic only:
 * the bridge enforces the same rules (lib/auth/roles.ts) on every call.
 *
 *   const { can } = useAccess();
 *   {can("POST", "endpoints") && <AddEndpointButton />}
 */
import { useProject, useStatus } from "@/lib/api";
import type { BackendStatus } from "@/lib/types";
import { permits, type Role } from "./roles";

export type AuthKind = "oidc" | "basic" | "none";

export type AuthStatus = Omit<BackendStatus, "auth"> & { role?: Role; auth?: AuthKind };

export function useAccess() {
  const { data, error } = useStatus();
  const status = data as AuthStatus | undefined;
  const picked = useProject();
  // until /_status answers, show what an operator would see rather than flashing admin actions;
  // with a project picked, the role in that project
  const role: Role = status?.projects?.find((p) => p.name === picked)?.role ?? status?.role ?? "operator";
  return {
    status,
    error,
    role,
    auth: status?.auth,
    can: (method: string, path: string) => permits(role, method, path),
  };
}
