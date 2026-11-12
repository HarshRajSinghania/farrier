"use client";

/**
 * The signed-in user's role in the browser, to hide actions they can't use. Cosmetic only:
 * the bridge enforces the same rules (lib/auth/roles.ts) on every call.
 *
 *   const { can } = useAccess();
 *   {can("POST", "endpoints") && <AddEndpointButton />}
 */
import { useStatus } from "@/lib/api";
import type { BackendStatus } from "@/lib/types";
import { permits, type Role } from "./roles";

export type AuthKind = "oidc" | "basic" | "none";

export type AuthStatus = Omit<BackendStatus, "auth"> & { role?: Role; auth?: AuthKind };

export function useAccess() {
  const { data, error } = useStatus();
  const status = data as AuthStatus | undefined;
  // until /_status answers, show what an operator would see rather than flashing admin actions
  const role: Role = status?.role ?? "operator";
  return {
    status,
    error,
    role,
    auth: status?.auth,
    can: (method: string, path: string) => permits(role, method, path),
  };
}
