/**
 * Pure helpers for the project switcher (no imports, so `node --test` runs them).
 */

export interface SwitcherProject {
  name: string;
  title: string;
}

/** `path` with ?project=<name> (or &project=) when a project is picked. */
export function withProject(path: string, project: string | null | undefined): string {
  if (!project) return path;
  return `${path}${path.includes("?") ? "&" : "?"}project=${encodeURIComponent(project)}`;
}

/**
 * What the topbar switcher offers, or null to hide it. A single-team install (only "default") looks exactly
 * as before; so does someone who can open one project only and isn't a global admin.
 */
export function switcherOptions(
  projects: SwitcherProject[] | undefined,
  allProjects: boolean | undefined,
): { all: boolean; projects: SwitcherProject[] } | null {
  const list = projects ?? [];
  if (list.length === 0) return null;
  if (list.length === 1 && (list[0].name === "default" || !allProjects)) return null;
  return { all: Boolean(allProjects), projects: list };
}

/** The pick to use: the stored one if the user may still open it, else none ("all of mine"). */
export function validPick(pick: string | null, projects: SwitcherProject[] | undefined): string | null {
  return pick && (projects ?? []).some((p) => p.name === pick) ? pick : null;
}
