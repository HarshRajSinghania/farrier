"use client";

import { useEffect } from "react";
import { Check, ChevronsUpDown, FolderKanban } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Dropdown, DropdownContent, DropdownItem, DropdownSeparator, DropdownTrigger } from "@/components/ui/dropdown";
import { setProject, useProject } from "@/lib/api";
import { useAccess } from "@/lib/auth/client";
import { switcherOptions, validPick } from "@/lib/projects";

/**
 * The project the dashboard shows. Hidden on a single-team install (only "default") and for someone who
 * can open one project only. The pick lives in ?project= and localStorage; the server enforces it anyway.
 */
export function ProjectSwitcher() {
  const { status } = useAccess();
  const picked = useProject();
  const opts = switcherOptions(status?.projects, status?.allProjects);

  // a pick that is no longer allowed (removed from a project, project deleted) falls back to all of mine
  useEffect(() => {
    if (status?.projects && picked && validPick(picked, status.projects) === null) setProject(null);
  }, [status?.projects, picked]);

  if (!opts) return null;
  const current = opts.projects.find((p) => p.name === picked);
  const allLabel = opts.all ? "All projects" : "All my projects";
  return (
    <Dropdown>
      <DropdownTrigger asChild>
        <Button variant="secondary" size="sm" className="h-9 max-w-48 gap-2" aria-label="Choose a project">
          <FolderKanban />
          <span className="truncate">{current?.title ?? allLabel}</span>
          <ChevronsUpDown className="opacity-60" />
        </Button>
      </DropdownTrigger>
      <DropdownContent align="start" className="w-56">
        <DropdownItem onSelect={() => setProject(null)}>
          <Check className={picked ? "invisible" : ""} /> {allLabel}
        </DropdownItem>
        <DropdownSeparator />
        {opts.projects.map((p) => (
          <DropdownItem key={p.name} onSelect={() => setProject(p.name)}>
            <Check className={picked === p.name ? "" : "invisible"} />
            <span className="truncate">{p.title}</span>
          </DropdownItem>
        ))}
      </DropdownContent>
    </Dropdown>
  );
}
