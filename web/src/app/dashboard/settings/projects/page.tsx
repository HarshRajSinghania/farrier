"use client";

import { useState } from "react";
import { FolderKanban, Pencil, Plus, Trash2 } from "lucide-react";
import { toast } from "sonner";
import { ErrorNotice, PageHeader } from "@/components/dashboard/shell";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Dialog, DialogClose, DialogContent } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { EmptyState, Skeleton } from "@/components/ui/misc";
import { Table, TBody, TD, TH, THead, TR } from "@/components/ui/table";
import { api, useProjects } from "@/lib/api";
import { useAccess } from "@/lib/auth/client";
import { parseList } from "@/lib/auth/roles";
import type { Project, ProjectMembers } from "@/lib/types";

const ROLE_FIELDS: { key: keyof ProjectMembers; label: string; help: string }[] = [
  { key: "groups", label: "Member groups", help: "See the project with their install-wide role (viewer or operator)." },
  { key: "operator", label: "Operator groups", help: "Renew, cancel, discover and scan in this project." },
  { key: "admin", label: "Admin groups", help: "Also approve discovered endpoints and remove them." },
  { key: "viewer", label: "Viewer groups", help: "Read only, whatever their install-wide role." },
];

const EMPTY: ProjectMembers = { groups: [], admin: [], operator: [], viewer: [] };

function Editor({ project, onClose }: { project: Project | "new"; onClose: () => void }) {
  const isNew = project === "new";
  const [name, setName] = useState(isNew ? "" : project.name);
  const [title, setTitle] = useState(isNew ? "" : project.title);
  const [members, setMembers] = useState<Record<keyof ProjectMembers, string>>(() => {
    const m = isNew ? EMPTY : project.members;
    return { groups: m.groups.join(", "), admin: m.admin.join(", "), operator: m.operator.join(", "), viewer: m.viewer.join(", ") };
  });
  const [state, setState] = useState<{ busy?: boolean; error?: Error }>({});

  const save = async () => {
    setState({ busy: true });
    try {
      await api.saveProject(name.trim(), {
        title: title.trim() || name.trim(),
        members: {
          groups: parseList(members.groups),
          admin: parseList(members.admin),
          operator: parseList(members.operator),
          viewer: parseList(members.viewer),
        },
      });
      toast.success(isNew ? `Project ${name} created` : `Project ${name} saved`);
      onClose();
    } catch (e) {
      setState({ error: e as Error });
    }
  };

  return (
    <form
      className="grid gap-4"
      onSubmit={(e) => {
        e.preventDefault();
        save();
      }}
    >
      <ErrorNotice error={state.error} />
      <label className="grid gap-1 text-sm">
        <span className="font-medium">Name</span>
        <Input
          value={name}
          onChange={(e) => setName(e.target.value.toLowerCase())}
          disabled={!isNew}
          required
          pattern="[a-z0-9][a-z0-9\-]{0,62}"
          placeholder="payments"
        />
        <span className="text-xs text-muted-foreground">Lowercase letters, digits and dashes. It can&apos;t be changed later.</span>
      </label>
      <label className="grid gap-1 text-sm">
        <span className="font-medium">Title</span>
        <Input value={title} onChange={(e) => setTitle(e.target.value)} maxLength={80} placeholder="Payments" />
      </label>
      {ROLE_FIELDS.map(({ key, label, help }) => (
        <label key={key} className="grid gap-1 text-sm">
          <span className="font-medium">{label}</span>
          <Input
            value={members[key]}
            onChange={(e) => setMembers({ ...members, [key]: e.target.value })}
            placeholder="sso-group, another-group"
          />
          <span className="text-xs text-muted-foreground">{help}</span>
        </label>
      ))}
      <div className="flex justify-end gap-2">
        <DialogClose asChild>
          <Button type="button" variant="secondary">
            Cancel
          </Button>
        </DialogClose>
        <Button type="submit" disabled={state.busy || !name.trim()}>
          {state.busy ? "Saving…" : isNew ? "Create project" : "Save"}
        </Button>
      </div>
    </form>
  );
}

const groupsOf = (m: ProjectMembers) =>
  [
    ...m.groups,
    ...m.admin.map((g) => `${g} (admin)`),
    ...m.operator.map((g) => `${g} (operator)`),
    ...m.viewer.map((g) => `${g} (viewer)`),
  ].join(", ");

export default function ProjectsPage() {
  const { status } = useAccess();
  const admin = Boolean(status?.allProjects);
  const { data, error, isLoading } = useProjects();
  const [editing, setEditing] = useState<Project | "new" | null>(null);
  const [confirm, setConfirm] = useState<Project | null>(null);

  return (
    <>
      <PageHeader
        title="Projects"
        description="One install, several teams. Each project's endpoints, renewals, SSH keys and crypto assets are visible only to the SSO groups you name here, and to global admins."
        actions={
          admin && (
            <Button onClick={() => setEditing("new")}>
              <Plus /> New project
            </Button>
          )
        }
      />
      {status && !admin ? (
        <Card>
          <EmptyState icon={<FolderKanban />} title="Global admins only">
            Projects and their member groups are managed by the install&apos;s global admins.
          </EmptyState>
        </Card>
      ) : (
        <>
          <ErrorNotice error={error} />
          <Card className="overflow-hidden">
            {isLoading || !data ? (
              <Skeleton className="m-4 h-32" />
            ) : (
              <Table>
                <THead>
                  <TR>
                    <TH>Project</TH>
                    <TH>Groups</TH>
                    <TH className="text-right">Endpoints</TH>
                    <TH className="w-24">
                      <span className="sr-only">Actions</span>
                    </TH>
                  </TR>
                </THead>
                <TBody>
                  {data.map((p) => (
                    <TR key={p.name}>
                      <TD>
                        <p className="font-medium">{p.title}</p>
                        <p className="font-mono text-xs text-muted-foreground">{p.name}</p>
                      </TD>
                      <TD className="max-w-md text-sm text-muted-foreground">
                        {groupsOf(p.members) ||
                          (p.name === "default" ? "Everyone who can sign in (no groups set)" : "Global admins only (no groups set)")}
                      </TD>
                      <TD className="tabular text-right">{p.endpoints}</TD>
                      <TD>
                        <div className="flex justify-end gap-1">
                          <Button size="icon-sm" variant="ghost" aria-label={`Edit ${p.title}`} onClick={() => setEditing(p)}>
                            <Pencil />
                          </Button>
                          {p.name !== "default" && (
                            <Button size="icon-sm" variant="ghost" aria-label={`Delete ${p.title}`} onClick={() => setConfirm(p)}>
                              <Trash2 />
                            </Button>
                          )}
                        </div>
                      </TD>
                    </TR>
                  ))}
                </TBody>
              </Table>
            )}
          </Card>
          <p className="mt-4 text-xs text-muted-foreground">
            Group names are matched against the FARRIER_OIDC_PROJECT_CLAIM claim (default: the role claim). Edits here apply
            within seconds; a person&apos;s own groups are read when they sign in.
          </p>
        </>
      )}

      <Dialog open={editing !== null} onOpenChange={(o) => !o && setEditing(null)}>
        <DialogContent
          title={editing === "new" ? "New project" : `Edit ${editing?.title ?? ""}`}
          description="Who may open the project, and with which role."
        >
          {editing && <Editor project={editing} onClose={() => setEditing(null)} />}
        </DialogContent>
      </Dialog>

      <Dialog open={!!confirm} onOpenChange={(o) => !o && setConfirm(null)}>
        <DialogContent title={`Delete ${confirm?.title}?`} description="Only an empty project can be deleted: move its endpoints first.">
          <div className="flex justify-end gap-2">
            <DialogClose asChild>
              <Button variant="secondary">Keep it</Button>
            </DialogClose>
            <Button
              variant="danger"
              onClick={async () => {
                const p = confirm!;
                setConfirm(null);
                try {
                  await api.deleteProject(p.name);
                  toast.success(`Deleted ${p.title}`);
                } catch (err) {
                  toast.error("Could not delete project", { description: (err as Error).message });
                }
              }}
            >
              Delete project
            </Button>
          </div>
        </DialogContent>
      </Dialog>
    </>
  );
}
