"use client";

import { useMemo, useState } from "react";
import { usePathname, useRouter, useSearchParams } from "next/navigation";
import { AlertTriangle, DownloadCloud, Info, KeyRound, OctagonAlert, Plus, Radar, Search, Server, ShieldCheck, Trash2, Users } from "lucide-react";
import { toast } from "sonner";
import useSWR from "swr";
import { ErrorNotice, PageHeader } from "@/components/dashboard/shell";
import { StatTile, TableSkeleton } from "@/components/dashboard/widgets";
import { Badge, type BadgeTone } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Dialog, DialogClose, DialogContent } from "@/components/ui/dialog";
import { Input, Textarea } from "@/components/ui/input";
import { EmptyState, Skeleton } from "@/components/ui/misc";
import { Segmented } from "@/components/ui/segmented";
import { Select } from "@/components/ui/select";
import { Table, TBody, TD, TH, THead, TR } from "@/components/ui/table";
import { api, useSshAccess, useSshHosts, useSshKeys, useSshSummary } from "@/lib/api";
import { useAccess } from "@/lib/auth/client";
import type { FindingSeverity, SshAccess, SshFinding, SshHost, SshKey, SshRemoveResult } from "@/lib/types";
import { cn, relativeTime } from "@/lib/utils";
import {
  ChipsInput,
  ConfirmDelete,
  dropOwnedSecrets,
  Field,
  FormActions,
  NAME_PATTERN,
  nameError,
  planSecrets,
  RowActions,
  SecretInput,
  secretState,
  storeSecrets,
  Switch,
  TestOutcome,
  useTests,
  type SecretState,
} from "./integrations/common";

/* ------------------------------------------------------------- vocabulary */

const SEVERITY: Record<FindingSeverity, { label: string; tone: BadgeTone; icon: React.ElementType }> = {
  critical: { label: "Critical", tone: "critical", icon: OctagonAlert },
  warning: { label: "Warning", tone: "warning", icon: AlertTriangle },
  info: { label: "Info", tone: "neutral", icon: Info },
};
const RANK: Record<FindingSeverity, number> = { critical: 0, warning: 1, info: 2 };

function worst(findings: SshFinding[] | null | undefined): FindingSeverity | null {
  if (!findings?.length) return null;
  return [...findings].sort((a, b) => RANK[a.severity] - RANK[b.severity])[0].severity;
}

/** "ssh-ed25519" -> "Ed25519", "ssh-rsa" + 2048 -> "RSA 2048" */
function keyType(type: string, bits: number | null | undefined) {
  const t = type.replace(/^ssh-/, "").replace(/^ecdsa-sha2-nistp/, "ECDSA P-").replace(/^sk-/, "FIDO ");
  const name = t === "ed25519" ? "Ed25519" : t === "rsa" ? "RSA" : t === "dss" ? "DSA" : t;
  return bits && !name.startsWith("ECDSA") && name !== "Ed25519" ? `${name} ${bits}` : name;
}

const weakHostKey = (k: { type: string; bits: number | null }) => k.type === "ssh-dss" || (k.type === "ssh-rsa" && (k.bits ?? 0) < 2048);
const hasPqc = (h: SshHost) => (Array.isArray(h.pqc_kex) ? h.pqc_kex.length > 0 : !!h.pqc_kex);

function Findings({ findings }: { findings: SshFinding[] | null | undefined }) {
  const w = worst(findings);
  if (!w) return <span className="text-sm text-muted-foreground">None</span>;
  const m = SEVERITY[w];
  const list = [...(findings ?? [])].sort((a, b) => RANK[a.severity] - RANK[b.severity]);
  return (
    <div className="min-w-0 space-y-1">
      <Badge tone={m.tone}>
        <m.icon aria-hidden /> {m.label}
      </Badge>
      <p className="max-w-72 truncate text-xs text-muted-foreground" title={list.map((f) => f.detail).join("\n")}>
        {list[0].detail}
        {list.length > 1 && ` · ${list.length - 1} more`}
      </p>
    </div>
  );
}

/* ------------------------------------------------------------------- scan */

function ScanDialog({ open, onOpenChange }: { open: boolean; onOpenChange: (o: boolean) => void }) {
  const [targets, setTargets] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<Error | null>(null);
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent
        title="Scan SSH hosts"
        description="Reads each server's banner, host keys and algorithms. It doesn't log in, so it needs no credentials."
      >
        <form
          className="space-y-4"
          onSubmit={async (e) => {
            e.preventDefault();
            setBusy(true);
            setError(null);
            try {
              const r = await api.sshScan(targets);
              const n = typeof r.scanned === "number" ? r.scanned : null;
              toast.success("SSH scan finished", { description: n !== null ? `${n} targets probed.` : undefined });
              onOpenChange(false);
              setTargets("");
            } catch (err) {
              setError(err as Error);
            } finally {
              setBusy(false);
            }
          }}
        >
          <Field id="ssh-targets" label="Targets" hint="Hosts, IPs or CIDR ranges, separated by commas or new lines. Port 22 unless you add :port.">
            <Textarea
              id="ssh-targets"
              rows={3}
              value={targets}
              onChange={(e) => setTargets(e.target.value)}
              placeholder="10.20.0.0/24, bastion.example.com:2222"
              autoFocus
            />
          </Field>
          <ErrorNotice error={error} />
          <div className="flex justify-end gap-2 border-t pt-4">
            <DialogClose asChild>
              <Button type="button" variant="secondary">
                Cancel
              </Button>
            </DialogClose>
            <Button type="submit" disabled={busy || !targets.trim()}>
              <Radar className={busy ? "animate-pulse" : undefined} /> {busy ? "Scanning…" : "Scan"}
            </Button>
          </div>
        </form>
      </DialogContent>
    </Dialog>
  );
}

/* ------------------------------------------------------------------- keys */

type SeverityFilter = "all" | FindingSeverity | "none";

const PLAN_LABEL: Record<string, string> = {
  host: "Host",
  user: "User",
  file: "File",
  path: "File",
  fingerprint_sha256: "Fingerprint",
  comment: "Comment",
  lines_removed: "Lines removed",
  backup: "Backup",
  access: "Access profile",
};

function RemoveKeyDialog({ sshKey, onClose }: { sshKey: SshKey | null; onClose: () => void }) {
  // a dry run first: the server says what it would change and changes nothing
  const { data: plan, error: planError } = useSWR<SshRemoveResult>(
    sshKey ? ["ssh-remove-plan", sshKey.id] : null,
    () => api.sshRemoveKey(sshKey!.id, true),
    { revalidateOnFocus: false, revalidateIfStale: false, shouldRetryOnError: false },
  );
  const [removeError, setRemoveError] = useState<Error | null>(null);
  const [busy, setBusy] = useState(false);
  const error = removeError ?? planError;

  const rows = plan
    ? Object.entries(plan).filter(([k, v]) => k !== "dry_run" && k !== "removed" && v !== null && v !== undefined && typeof v !== "object")
    : [];

  return (
    <Dialog
      open={!!sshKey}
      onOpenChange={(o) => {
        if (!o) {
          setRemoveError(null);
          onClose();
        }
      }}
    >
      <DialogContent
        title={sshKey ? `Remove ${sshKey.user}'s key from ${sshKey.host}?` : "Remove key"}
        description="Farrier deletes the line from authorized_keys and keeps a backup of the file. Anyone using this key loses access to this account on this host."
      >
        <div className="space-y-4">
          <p className="text-sm font-medium">What will change</p>
          {error ? (
            <ErrorNotice error={error} />
          ) : !plan ? (
            <div role="status" aria-label="Checking what will change" className="space-y-2">
              <Skeleton className="h-4 w-3/4" />
              <Skeleton className="h-4 w-2/3" />
              <Skeleton className="h-4 w-1/2" />
            </div>
          ) : (
            <dl className="divide-y rounded-lg border text-sm">
              {rows.map(([k, v]) => (
                <div key={k} className="grid grid-cols-[8rem_1fr] gap-4 px-4 py-2">
                  <dt className="text-muted-foreground">{PLAN_LABEL[k] ?? k.replaceAll("_", " ")}</dt>
                  <dd className="min-w-0 break-all font-mono text-xs leading-5">{String(v)}</dd>
                </div>
              ))}
            </dl>
          )}
          <p className="text-xs text-muted-foreground">This was a dry run. Nothing has changed yet.</p>
        </div>
        <div className="mt-6 flex justify-end gap-2 border-t pt-4">
          <DialogClose asChild>
            <Button variant="secondary">Keep it</Button>
          </DialogClose>
          <Button
            variant="danger"
            disabled={!plan || busy}
            onClick={async () => {
              if (!sshKey) return;
              setBusy(true);
              try {
                await api.sshRemoveKey(sshKey.id, false);
                toast.success(`Removed ${sshKey.user}'s key from ${sshKey.host}`, { description: "A backup of authorized_keys was kept." });
                onClose();
              } catch (e) {
                setRemoveError(e as Error);
              } finally {
                setBusy(false);
              }
            }}
          >
            <Trash2 /> {busy ? "Removing…" : "Remove key"}
          </Button>
        </div>
      </DialogContent>
    </Dialog>
  );
}

function KeysPanel({ canRemove, canCollect, onCollect, toAccess }: { canRemove: boolean; canCollect: boolean; onCollect: () => void; toAccess: () => void }) {
  const { data, error, isLoading } = useSshKeys();
  const [severity, setSeverity] = useState<SeverityFilter>("all");
  const [query, setQuery] = useState("");
  const [removing, setRemoving] = useState<SshKey | null>(null);

  const rows = useMemo(() => {
    const q = query.trim().toLowerCase();
    return (data ?? [])
      .filter((k) => {
        const w = worst(k.findings);
        if (severity === "none" ? w !== null : severity !== "all" && w !== severity) return false;
        return !q || [k.host, k.user, k.comment, k.fingerprint_sha256, k.type].some((v) => v?.toLowerCase().includes(q));
      })
      .sort((a, b) => RANK[worst(a.findings) ?? "info"] + (worst(a.findings) ? 0 : 3) - (RANK[worst(b.findings) ?? "info"] + (worst(b.findings) ? 0 : 3)) || a.host.localeCompare(b.host));
  }, [data, severity, query]);

  return (
    <>
      <ErrorNotice error={error} />
      <div className="mb-4 flex flex-wrap items-center gap-2">
        <Select
          value={severity}
          onValueChange={(v) => setSeverity(v as SeverityFilter)}
          aria-label="Filter by finding"
          className="w-full sm:w-48"
          options={[
            { value: "all", label: "All keys" },
            { value: "critical", label: "Critical findings" },
            { value: "warning", label: "Warnings" },
            { value: "info", label: "Info only" },
            { value: "none", label: "No findings" },
          ]}
        />
        <div className="relative ml-auto w-full sm:w-64">
          <Search className="pointer-events-none absolute left-2 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" />
          <Input
            placeholder="Search host, user, comment…"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            className="pl-8"
            aria-label="Search SSH keys"
          />
        </div>
      </div>
      <Card className="overflow-hidden">
        {isLoading ? (
          <TableSkeleton />
        ) : rows.length === 0 ? (
          <EmptyState
            icon={<KeyRound />}
            title={data?.length ? "No keys match" : "No keys collected yet"}
            action={
              !data?.length &&
              (canCollect ? (
                <Button onClick={onCollect}>
                  <DownloadCloud /> Collect keys
                </Button>
              ) : (
                <Button variant="secondary" onClick={toAccess}>
                  Set up access
                </Button>
              ))
            }
          >
            {data?.length
              ? "Try a different filter or search."
              : "Farrier reads authorized_keys over SSH using an access profile. Add one under Access, then collect."}
          </EmptyState>
        ) : (
          <Table>
            <THead>
              <TR>
                <TH>Key</TH>
                <TH>Account</TH>
                <TH className="hidden lg:table-cell">Comment</TH>
                <TH>Findings</TH>
                <TH className="hidden md:table-cell">Last seen</TH>
                {canRemove && (
                  <TH className="w-10">
                    <span className="sr-only">Actions</span>
                  </TH>
                )}
              </TR>
            </THead>
            <TBody>
              {rows.map((k) => (
                <TR key={k.id}>
                  <TD>
                    <p className="font-medium">{keyType(k.type, k.bits)}</p>
                    <p className="max-w-56 truncate font-mono text-xs text-muted-foreground" title={k.fingerprint_sha256}>
                      {k.fingerprint_sha256.replace(/^SHA256:/, "").slice(0, 16)}
                    </p>
                  </TD>
                  <TD>
                    <p className="font-medium">{k.user}</p>
                    <p className="font-mono text-xs text-muted-foreground">{k.host}</p>
                  </TD>
                  <TD className="hidden max-w-48 lg:table-cell">
                    <p className="truncate text-sm text-muted-foreground" title={k.comment ?? undefined}>
                      {k.comment || "—"}
                    </p>
                    {k.options && (
                      <p className="truncate font-mono text-xs text-muted-foreground" title={String(k.options)}>
                        {Array.isArray(k.options) ? k.options.join(",") : k.options}
                      </p>
                    )}
                  </TD>
                  <TD>
                    <Findings findings={k.findings} />
                  </TD>
                  <TD className="hidden text-xs text-muted-foreground md:table-cell">{relativeTime(k.last_seen)}</TD>
                  {canRemove && (
                    <TD>
                      <Button size="icon-sm" variant="ghost" aria-label={`Remove ${k.user}'s key from ${k.host}`} title="Remove key" onClick={() => setRemoving(k)}>
                        <Trash2 />
                      </Button>
                    </TD>
                  )}
                </TR>
              ))}
            </TBody>
          </Table>
        )}
      </Card>
      {data && (
        <p className="mt-4 text-xs text-muted-foreground">
          Showing {rows.length} of {data.length} keys
        </p>
      )}
      <RemoveKeyDialog sshKey={removing} onClose={() => setRemoving(null)} />
    </>
  );
}

/* ------------------------------------------------------------------ hosts */

function HostsPanel({ canScan, onScan }: { canScan: boolean; onScan: () => void }) {
  const { data, error, isLoading } = useSshHosts();
  const rows = useMemo(
    () => [...(data ?? [])].sort((a, b) => RANK[worst(a.findings) ?? "info"] - RANK[worst(b.findings) ?? "info"] || a.host.localeCompare(b.host)),
    [data],
  );
  return (
    <>
      <ErrorNotice error={error} />
      <Card className="overflow-hidden">
        {isLoading ? (
          <TableSkeleton />
        ) : !rows.length ? (
          <EmptyState
            icon={<Server />}
            title="No SSH hosts yet"
            action={
              canScan && (
                <Button onClick={onScan}>
                  <Radar /> Scan hosts
                </Button>
              )
            }
          >
            Scan a range to see every SSH server, its host keys and the algorithms it accepts.
          </EmptyState>
        ) : (
          <Table>
            <THead>
              <TR>
                <TH>Host</TH>
                <TH>Host keys</TH>
                <TH>Key exchange</TH>
                <TH>Findings</TH>
                <TH className="hidden md:table-cell">Scanned</TH>
              </TR>
            </THead>
            <TBody>
              {rows.map((h) => (
                <TR key={h.id}>
                  <TD>
                    <p className="font-medium">
                      {h.host}
                      {h.port !== 22 && <span className="text-muted-foreground">:{h.port}</span>}
                    </p>
                    <p className="max-w-56 truncate font-mono text-xs text-muted-foreground" title={h.banner ?? undefined}>
                      {h.banner?.replace(/^SSH-2\.0-/, "") ?? "—"}
                    </p>
                  </TD>
                  <TD>
                    <ul className="flex max-w-64 flex-wrap gap-1">
                      {h.host_keys.map((k) => (
                        <li
                          key={k.fingerprint_sha256}
                          title={k.fingerprint_sha256}
                          className={cn(
                            "inline-flex h-6 items-center rounded-full px-2 text-xs font-medium",
                            weakHostKey(k) ? "bg-critical/12 text-critical-fg" : "bg-muted",
                          )}
                        >
                          {keyType(k.type, k.bits)}
                        </li>
                      ))}
                    </ul>
                  </TD>
                  <TD>
                    {hasPqc(h) ? (
                      <Badge tone="info" title={h.kex.filter((k) => /mlkem|sntrup/.test(k)).join(", ")}>
                        <ShieldCheck aria-hidden /> Post-quantum hybrid
                      </Badge>
                    ) : (
                      <Badge tone="neutral" title={h.kex.slice(0, 4).join(", ")}>
                        Classical only
                      </Badge>
                    )}
                  </TD>
                  <TD>
                    <Findings findings={h.findings} />
                  </TD>
                  <TD className="hidden text-xs text-muted-foreground md:table-cell">{relativeTime(h.observed_at)}</TD>
                </TR>
              ))}
            </TBody>
          </Table>
        )}
      </Card>
    </>
  );
}

/* ----------------------------------------------------------------- access */

const USER_RE = /^[a-z_][a-z0-9_.-]{0,31}$/i;
const HOST_RE = /^[A-Za-z0-9.*:[\]/_-]+$/;

function AccessForm({ entry, taken, onDone }: { entry: SshAccess | null; taken: string[]; onDone: () => void }) {
  const [name, setName] = useState(entry?.name ?? "");
  const [username, setUsername] = useState(entry?.username ?? "");
  const [key, setKey] = useState<SecretState>(() => secretState(entry?.private_key ?? null));
  const [port, setPort] = useState(String(entry?.port ?? 22));
  const [hosts, setHosts] = useState<string[]>(entry?.hosts ?? []);
  const [sudo, setSudo] = useState(entry?.sudo ?? false);
  const [policy, setPolicy] = useState<SshAccess["known_hosts_policy"]>(entry?.known_hosts_policy ?? "strict");
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [busy, setBusy] = useState(false);
  const [serverError, setServerError] = useState<Error | null>(null);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setServerError(null);
    const errs: Record<string, string> = {};
    const nameErr = entry ? null : nameError(name, taken);
    if (nameErr) errs.name = nameErr;
    if (!USER_RE.test(username)) errs.username = "Enter the account Farrier logs in as.";
    const p = Number(port);
    if (!Number.isInteger(p) || p < 1 || p > 65535) errs.port = "1 to 65535.";
    if (!hosts.length) errs.hosts = "Add at least one host or pattern.";
    const plan = planSecrets([{ key: "private_key", required: true }], { private_key: key }, `ssh-${name}`);
    Object.assign(errs, plan.errors);
    setErrors(errs);
    if (Object.keys(errs).length) return;
    setBusy(true);
    try {
      await storeSecrets(plan.puts);
      await api.saveSshAccess(name, {
        username,
        private_key: plan.refs.private_key,
        port: p,
        hosts,
        sudo,
        known_hosts_policy: policy,
      });
      toast.success(entry ? `Saved ${name}` : `Added ${name}`, { description: "Test it before collecting keys." });
      onDone();
    } catch (err) {
      setServerError(err as Error);
    } finally {
      setBusy(false);
    }
  }

  return (
    <form onSubmit={submit} className="space-y-6" noValidate>
      <div className="grid gap-4 sm:grid-cols-2">
        <Field id="ssh-name" label="Name" error={errors.name} hint={entry ? "Names can't change." : "Like linux-ops."}>
          <Input
            id="ssh-name"
            value={name}
            onChange={(e) => setName(e.target.value.trim())}
            disabled={!!entry}
            pattern={NAME_PATTERN}
            placeholder="linux-ops"
            aria-invalid={!!errors.name}
            autoFocus={!entry}
          />
        </Field>
        <Field id="ssh-user" label="Username" error={errors.username} hint="The account Farrier logs in as.">
          <Input id="ssh-user" value={username} onChange={(e) => setUsername(e.target.value.trim())} placeholder="farrier" aria-invalid={!!errors.username} spellCheck={false} />
        </Field>
      </div>
      <SecretInput
        id="ssh-key"
        label="Private key"
        required
        multiline
        placeholder="-----BEGIN OPENSSH PRIVATE KEY-----"
        help="An Ed25519 or RSA key whose public half is in the account's authorized_keys."
        state={key}
        onChange={setKey}
        error={errors.private_key}
      />
      <Field id="ssh-hosts" label="Hosts" error={errors.hosts} hint="Names, patterns like *.example.internal, or CIDR ranges.">
        <ChipsInput
          id="ssh-hosts"
          value={hosts}
          onChange={setHosts}
          placeholder="*.acme.internal, 10.20.0.0/24"
          validate={(h) => (HOST_RE.test(h) ? null : `${h} isn't a host, pattern or range.`)}
          invalid={!!errors.hosts}
        />
      </Field>
      <div className="grid gap-4 sm:grid-cols-2">
        <Field id="ssh-port" label="Port" error={errors.port}>
          <Input id="ssh-port" inputMode="numeric" value={port} onChange={(e) => setPort(e.target.value)} aria-invalid={!!errors.port} />
        </Field>
        <Field
          id="ssh-policy"
          label="Unknown host keys"
          hint={policy === "strict" ? "Only connects to hosts whose key is already known." : "Trusts a host's key the first time, then refuses a change."}
        >
          <Select
            id="ssh-policy"
            value={policy}
            onValueChange={(v) => setPolicy(v as SshAccess["known_hosts_policy"])}
            options={[
              { value: "strict", label: "Strict" },
              { value: "tofu", label: "Trust on first use" },
            ]}
          />
        </Field>
      </div>
      <div className="space-y-2">
        <div className="flex items-center gap-4">
          <Switch id="ssh-sudo" checked={sudo} onChange={setSudo} label="Use sudo" />
          <label htmlFor="ssh-sudo" className="text-sm font-medium">
            Use sudo
          </label>
        </div>
        <p className="text-xs text-muted-foreground">Needed to read and edit other users&rsquo; authorized_keys. Without it Farrier only sees this account&rsquo;s keys.</p>
      </div>
      <ErrorNotice error={serverError} />
      <FormActions busy={busy} label={entry ? "Save changes" : "Add access"} busyLabel="Saving…" />
    </form>
  );
}

function AccessPanel({ canWrite, canCollect, onCollect }: { canWrite: boolean; canCollect: boolean; onCollect: (name?: string) => void }) {
  const { data, error, isLoading } = useSshAccess();
  const [editing, setEditing] = useState<SshAccess | "new" | null>(null);
  const [deleting, setDeleting] = useState<SshAccess | null>(null);
  const tests = useTests();
  const add = (
    <Button onClick={() => setEditing("new")}>
      <Plus /> Add access
    </Button>
  );
  return (
    <>
      <ErrorNotice error={error} />
      <Card className="overflow-hidden">
        {canWrite && !!data?.length && <div className="flex justify-end border-b px-6 py-4">{add}</div>}
        {isLoading ? (
          <TableSkeleton rows={2} />
        ) : !data?.length ? (
          <EmptyState icon={<Users />} title="No access profiles" action={canWrite ? add : undefined}>
            An access profile is an account and key Farrier uses to read authorized_keys on a set of hosts.
          </EmptyState>
        ) : (
          <Table>
            <THead>
              <TR>
                <TH>Name</TH>
                <TH>Logs in as</TH>
                <TH>Hosts</TH>
                <TH className="hidden md:table-cell">Host keys</TH>
                <TH className="text-right">
                  <span className="sr-only">Actions</span>
                </TH>
              </TR>
            </THead>
            <TBody>
              {data.map((a) => {
                const result = tests.results[a.name];
                return [
                  <TR key={a.name}>
                    <TD className="font-medium">{a.name}</TD>
                    <TD>
                      <span className="font-mono text-sm">
                        {a.username}
                        {a.port !== 22 && <span className="text-muted-foreground"> :{a.port}</span>}
                      </span>
                      {a.sudo && (
                        <Badge tone="neutral" className="ml-2">
                          sudo
                        </Badge>
                      )}
                    </TD>
                    <TD>
                      <p className="max-w-72 truncate font-mono text-xs text-muted-foreground" title={a.hosts.join(", ")}>
                        {a.hosts.join(", ")}
                      </p>
                    </TD>
                    <TD className="hidden text-sm text-muted-foreground md:table-cell">{a.known_hosts_policy === "tofu" ? "Trust on first use" : "Strict"}</TD>
                    <TD>
                      <div className="flex items-center justify-end gap-1">
                        {canCollect && (
                          <Button size="sm" variant="ghost" onClick={() => onCollect(a.name)}>
                            <DownloadCloud /> Collect
                          </Button>
                        )}
                        <RowActions
                          name={a.name}
                          canWrite={canWrite}
                          canTest={canWrite}
                          readOnly={a.source === "file"}
                          testing={result === "running"}
                          onTest={() => tests.run(a.name, () => api.testSshAccess(a.name))}
                          onEdit={() => setEditing(a)}
                          onDelete={() => setDeleting(a)}
                        />
                      </div>
                    </TD>
                  </TR>,
                  result && result !== "running" && (
                    <tr key={`${a.name}-test`} className="border-b">
                      <td colSpan={5} className="px-6 pb-4 pt-0">
                        <TestOutcome result={result} onDismiss={() => tests.dismiss(a.name)} />
                      </td>
                    </tr>
                  ),
                ];
              })}
            </TBody>
          </Table>
        )}
      </Card>

      <Dialog open={!!editing} onOpenChange={(o) => !o && setEditing(null)}>
        <DialogContent
          title={editing && editing !== "new" ? `Edit ${editing.name}` : "Add SSH access"}
          description="An account and key Farrier uses to read authorized_keys."
          className="max-w-xl"
        >
          {editing && (
            <AccessForm
              key={editing === "new" ? "new" : editing.name}
              entry={editing === "new" ? null : editing}
              taken={(data ?? []).map((a) => a.name)}
              onDone={() => setEditing(null)}
            />
          )}
        </DialogContent>
      </Dialog>

      <ConfirmDelete
        open={!!deleting}
        onOpenChange={(o) => !o && setDeleting(null)}
        title={`Delete ${deleting?.name ?? ""}?`}
        onConfirm={async () => {
          if (!deleting) return;
          await api.deleteSshAccess(deleting.name);
          await dropOwnedSecrets([deleting.private_key], `ssh-${deleting.name}`);
          toast.success(`Deleted ${deleting.name}`);
        }}
      >
        <p>Farrier stops collecting keys with this profile. Its stored private key is deleted too. Keys already collected stay listed.</p>
      </ConfirmDelete>
    </>
  );
}

/* ------------------------------------------------------------------- page */

type Tab = "keys" | "hosts" | "access";

export function SshView() {
  const params = useSearchParams();
  const router = useRouter();
  const path = usePathname();
  const raw = params.get("tab");
  const tab: Tab = raw === "hosts" || raw === "access" ? raw : "keys";
  const setTab = (t: Tab) => router.replace(t === "keys" ? path : `${path}?tab=${t}`, { scroll: false });
  const { data: summary, error, isLoading } = useSshSummary();
  const { data: access } = useSshAccess();
  const { can } = useAccess();
  const [scanning, setScanning] = useState(false);
  const [collecting, setCollecting] = useState(false);
  const canScan = can("POST", "ssh/scan");
  const canCollect = can("POST", "ssh/collect");
  const canWrite = can("PUT", "ssh/access/x");

  const collect = async (name?: string) => {
    setCollecting(true);
    try {
      const r = await api.sshCollect(name);
      const parts = [typeof r.hosts === "number" && `${r.hosts} hosts`, typeof r.keys === "number" && `${r.keys} keys`].filter(Boolean);
      toast.success("Keys collected", { description: parts.length ? parts.join(", ") : undefined });
    } catch (e) {
      toast.error("Could not collect keys", { description: (e as Error).message });
    } finally {
      setCollecting(false);
    }
  };

  const by = summary?.by_severity;
  return (
    <>
      <PageHeader
        title="SSH keys"
        description="Every authorized key and SSH server Farrier has seen, with what's wrong with each."
        actions={
          <>
            {canScan && (
              <Button variant="secondary" onClick={() => setScanning(true)}>
                <Radar /> Scan hosts
              </Button>
            )}
            {canCollect && (
              <Button onClick={() => collect()} disabled={collecting || !access?.length} title={access?.length ? undefined : "Add an access profile first"}>
                <DownloadCloud className={collecting ? "animate-pulse" : undefined} /> {collecting ? "Collecting…" : "Collect keys"}
              </Button>
            )}
          </>
        }
      />
      <ErrorNotice error={error} />

      <div className="mb-8 grid grid-cols-2 gap-4 lg:grid-cols-5">
        <StatTile label="Hosts" value={summary?.hosts ?? "—"} icon={Server} loading={isLoading}
          footer={summary ? `${summary.pqc_kex_hosts} offer post-quantum key exchange` : undefined} />
        <StatTile label="Authorized keys" value={summary?.keys ?? "—"} icon={KeyRound} loading={isLoading}
          footer={by ? `${summary!.keys - by.critical - by.warning - by.info} with no findings` : undefined} />
        <StatTile label="Critical" value={by?.critical ?? "—"} icon={OctagonAlert} loading={isLoading}
          tone={by?.critical ? "critical" : "default"} footer={by?.critical ? "Weak or retired key types" : "No weak key types"} />
        <StatTile label="Warnings" value={by?.warning ?? "—"} icon={AlertTriangle} loading={isLoading}
          tone={by?.warning ? "warning" : "default"} footer={by?.warning ? "Unowned or unrestricted keys" : "Nothing to review"} />
        <StatTile label="Weak host keys" value={summary?.weak_host_keys ?? "—"} icon={ShieldCheck} loading={isLoading}
          tone={summary?.weak_host_keys ? "critical" : "good"} footer={summary?.weak_host_keys ? "DSA or RSA under 2048 bits" : "All host keys are strong"} />
      </div>

      <Segmented
        label="SSH section"
        value={tab}
        onChange={setTab}
        className="mb-6"
        options={[
          { value: "keys", label: "Keys", count: summary?.keys },
          { value: "hosts", label: "Hosts", count: summary?.hosts },
          { value: "access", label: "Access", count: access?.length },
        ]}
      />
      {tab === "keys" ? (
        <KeysPanel canRemove={can("POST", "ssh/keys/x/remove")} canCollect={canCollect && !!access?.length} onCollect={() => collect()} toAccess={() => setTab("access")} />
      ) : tab === "hosts" ? (
        <HostsPanel canScan={canScan} onScan={() => setScanning(true)} />
      ) : (
        <AccessPanel canWrite={canWrite} canCollect={canCollect} onCollect={collect} />
      )}
      <ScanDialog open={scanning} onOpenChange={setScanning} />
    </>
  );
}
