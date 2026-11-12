"use client";

import { useState } from "react";
import { usePathname, useRouter, useSearchParams } from "next/navigation";
import { BellRing, ChevronRight, Mail, MessageSquare, Plus, Send, Webhook } from "lucide-react";
import { toast } from "sonner";
import { ErrorNotice, PageHeader } from "@/components/dashboard/shell";
import { TableSkeleton } from "@/components/dashboard/widgets";
import { CONNECTOR_LABEL } from "@/components/status";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Dialog, DialogContent } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Select } from "@/components/ui/select";
import { EmptyState } from "@/components/ui/misc";
import { Segmented } from "@/components/ui/segmented";
import { Table, TBody, TD, TH, THead, TR } from "@/components/ui/table";
import { api, useAlertRules, useCatalog, useConnectors, useNotifiers } from "@/lib/api";
import { useAccess } from "@/lib/auth/client";
import type { AlertRule, AlertRuleInput, AlertWhen, HealthGrade, NotifierChannel, NotifierInput } from "@/lib/types";
import { cn, relativeTime } from "@/lib/utils";
import {
  ChipsInput,
  ConfirmDelete,
  dropOwnedSecrets,
  Field,
  LogoTile,
  FormActions,
  NAME_PATTERN,
  nameError,
  planSecrets,
  RowActions,
  SecretInput,
  secretState,
  SourceBadge,
  storeSecrets,
  Switch,
  TestOutcome,
  useTests,
  type SecretState,
} from "./common";

/* -------------------------------------------------------------- vocabulary */

const EVENTS: { id: string; label: string; verb: string }[] = [
  { id: "failed", label: "Failed", verb: "fails" },
  { id: "rolled_back", label: "Rolled back", verb: "is rolled back" },
  { id: "awaiting_manual", label: "Awaiting a person", verb: "needs a person" },
  { id: "issued", label: "Issued", verb: "is issued" },
  { id: "done", label: "Done", verb: "completes" },
];
const DEFAULT_EVENTS = ["failed", "rolled_back", "awaiting_manual"];

const ZOMBIE_KINDS: Record<string, string> = {
  expired_served: "Expired, still served",
  stale_duplicate: "Old certificate still served",
  unexpected_issuer: "Issued by another CA",
  unexpected_issuance: "Not issued by Farrier",
  dead_endpoint: "Endpoint not answering",
  pack_never_installed: "Change pack never installed",
  discovered_unowned: "Discovered, no owner",
  not_in_inventory: "Not in the inventory",
};

const RULE_TYPES: { id: AlertWhen["type"]; label: string }[] = [
  { id: "expiring", label: "Certificate expiring" },
  { id: "event", label: "Renewal event" },
  { id: "health", label: "Health grade drops" },
  { id: "zombie", label: "Zombie certificate found" },
  { id: "unreachable", label: "Endpoint unreachable" },
];

const CHANNEL_ICON: Record<string, React.ElementType> = { slack: MessageSquare, teams: MessageSquare, webhook: Webhook, email: Mail, ses: Mail };
// brand marks shipped in public/assets/icons; ServiceNow has no free mark, so it gets the initial tile
const CHANNEL_LOGO: Record<string, string | null> = {
  jira: "/assets/icons/jira.svg",
  datadog: "/assets/icons/datadog.svg",
  splunk: "/assets/icons/splunk.svg",
  servicenow: null,
};

function ChannelMark({ type, label }: { type: string; label: string }) {
  if (type in CHANNEL_LOGO) return <LogoTile src={CHANNEL_LOGO[type]} label={label} className="size-5 rounded p-0.5 text-xs" />;
  const Icon = CHANNEL_ICON[type] ?? BellRing;
  return <Icon className="size-4 shrink-0 text-muted-foreground" aria-hidden />;
}

const joinOr = (xs: string[]) => (xs.length <= 1 ? xs.join("") : `${xs.slice(0, -1).join(", ")} or ${xs.at(-1)}`);

/** The rule's condition in plain words. */
export function describeWhen(w: AlertWhen): string {
  switch (w.type) {
    case "expiring":
      return `Certificate expires within ${w.days} day${w.days === 1 ? "" : "s"}`;
    case "event":
      return `A renewal ${joinOr(w.events.map((e) => EVENTS.find((x) => x.id === e)?.verb ?? e.replaceAll("_", " ")))}`;
    case "health":
      return `Health grade drops below ${w.below}`;
    case "zombie":
      return w.kinds?.length
        ? `Zombie certificate found: ${joinOr(w.kinds.map((k) => (ZOMBIE_KINDS[k] ?? k).toLowerCase()))}`
        : "Zombie certificate found";
    case "unreachable":
      return `Endpoint unreachable for ${w.days} day${w.days === 1 ? "" : "s"}`;
  }
}

function describeFilter(f: AlertRule["filter"]): string | null {
  if (!f) return null;
  const parts = [
    f.tags?.length && `tagged ${f.tags.join(", ")}`,
    f.connectors?.length && `on ${f.connectors.map((c) => CONNECTOR_LABEL[c] ?? c).join(", ")}`,
    f.name && `named ${f.name}`,
  ].filter(Boolean);
  return parts.length ? `Only endpoints ${parts.join(", ")}` : null;
}

const toInput = (r: AlertRule, patch: Partial<AlertRuleInput> = {}): AlertRuleInput => ({
  enabled: r.enabled,
  when: r.when,
  ...(r.filter ? { filter: r.filter } : {}),
  channels: r.channels,
  ...(r.cooldown_hours != null ? { cooldown_hours: r.cooldown_hours } : {}),
  ...patch,
});

function Toggles({
  label,
  options,
  value,
  onChange,
  invalid,
}: {
  label: string;
  options: { id: string; label: React.ReactNode }[];
  value: string[];
  onChange: (v: string[]) => void;
  invalid?: boolean;
}) {
  return (
    <div role="group" aria-label={label} className="flex flex-wrap gap-2">
      {options.map((o) => {
        const on = value.includes(o.id);
        return (
          <button
            key={o.id}
            type="button"
            aria-pressed={on}
            onClick={() => onChange(on ? value.filter((x) => x !== o.id) : [...value, o.id])}
            className={cn(
              "inline-flex h-8 items-center gap-2 rounded-md border px-2 text-xs font-medium text-muted-foreground hover:bg-muted",
              on && "border-foreground bg-muted text-foreground",
              invalid && !on && "border-critical/60",
            )}
          >
            {o.label}
          </button>
        );
      })}
    </div>
  );
}

/* --------------------------------------------------------------- channels */

// a field the server keeps but doesn't return: shown as stored, left out of the save
const UNKNOWN_REF = "vault:(stored)";

function ChannelForm({ entry, taken, onDone }: { entry: NotifierChannel | null; taken: string[]; onDone: () => void }) {
  const { data: catalog } = useCatalog();
  const types = catalog?.notifier_types ?? [];
  const [name, setName] = useState(entry?.name ?? "");
  const [typeId, setTypeId] = useState(entry?.type ?? "slack");
  const type = types.find((t) => t.id === typeId);
  const initial = (id: string) => {
    const t = types.find((x) => x.id === id);
    const vals: Record<string, string> = {};
    const secs: Record<string, SecretState> = {};
    for (const f of t?.fields ?? []) {
      const v = entry && entry.type === id ? entry[f.key] : undefined;
      if (f.secret) secs[f.key] = secretState(typeof v === "string" ? v : entry && entry.type === id && f.required ? UNKNOWN_REF : null);
      else if (typeof v === "string" || typeof v === "number" || typeof v === "boolean") vals[f.key] = String(v);
      else if (f.default !== undefined && f.default !== null) vals[f.key] = String(f.default);
    }
    return { vals, secs };
  };
  const [values, setValues] = useState<Record<string, string>>(() => initial(typeId).vals);
  const [secrets, setSecrets] = useState<Record<string, SecretState>>(() => initial(typeId).secs);
  const [events, setEvents] = useState<string[]>(entry?.events ?? DEFAULT_EVENTS);
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [busy, setBusy] = useState(false);
  const [serverError, setServerError] = useState<Error | null>(null);

  const pick = (id: string) => {
    setTypeId(id);
    const i = initial(id);
    setValues(i.vals);
    setSecrets(i.secs);
    setErrors({});
  };

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setServerError(null);
    if (!type) return;
    const errs: Record<string, string> = {};
    const nameErr = entry ? null : nameError(name, taken);
    if (nameErr) errs.name = nameErr;
    for (const f of type.fields) {
      const v = values[f.key]?.trim() ?? "";
      if (!f.secret && f.required && !v) errs[f.key] = "Required.";
      if (!f.secret && f.key === "url" && v && !/^https?:\/\/\S+$/.test(v)) errs[f.key] = "Enter an https:// URL.";
      if (!f.secret && (f.key === "from" || f.key === "to") && v && !v.split(",").every((a) => /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(a.trim())))
        errs[f.key] = f.key === "to" ? "Enter email addresses separated by commas." : "Enter an email address.";
    }
    const plan = planSecrets(type.fields.filter((f) => f.secret), secrets, `notifier-${name}`);
    Object.assign(errs, plan.errors);
    setErrors(errs);
    if (Object.keys(errs).length) return;

    const body: NotifierInput = { type: type.id, events };
    for (const f of type.fields) {
      if (f.secret) {
        const ref = plan.refs[f.key];
        if (ref && ref !== UNKNOWN_REF) body[f.key] = ref;
      } else if (f.type === "bool") body[f.key] = values[f.key] === "true";
      else if (values[f.key]?.trim()) body[f.key] = values[f.key].trim();
    }
    setBusy(true);
    try {
      await storeSecrets(plan.puts);
      await api.saveNotifier(name, body);
      toast.success(entry ? `Saved ${name}` : `Added ${name}`, { description: "Send a test to check it arrives." });
      onDone();
    } catch (err) {
      setServerError(err as Error);
    } finally {
      setBusy(false);
    }
  }

  return (
    <form onSubmit={submit} className="space-y-6" noValidate>
      <Field id="ch-name" label="Name" error={errors.name} hint={entry ? "Names can't change; add a new channel instead." : "Rules send to it by this name."}>
        <Input
          id="ch-name"
          value={name}
          onChange={(e) => setName(e.target.value.trim())}
          disabled={!!entry}
          pattern={NAME_PATTERN}
          placeholder="ops-slack"
          aria-invalid={!!errors.name}
          autoFocus={!entry}
        />
      </Field>

      <fieldset>
        <legend className="mb-2 text-sm font-medium">Type</legend>
        {entry ? (
          <p className="text-sm font-medium">{type?.label ?? typeId}</p>
        ) : (
          <div role="radiogroup" aria-label="Channel type" className="grid grid-cols-2 gap-2 sm:grid-cols-3">
            {types.map((t) => {
              const on = t.id === typeId;
              return (
                <button
                  key={t.id}
                  type="button"
                  role="radio"
                  aria-checked={on}
                  onClick={() => pick(t.id)}
                  className={cn(
                    "flex h-10 items-center gap-2 rounded-lg border px-4 text-left text-sm font-medium text-muted-foreground hover:bg-muted",
                    on && "border-foreground bg-muted text-foreground",
                  )}
                >
                  <ChannelMark type={t.id} label={t.label} />
                  <span className="truncate">{t.label}</span>
                </button>
              );
            })}
          </div>
        )}
      </fieldset>

      {type && (
        <div className="grid gap-4 sm:grid-cols-2">
          {type.fields.map((f) =>
            f.secret ? (
              <SecretInput
                key={`${type.id}-${f.key}`}
                id={`ch-${f.key}`}
                label={f.label}
                required={f.required}
                help={f.help}
                state={secrets[f.key] ?? secretState()}
                onChange={(s) => setSecrets((x) => ({ ...x, [f.key]: s }))}
                error={errors[f.key]}
              />
            ) : f.type === "bool" ? (
              <div key={`${type.id}-${f.key}`} className="space-y-2 sm:col-span-2">
                <div className="flex items-center gap-4">
                  <Switch
                    id={`ch-${f.key}`}
                    checked={values[f.key] === "true"}
                    onChange={(v) => setValues((x) => ({ ...x, [f.key]: String(v) }))}
                    label={f.label}
                  />
                  <label htmlFor={`ch-${f.key}`} className="text-sm font-medium">
                    {f.label}
                  </label>
                </div>
                {f.help && <p className="text-xs text-muted-foreground">{f.help}</p>}
              </div>
            ) : f.options?.length ? (
              <Field key={`${type.id}-${f.key}`} id={`ch-${f.key}`} label={f.label} optional={!f.required} hint={f.help} error={errors[f.key]}>
                <Select
                  id={`ch-${f.key}`}
                  value={values[f.key] ?? ""}
                  onValueChange={(v) => setValues((x) => ({ ...x, [f.key]: v }))}
                  options={f.options.map((o) => ({ value: o, label: o }))}
                  aria-invalid={!!errors[f.key]}
                />
              </Field>
            ) : (
              <Field key={`${type.id}-${f.key}`} id={`ch-${f.key}`} label={f.label} optional={!f.required} hint={f.help} error={errors[f.key]}>
                <Input
                  id={`ch-${f.key}`}
                  value={values[f.key] ?? ""}
                  onChange={(e) => setValues((x) => ({ ...x, [f.key]: e.target.value }))}
                  aria-invalid={!!errors[f.key]}
                  spellCheck={false}
                />
              </Field>
            ),
          )}
        </div>
      )}

      <div className="space-y-2">
        <p className="text-sm font-medium">Renewal events</p>
        <Toggles label="Renewal events" options={EVENTS} value={events} onChange={setEvents} />
        <p className="text-xs text-muted-foreground">Sent straight to this channel as they happen. Alert rules can send here as well.</p>
      </div>

      <ErrorNotice error={serverError} />
      <FormActions busy={busy} label={entry ? "Save changes" : "Add channel"} busyLabel="Saving…" />
    </form>
  );
}

function ChannelsPanel({ canWrite, canTest }: { canWrite: boolean; canTest: boolean }) {
  const { data, error, isLoading } = useNotifiers();
  const { data: rules } = useAlertRules();
  const { data: catalog } = useCatalog();
  const [editing, setEditing] = useState<NotifierChannel | "new" | null>(null);
  const [deleting, setDeleting] = useState<NotifierChannel | null>(null);
  const tests = useTests();
  const label = (id: string) => catalog?.notifier_types.find((t) => t.id === id)?.label ?? id;
  const add = (
    <Button onClick={() => setEditing("new")}>
      <Plus /> Add channel
    </Button>
  );
  const usedBy = deleting ? (rules ?? []).filter((r) => r.channels.includes(deleting.name)).map((r) => r.name) : [];

  return (
    <>
      <ErrorNotice error={error} />
      <Card className="overflow-hidden">
        {canWrite && !!data?.length && <div className="flex justify-end border-b px-6 py-4">{add}</div>}
        {isLoading ? (
          <TableSkeleton rows={2} />
        ) : !data?.length ? (
          <EmptyState icon={<Send />} title="No channels" action={canWrite ? add : undefined}>
            Channels are where alerts go: Slack, Teams, email, a webhook, ServiceNow, Jira, Datadog or Splunk.
          </EmptyState>
        ) : (
          <Table>
            <THead>
              <TR>
                <TH>Name</TH>
                <TH>Type</TH>
                <TH>Sends to</TH>
                <TH>Renewal events</TH>
                <TH>Source</TH>
                <TH className="text-right">
                  <span className="sr-only">Actions</span>
                </TH>
              </TR>
            </THead>
            <TBody>
              {data.map((n) => {
                const result = tests.results[n.name];
                return [
                  <TR key={n.name}>
                    <TD className="font-medium">{n.name}</TD>
                    <TD>
                      <span className="flex items-center gap-2">
                        <ChannelMark type={n.type} label={label(n.type)} />
                        {label(n.type)}
                      </span>
                    </TD>
                    <TD className="max-w-56 truncate text-muted-foreground">{n.target ?? "—"}</TD>
                    <TD className="text-muted-foreground">
                      {n.events.length ? n.events.map((e) => EVENTS.find((x) => x.id === e)?.label ?? e).join(", ") : "Rules only"}
                    </TD>
                    <TD>
                      <SourceBadge source={n.source} file="notifiers.json" />
                    </TD>
                    <TD>
                      <RowActions
                        name={n.name}
                        canWrite={canWrite}
                        canTest={canTest}
                        readOnly={n.source === "file"}
                        testing={result === "running"}
                        onTest={() => tests.run(n.name, () => api.testNotifier(n.name))}
                        onEdit={() => setEditing(n)}
                        onDelete={() => setDeleting(n)}
                      />
                    </TD>
                  </TR>,
                  result && result !== "running" && (
                    <tr key={`${n.name}-test`} className="border-b">
                      <td colSpan={6} className="px-6 pb-4 pt-0">
                        <TestOutcome result={result} onDismiss={() => tests.dismiss(n.name)} />
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
          title={editing && editing !== "new" ? `Edit ${editing.name}` : "Add channel"}
          description="Somewhere Farrier can send alerts."
          className="max-w-xl"
        >
          {editing && (
            <ChannelForm
              key={editing === "new" ? "new" : editing.name}
              entry={editing === "new" ? null : editing}
              taken={(data ?? []).map((n) => n.name)}
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
          await api.deleteNotifier(deleting.name);
          const refs = Object.values(deleting).filter((v): v is string => typeof v === "string");
          await dropOwnedSecrets(refs, `notifier-${deleting.name}`);
          toast.success(`Deleted ${deleting.name}`);
        }}
      >
        {usedBy.length ? (
          <p>
            Rule {usedBy.join(", ")} still sends here. Remove the channel from {usedBy.length > 1 ? "those rules" : "that rule"} first, or the delete is refused.
          </p>
        ) : (
          <p>Farrier stops sending here straight away. Its stored webhook or password is deleted too.</p>
        )}
      </ConfirmDelete>
    </>
  );
}

/* ------------------------------------------------------------------ rules */

function RuleForm({ entry, taken, onDone }: { entry: AlertRule | null; taken: string[]; onDone: () => void }) {
  const { data: channels } = useNotifiers();
  const { data: connectors } = useConnectors();
  const { data: catalog } = useCatalog();
  const types = catalog?.alert_rule_types?.length ? catalog.alert_rule_types : RULE_TYPES;
  const w = entry?.when;
  const [name, setName] = useState(entry?.name ?? "");
  const [type, setType] = useState<AlertWhen["type"]>(w?.type ?? "expiring");
  const [days, setDays] = useState(String(w && "days" in w ? w.days : 21));
  const [unreachableDays, setUnreachableDays] = useState(String(w?.type === "unreachable" ? w.days : 3));
  const [events, setEvents] = useState<string[]>(w?.type === "event" ? w.events : ["failed", "rolled_back"]);
  const [below, setBelow] = useState<HealthGrade>(w?.type === "health" ? w.below : "B");
  const [kinds, setKinds] = useState<string[]>(w?.type === "zombie" ? w.kinds ?? [] : []);
  const [tags, setTags] = useState<string[]>(entry?.filter?.tags ?? []);
  const [conns, setConns] = useState<string[]>(entry?.filter?.connectors ?? []);
  const [pattern, setPattern] = useState(entry?.filter?.name ?? "");
  const [picked, setPicked] = useState<string[]>(entry?.channels ?? (channels?.length === 1 ? [channels[0].name] : []));
  const [cooldown, setCooldown] = useState(String(entry?.cooldown_hours ?? 24));
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [busy, setBusy] = useState(false);
  const [serverError, setServerError] = useState<Error | null>(null);

  const whole = (v: string, min: number, max: number) => /^\d+$/.test(v) && Number(v) >= min && Number(v) <= max;

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setServerError(null);
    const errs: Record<string, string> = {};
    const nameErr = entry ? null : nameError(name, taken);
    if (nameErr) errs.name = nameErr;
    if (type === "expiring" && !whole(days, 1, 365)) errs.param = "Enter 1 to 365 days.";
    if (type === "unreachable" && !whole(unreachableDays, 1, 90)) errs.param = "Enter 1 to 90 days.";
    if (type === "event" && !events.length) errs.param = "Pick at least one event.";
    if (!picked.length) errs.channels = "Pick at least one channel.";
    if (!whole(cooldown, 0, 720)) errs.cooldown = "Enter 0 to 720 hours.";
    setErrors(errs);
    if (Object.keys(errs).length) return;

    const when: AlertWhen =
      type === "expiring"
        ? { type, days: Number(days) }
        : type === "unreachable"
          ? { type, days: Number(unreachableDays) }
          : type === "event"
            ? { type, events }
            : type === "health"
              ? { type, below }
              : kinds.length
                ? { type: "zombie", kinds }
                : { type: "zombie" };
    const filter = {
      ...(tags.length ? { tags } : {}),
      ...(conns.length ? { connectors: conns } : {}),
      ...(pattern.trim() ? { name: pattern.trim() } : {}),
    };
    setBusy(true);
    try {
      await api.saveAlertRule(name, {
        enabled: entry?.enabled ?? true,
        when,
        ...(Object.keys(filter).length ? { filter } : {}),
        channels: picked,
        cooldown_hours: Number(cooldown),
      });
      toast.success(entry ? `Saved ${name}` : `Added ${name}`, { description: describeWhen(when) });
      onDone();
    } catch (err) {
      setServerError(err as Error);
    } finally {
      setBusy(false);
    }
  }

  return (
    <form onSubmit={submit} className="space-y-6" noValidate>
      <Field id="rule-name" label="Name" error={errors.name} hint={entry ? "Names can't change; add a new rule instead." : undefined}>
        <Input
          id="rule-name"
          value={name}
          onChange={(e) => setName(e.target.value.trim())}
          disabled={!!entry}
          pattern={NAME_PATTERN}
          placeholder="expiring-21d"
          aria-invalid={!!errors.name}
          autoFocus={!entry}
        />
      </Field>

      <div className="space-y-4 rounded-lg border p-4">
        <p className="text-sm font-medium">When</p>
        <div className="grid gap-4 sm:grid-cols-2">
          <Field id="rule-type" label="Condition">
            <Select
              id="rule-type"
              value={type}
              onValueChange={(v) => {
                setType(v as AlertWhen["type"]);
                setErrors((x) => ({ ...x, param: "" }));
              }}
              options={types.map((t) => ({ value: t.id, label: t.label }))}
            />
          </Field>
          {type === "expiring" && (
            <Field id="rule-days" label="Days before expiry" error={errors.param}>
              <Input id="rule-days" type="number" min={1} max={365} value={days} onChange={(e) => setDays(e.target.value)} aria-invalid={!!errors.param} />
            </Field>
          )}
          {type === "unreachable" && (
            <Field id="rule-udays" label="Unreachable for (days)" error={errors.param}>
              <Input id="rule-udays" type="number" min={1} max={90} value={unreachableDays} onChange={(e) => setUnreachableDays(e.target.value)} aria-invalid={!!errors.param} />
            </Field>
          )}
          {type === "health" && (
            <Field id="rule-grade" label="Grade drops below">
              <Select
                id="rule-grade"
                value={below}
                onValueChange={(v) => setBelow(v as HealthGrade)}
                options={(["A", "B", "C", "D"] as const).map((g) => ({ value: g, label: g }))}
              />
            </Field>
          )}
        </div>
        {type === "event" && (
          <div className="space-y-2">
            <p className="text-sm font-medium">Events</p>
            <Toggles label="Events" options={EVENTS} value={events} onChange={setEvents} invalid={!!errors.param} />
            {errors.param && <p className="text-xs text-critical-fg">{errors.param}</p>}
          </div>
        )}
        {type === "zombie" && (
          <div className="space-y-2">
            <p className="text-sm font-medium">
              Kinds <span className="text-xs font-normal text-muted-foreground">Optional; none means all</span>
            </p>
            <Toggles label="Zombie kinds" options={Object.entries(ZOMBIE_KINDS).map(([id, label]) => ({ id, label }))} value={kinds} onChange={setKinds} />
          </div>
        )}
        <p className="text-sm text-muted-foreground">
          Reads as: <span className="font-medium text-foreground">{describeWhen(
            type === "expiring" ? { type, days: Number(days) || 0 }
              : type === "unreachable" ? { type, days: Number(unreachableDays) || 0 }
              : type === "event" ? { type, events }
              : type === "health" ? { type, below }
              : { type: "zombie", kinds },
          )}</span>
        </p>
      </div>

      <details className="group rounded-lg border" open={!!entry?.filter}>
        <summary className="flex cursor-pointer list-none items-center gap-2 px-4 py-2 text-sm font-medium">
          <ChevronRight className="size-4 text-muted-foreground transition-transform group-open:rotate-90" />
          Only some endpoints
          {(tags.length > 0 || conns.length > 0 || pattern) && <Badge tone="neutral">Filtered</Badge>}
        </summary>
        <div className="space-y-4 border-t p-4">
          <Field id="rule-tags" label="Tags" optional hint="Endpoints with any of these tags.">
            <ChipsInput id="rule-tags" value={tags} onChange={setTags} placeholder="prod" />
          </Field>
          <div className="space-y-2">
            <p className="text-sm font-medium">
              Connectors <span className="text-xs font-normal text-muted-foreground">Optional</span>
            </p>
            <Toggles
              label="Connectors"
              options={(connectors ?? []).map((c) => ({ id: c.kind, label: CONNECTOR_LABEL[c.kind] ?? c.kind }))}
              value={conns}
              onChange={setConns}
            />
          </div>
          <Field id="rule-pattern" label="Name pattern" optional hint="A glob over endpoint names, like vpn-* or *-prod.">
            <Input id="rule-pattern" value={pattern} onChange={(e) => setPattern(e.target.value)} placeholder="vpn-*" className="font-mono" />
          </Field>
        </div>
      </details>

      <div className="space-y-2">
        <p className="text-sm font-medium">Send to</p>
        <Toggles
          label="Channels"
          options={(channels ?? []).map((c) => ({ id: c.name, label: c.name }))}
          value={picked}
          onChange={setPicked}
          invalid={!!errors.channels}
        />
        {errors.channels && <p className="text-xs text-critical-fg">{errors.channels}</p>}
      </div>

      <Field id="rule-cooldown" label="Cooldown" error={errors.cooldown} hint="Hours before the same certificate alerts again. 0 sends every time.">
        <div className="flex items-center gap-2">
          <Input id="rule-cooldown" type="number" min={0} max={720} value={cooldown} onChange={(e) => setCooldown(e.target.value)} className="w-28" aria-invalid={!!errors.cooldown} />
          <span className="text-sm text-muted-foreground">hours</span>
        </div>
      </Field>

      <ErrorNotice error={serverError} />
      <FormActions busy={busy} label={entry ? "Save changes" : "Add rule"} busyLabel="Saving…" />
    </form>
  );
}

function RulesPanel({ canWrite, canTest, toChannels }: { canWrite: boolean; canTest: boolean; toChannels: () => void }) {
  const { data, error, isLoading } = useAlertRules();
  const { data: channels, isLoading: channelsLoading } = useNotifiers();
  const [editing, setEditing] = useState<AlertRule | "new" | null>(null);
  const [deleting, setDeleting] = useState<AlertRule | null>(null);
  const [toggling, setToggling] = useState<string | null>(null);
  const tests = useTests();
  const noChannels = !channelsLoading && channels !== undefined && channels.length === 0;
  const add = (
    <Button onClick={() => setEditing("new")}>
      <Plus /> Add rule
    </Button>
  );

  const toggle = async (r: AlertRule, enabled: boolean) => {
    setToggling(r.name);
    try {
      await api.saveAlertRule(r.name, toInput(r, { enabled }));
      toast.success(enabled ? `${r.name} is on` : `${r.name} is paused`);
    } catch (e) {
      toast.error(`Couldn't update ${r.name}`, { description: (e as Error).message });
    } finally {
      setToggling(null);
    }
  };

  return (
    <>
      <ErrorNotice error={error} />
      <Card className="overflow-hidden">
        {canWrite && !!data?.length && !noChannels && <div className="flex justify-end border-b px-6 py-4">{add}</div>}
        {isLoading || channelsLoading ? (
          <TableSkeleton rows={3} />
        ) : noChannels && !data?.length ? (
          <EmptyState
            icon={<Send />}
            title="Add a channel first"
            action={
              <Button onClick={toChannels} variant={canWrite ? "primary" : "secondary"}>
                Go to channels
              </Button>
            }
          >
            Rules send alerts to channels. Add Slack, Teams, a webhook or email, then come back to choose what to alert on.
          </EmptyState>
        ) : !data?.length ? (
          <EmptyState icon={<BellRing />} title="No alert rules" action={canWrite ? add : undefined}>
            Say when Farrier should speak up, like a certificate expiring within 21 days or a renewal that fails.
          </EmptyState>
        ) : (
          <Table>
            <THead>
              <TR>
                <TH>Name</TH>
                <TH>Condition</TH>
                <TH>Channels</TH>
                <TH>On</TH>
                <TH>Last fired</TH>
                <TH className="text-right">
                  <span className="sr-only">Actions</span>
                </TH>
              </TR>
            </THead>
            <TBody>
              {data.map((r) => {
                const result = tests.results[r.name];
                const filter = describeFilter(r.filter);
                return [
                  <TR key={r.name} className={cn(!r.enabled && "text-muted-foreground")}>
                    <TD className="font-medium">{r.name}</TD>
                    <TD className="whitespace-normal">
                      <p className={cn(r.enabled && "text-foreground")}>{describeWhen(r.when)}</p>
                      {filter && <p className="text-xs text-muted-foreground">{filter}</p>}
                    </TD>
                    <TD className="text-muted-foreground">{r.channels.join(", ")}</TD>
                    <TD>
                      <Switch
                        checked={r.enabled}
                        disabled={!canWrite || toggling === r.name}
                        onChange={(v) => toggle(r, v)}
                        label={`${r.enabled ? "Pause" : "Turn on"} ${r.name}`}
                      />
                    </TD>
                    <TD className="text-muted-foreground" title={r.last_fired_at ?? undefined}>
                      {r.last_fired_at ? relativeTime(r.last_fired_at) : "Never"}
                    </TD>
                    <TD>
                      <RowActions
                        name={r.name}
                        canWrite={canWrite}
                        canTest={canTest}
                        readOnly={false}
                        testing={result === "running"}
                        onTest={() =>
                          tests.run(r.name, async () => {
                            const out = await api.testAlertRule(r.name);
                            return {
                              ok: out.ok,
                              detail: out.ok ? `Sent a test alert to ${out.sent} channel${out.sent === 1 ? "" : "s"}.` : "Nothing was sent.",
                            };
                          })
                        }
                        onEdit={() => setEditing(r)}
                        onDelete={() => setDeleting(r)}
                      />
                    </TD>
                  </TR>,
                  result && result !== "running" && (
                    <tr key={`${r.name}-test`} className="border-b">
                      <td colSpan={6} className="px-6 pb-4 pt-0">
                        <TestOutcome result={result} onDismiss={() => tests.dismiss(r.name)} />
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
          title={editing && editing !== "new" ? `Edit ${editing.name}` : "Add alert rule"}
          description="A condition, an optional filter and where to send it."
          className="max-w-xl"
        >
          {editing && (
            <RuleForm
              key={editing === "new" ? "new" : editing.name}
              entry={editing === "new" ? null : editing}
              taken={(data ?? []).map((r) => r.name)}
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
          await api.deleteAlertRule(deleting.name);
          toast.success(`Deleted ${deleting.name}`);
        }}
      >
        <p>
          {deleting ? describeWhen(deleting.when) : ""} will no longer alert. To stop it for a while instead, switch it off.
        </p>
      </ConfirmDelete>
    </>
  );
}

/* ------------------------------------------------------------------ page */

type Tab = "rules" | "channels";

export function AlertsView() {
  const params = useSearchParams();
  const router = useRouter();
  const path = usePathname();
  const tab: Tab = params.get("tab") === "channels" ? "channels" : "rules";
  const setTab = (t: Tab) => router.replace(t === "rules" ? path : `${path}?tab=${t}`, { scroll: false });
  const { data: rules } = useAlertRules();
  const { data: channels } = useNotifiers();
  const { can } = useAccess();
  const canWrite = can("PUT", "alert-rules/x");

  return (
    <>
      <PageHeader
        title="Alerts"
        description={`Rules decide when Farrier speaks up; channels are where it says it.${canWrite ? "" : " Only admins can change these."}`}
      />
      <Segmented
        label="Alerts section"
        value={tab}
        onChange={setTab}
        className="mb-6"
        options={[
          { value: "rules", label: "Rules", count: rules?.length },
          { value: "channels", label: "Channels", count: channels?.length },
        ]}
      />
      {tab === "rules" ? (
        <RulesPanel canWrite={canWrite} canTest={can("POST", "alert-rules/x/test")} toChannels={() => setTab("channels")} />
      ) : (
        <ChannelsPanel canWrite={can("PUT", "notifiers/x")} canTest={can("POST", "notifiers/x/test")} />
      )}
    </>
  );
}
