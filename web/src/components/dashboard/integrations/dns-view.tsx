"use client";

import { useMemo, useState } from "react";
import { Globe, Plus, Search } from "lucide-react";
import { toast } from "sonner";
import { ErrorNotice, PageHeader } from "@/components/dashboard/shell";
import { TableSkeleton } from "@/components/dashboard/widgets";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Dialog, DialogContent } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { EmptyState } from "@/components/ui/misc";
import { Table, TBody, TD, TH, THead, TR } from "@/components/ui/table";
import { api, useCatalog, useDnsAccounts } from "@/lib/api";
import { useAccess } from "@/lib/auth/client";
import type { DnsAccount, DnsProviderInfo } from "@/lib/types";
import { cn } from "@/lib/utils";
import {
  ChipsInput,
  ConfirmDelete,
  dropOwnedSecrets,
  Field,
  FormActions,
  LogoTile,
  NAME_PATTERN,
  nameError,
  planSecrets,
  RowActions,
  SecretInput,
  secretState,
  SourceBadge,
  storeSecrets,
  TestOutcome,
  useTests,
  type SecretState,
} from "./common";

// marks shipped in public/assets/icons/dns-<name>.svg, with the engine ids that differ
const LOGOS = new Set([
  "akamai", "amazonroute53", "cloudflare", "digitalocean", "godaddy", "google", "hetzner",
  "infomaniak", "namecheap", "ovh", "porkbun", "scaleway", "vultr",
]);
const ALIAS: Record<string, string> = {
  route53: "amazonroute53",
  gcloud: "google",
  googlecloud: "google",
  edgedns: "akamai",
  linode: "akamai",
};
export function dnsLogo(provider: string): string | null {
  const id = ALIAS[provider] ?? provider;
  return LOGOS.has(id) ? `/assets/icons/dns-${id}.svg` : null;
}

const ZONE = /^([a-z0-9-]+\.)+[a-z]{2,}$/i;
const zoneError = (z: string) => (ZONE.test(z) ? null : `${z} isn't a DNS zone (like example.com).`);

function Zones({ zones }: { zones: string[] }) {
  if (!zones.length) return <span className="text-muted-foreground">Any zone</span>;
  return (
    <span className="flex flex-wrap gap-1">
      {zones.map((z) => (
        <span key={z} className="rounded-full bg-muted px-2 text-xs leading-6">
          {z}
        </span>
      ))}
    </span>
  );
}

/* ------------------------------------------------------- provider picker */

function ProviderPicker({ providers, value, onChange }: { providers: DnsProviderInfo[]; value: string; onChange: (id: string) => void }) {
  const [q, setQ] = useState("");
  const shown = providers.filter((p) => `${p.label} ${p.id}`.toLowerCase().includes(q.trim().toLowerCase()));
  return (
    <div className="rounded-lg border">
      <div className="relative border-b">
        <Search className="pointer-events-none absolute left-4 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" aria-hidden />
        <input
          aria-label="Search DNS providers"
          value={q}
          onChange={(e) => setQ(e.target.value)}
          placeholder={`Search ${providers.length} providers`}
          className="h-9 w-full rounded-t-lg bg-transparent pl-10 pr-4 text-sm outline-none placeholder:text-muted-foreground/70"
        />
      </div>
      <div role="radiogroup" aria-label="DNS provider" className="grid max-h-56 gap-1 overflow-y-auto p-1 sm:grid-cols-2">
        {shown.map((p) => {
          const on = p.id === value;
          return (
            <button
              key={p.id}
              type="button"
              role="radio"
              aria-checked={on}
              onClick={() => onChange(p.id)}
              className={cn(
                "flex items-center gap-2 rounded-md px-2 py-1 text-left text-sm hover:bg-muted",
                on && "bg-muted font-medium ring-1 ring-foreground",
              )}
            >
              <LogoTile src={dnsLogo(p.id)} label={p.label} className="size-6" />
              <span className="truncate">{p.label}</span>
            </button>
          );
        })}
        {!shown.length && <p className="col-span-full px-2 py-4 text-center text-sm text-muted-foreground">No provider matches “{q}”.</p>}
      </div>
    </div>
  );
}

/* ------------------------------------------------------------------ form */

function DnsForm({ entry, taken, onDone }: { entry: DnsAccount | null; taken: string[]; onDone: () => void }) {
  const { data: catalog } = useCatalog();
  const providers = useMemo(() => [...(catalog?.dns_providers ?? [])].sort((a, b) => a.label.localeCompare(b.label)), [catalog]);
  const [name, setName] = useState(entry?.name ?? "");
  const [providerId, setProviderId] = useState(entry?.provider ?? "cloudflare");
  const [values, setValues] = useState<Record<string, string>>(entry?.options ?? {});
  const [secrets, setSecrets] = useState<Record<string, SecretState>>(() =>
    Object.fromEntries(Object.entries(entry?.credentials ?? {}).map(([k, v]) => [k, secretState(v)])),
  );
  const [zones, setZones] = useState<string[]>(entry?.zones ?? []);
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [busy, setBusy] = useState(false);
  const [serverError, setServerError] = useState<Error | null>(null);
  const provider = providers.find((p) => p.id === providerId);

  const pick = (id: string) => {
    setProviderId(id);
    setValues({});
    setSecrets({});
    setErrors({});
  };

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setServerError(null);
    if (!provider) return;
    const errs: Record<string, string> = {};
    const nameErr = entry ? null : nameError(name, taken);
    if (nameErr) errs.name = nameErr;
    for (const f of provider.fields) if (!f.secret && f.required && !values[f.key]?.trim()) errs[f.key] = "Required.";
    const plan = planSecrets(provider.fields.filter((f) => f.secret), secrets, `dns-${name}`);
    Object.assign(errs, plan.errors);
    setErrors(errs);
    if (Object.keys(errs).length) return;

    const credentials = Object.fromEntries(Object.entries(plan.refs).filter((kv): kv is [string, string] => !!kv[1]));
    const options = Object.fromEntries(
      provider.fields.filter((f) => !f.secret && values[f.key]?.trim()).map((f) => [f.key, values[f.key].trim()]),
    );
    setBusy(true);
    try {
      await storeSecrets(plan.puts);
      await api.saveDnsAccount(name, { provider: provider.id, credentials, options, zones });
      toast.success(entry ? `Saved ${name}` : `Added ${name}`, { description: "Test it to see the zones it can reach." });
      onDone();
    } catch (err) {
      setServerError(err as Error);
    } finally {
      setBusy(false);
    }
  }

  return (
    <form onSubmit={submit} className="space-y-6" noValidate>
      <Field id="dns-name" label="Name" error={errors.name} hint={entry ? "Names can't change; add a new account instead." : "Issuers can pick it by this name."}>
        <Input
          id="dns-name"
          value={name}
          onChange={(e) => setName(e.target.value.trim())}
          disabled={!!entry}
          pattern={NAME_PATTERN}
          placeholder="cf-prod"
          aria-invalid={!!errors.name}
          autoFocus={!entry}
        />
      </Field>

      <fieldset className="space-y-2">
        <legend className="mb-2 text-sm font-medium">Provider</legend>
        {entry ? (
          <div className="flex items-center gap-2 text-sm">
            <LogoTile src={dnsLogo(providerId)} label={provider?.label ?? providerId} />
            <span className="font-medium">{provider?.label ?? providerId}</span>
          </div>
        ) : (
          <ProviderPicker providers={providers} value={providerId} onChange={pick} />
        )}
      </fieldset>

      {provider && provider.fields.length > 0 && (
        <div className="space-y-4">
          {provider.fields.map((f) =>
            f.secret ? (
              <SecretInput
                key={`${provider.id}-${f.key}`}
                id={`dns-${f.key}`}
                label={f.label}
                required={f.required}
                help={f.help}
                state={secrets[f.key] ?? secretState()}
                onChange={(s) => setSecrets((x) => ({ ...x, [f.key]: s }))}
                error={errors[f.key]}
              />
            ) : (
              <Field key={`${provider.id}-${f.key}`} id={`dns-${f.key}`} label={f.label} optional={!f.required} hint={f.help} error={errors[f.key]}>
                <Input
                  id={`dns-${f.key}`}
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

      <Field id="dns-zones" label="Zones" optional hint="Names under these zones use this account; the most specific zone wins. Press Enter after each.">
        <ChipsInput id="dns-zones" value={zones} onChange={setZones} placeholder="example.com" validate={zoneError} />
      </Field>

      <ErrorNotice error={serverError} />
      <FormActions busy={busy} label={entry ? "Save changes" : "Add DNS account"} busyLabel="Saving…" />
    </form>
  );
}

/* ------------------------------------------------------------------ page */

export function DnsView() {
  const { data, error, isLoading } = useDnsAccounts();
  const { data: catalog } = useCatalog();
  const { can } = useAccess();
  const canWrite = can("PUT", "dns-accounts/x");
  const canTest = can("POST", "dns-accounts/x/test");
  const [editing, setEditing] = useState<DnsAccount | "new" | null>(null);
  const [deleting, setDeleting] = useState<DnsAccount | null>(null);
  const tests = useTests();
  const label = (id: string) => catalog?.dns_providers.find((p) => p.id === id)?.label ?? id;
  const add = (
    <Button onClick={() => setEditing("new")}>
      <Plus /> Add DNS account
    </Button>
  );

  return (
    <>
      <PageHeader
        title="DNS accounts"
        description={`Farrier writes a TXT record here to prove it controls a name (DNS-01).${canWrite ? "" : " Only admins can change these."}`}
        actions={canWrite && data?.length ? add : undefined}
      />
      <ErrorNotice error={error} />
      <Card className="overflow-hidden">
        {isLoading ? (
          <TableSkeleton rows={3} />
        ) : !data?.length ? (
          <EmptyState icon={<Globe />} title="No DNS accounts" action={canWrite ? add : undefined}>
            Connect the DNS provider for your zones so public CAs can validate names behind firewalls.
          </EmptyState>
        ) : (
          <Table>
            <THead>
              <TR>
                <TH>Name</TH>
                <TH>Provider</TH>
                <TH>Zones</TH>
                <TH>Source</TH>
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
                      <span className="flex items-center gap-2">
                        <LogoTile src={dnsLogo(a.provider)} label={label(a.provider)} className="size-6" />
                        {label(a.provider)}
                      </span>
                    </TD>
                    <TD className="whitespace-normal">
                      <Zones zones={a.zones} />
                    </TD>
                    <TD>
                      <SourceBadge source={a.source} file="dns.json" />
                    </TD>
                    <TD>
                      <RowActions
                        name={a.name}
                        canWrite={canWrite}
                        canTest={canTest}
                        readOnly={a.source === "file"}
                        testing={result === "running"}
                        onTest={() => tests.run(a.name, () => api.testDnsAccount(a.name))}
                        onEdit={() => setEditing(a)}
                        onDelete={() => setDeleting(a)}
                      />
                    </TD>
                  </TR>,
                  result && result !== "running" && (
                    <tr key={`${a.name}-test`} className="border-b">
                      <td colSpan={5} className="px-6 pb-4 pt-0">
                        <TestOutcome result={result} onDismiss={() => tests.dismiss(a.name)}>
                          {result.zones && result.zones.length > 0 && (
                            <div className="mt-2 flex flex-wrap items-center gap-1 text-foreground">
                              <span className="text-xs text-muted-foreground">Zones found:</span>
                              <Zones zones={result.zones} />
                            </div>
                          )}
                        </TestOutcome>
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
          title={editing && editing !== "new" ? `Edit ${editing.name}` : "Add DNS account"}
          description="Credentials for a DNS provider that hosts your zones."
          className="max-w-xl"
        >
          {editing && (
            <DnsForm
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
          await api.deleteDnsAccount(deleting.name);
          await dropOwnedSecrets(Object.values(deleting.credentials), `dns-${deleting.name}`);
          toast.success(`Deleted ${deleting.name}`);
        }}
      >
        <p>Renewals for names in {deleting?.zones.join(", ") || "its zones"} will fall back to another account, or fail validation if none matches. Its stored credentials are deleted too.</p>
      </ConfirmDelete>
    </>
  );
}
