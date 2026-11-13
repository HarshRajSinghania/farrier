"use client";

import Link from "next/link";
import { useState } from "react";
import { ChevronRight, Plus, ShieldCheck } from "lucide-react";
import { toast } from "sonner";
import { ErrorNotice, PageHeader } from "@/components/dashboard/shell";
import { TableSkeleton } from "@/components/dashboard/widgets";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Dialog, DialogContent } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Select } from "@/components/ui/select";
import { EmptyState } from "@/components/ui/misc";
import { Table, TBody, TD, TH, THead, TR } from "@/components/ui/table";
import { api, useCatalog, useDnsAccounts, useIssuers } from "@/lib/api";
import { useAccess } from "@/lib/auth/client";
import type { CaPreset, Issuer, IssuerInput } from "@/lib/types";
import { cn } from "@/lib/utils";
import {
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

const CA_LOGO: Record<string, string> = {
  letsencrypt: "/assets/icons/letsencrypt.svg",
  zerossl: "/assets/icons/ca-zerossl.png",
  google: "/assets/icons/google-cloud.svg",
  buypass: "/assets/icons/ca-buypass.png",
  sslcom: "/assets/icons/ca-ssl.png",
  digicert: "/assets/icons/ca-digicert.png",
  sectigo: "/assets/icons/ca-sectigo.png",
  "aws-acm": "/assets/icons/cert.svg",
  local_ca: "/assets/icons/cert.svg",
};

const PROFILES = [
  { id: "", label: "CA default" },
  { id: "classic", label: "classic · 90 days, server and client auth" },
  { id: "tlsserver", label: "tlsserver · 90 days, server auth only" },
  { id: "shortlived", label: "shortlived · about 6 days" },
];

const CUSTOM = "custom";
const isStaging = (p: CaPreset) => p.staging === true || p.id.endsWith("-staging");
const baseOf = (id: string) => id.replace(/-staging$/, "");
const hostOf = (url: string | null) => {
  if (!url) return null;
  try {
    return new URL(url).host;
  } catch {
    return url;
  }
};

function presetLabel(i: Issuer, presets: CaPreset[]) {
  if (i.type === "local_ca" && !i.preset) return "Built-in private CA";
  const p = presets.find((x) => x.id === i.preset);
  if (p) return p.label.replace(/\s*\(staging\)$/i, "");
  return i.preset ?? "Custom ACME";
}

/* ------------------------------------------------------------------ form */

function IssuerForm({ entry, taken, onDone }: { entry: Issuer | null; taken: string[]; onDone: () => void }) {
  const { data: catalog } = useCatalog();
  const { data: dnsAccounts } = useDnsAccounts();
  const presets = catalog?.ca_presets ?? [];
  const choices = presets.filter((p) => !isStaging(p));

  const initialBase = entry
    ? entry.preset
      ? baseOf(entry.preset)
      : entry.type === "local_ca"
        ? "local_ca"
        : CUSTOM
    : "letsencrypt";
  const [name, setName] = useState(entry?.name ?? "");
  const [base, setBase] = useState(initialBase);
  const [staging, setStaging] = useState(!!entry?.preset && entry.preset.endsWith("-staging"));
  const [email, setEmail] = useState(entry?.email ?? "");
  const [dns, setDns] = useState(entry?.dns ?? "auto");
  const [profile, setProfile] = useState(entry?.profile ?? "");
  const [chain, setChain] = useState(entry?.preferred_chain ?? "");
  const [directory, setDirectory] = useState(entry?.directory_url ?? "");
  const [eabKid, setEabKid] = useState(entry?.eab_kid ?? "");
  const [hmac, setHmac] = useState<SecretState>(secretState(entry?.eab_hmac_key));
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [busy, setBusy] = useState(false);
  const [serverError, setServerError] = useState<Error | null>(null);

  const stagingId = `${base}-staging`;
  const hasStaging = presets.some((p) => p.id === stagingId);
  const presetId = base === CUSTOM ? null : staging && hasStaging ? stagingId : base;
  const preset = presets.find((p) => p.id === presetId);
  const local = base === "local_ca";
  const custom = base === CUSTOM;
  const needsEab = !!preset?.eab;
  const showEab = needsEab || custom;
  const needsDirectory = custom || !!preset?.needs_directory_url;
  const prevalidated = base === "aws-acm"; // ACM validates domains on the endpoint: no DNS-01

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setServerError(null);
    const errs: Record<string, string> = {};
    const nameErr = entry ? null : nameError(name, taken);
    if (nameErr) errs.name = nameErr;
    if (!local) {
      if (email && !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) errs.email = "Enter a valid email address.";
      if (needsDirectory && !/^https:\/\/\S+$/.test(directory.trim())) errs.directory = "Enter the https:// ACME directory URL from your CA.";
      if (needsEab && !eabKid.trim()) errs.eab_kid = "Required by this CA.";
    }
    const secrets = local || !showEab ? null : planSecrets([{ key: "eab_hmac_key", required: needsEab }], { eab_hmac_key: hmac }, `issuer-${name}`);
    if (secrets) Object.assign(errs, secrets.errors);
    setErrors(errs);
    if (Object.keys(errs).length) return;

    const body: IssuerInput = custom ? { type: "acme" } : { preset: presetId! };
    if (!local) {
      Object.assign(body, {
        email: email.trim() || undefined,
        dns: prevalidated ? undefined : dns,
        profile: base === "letsencrypt" ? profile || undefined : undefined,
        preferred_chain: chain.trim() || undefined,
        directory_url: needsDirectory ? directory.trim() : undefined,
        eab_kid: showEab ? eabKid.trim() || undefined : undefined,
        eab_hmac_key: secrets?.refs.eab_hmac_key ?? undefined,
      });
    }
    setBusy(true);
    try {
      if (secrets) await storeSecrets(secrets.puts);
      await api.saveIssuer(name, body);
      toast.success(entry ? `Saved ${name}` : `Added ${name}`, {
        description: "Endpoints use it by setting their issuer to this name.",
      });
      onDone();
    } catch (err) {
      setServerError(err as Error);
    } finally {
      setBusy(false);
    }
  }

  return (
    <form onSubmit={submit} className="space-y-6" noValidate>
      <Field id="issuer-name" label="Name" error={errors.name} hint={entry ? "Names can't change; add a new authority instead." : "Endpoints refer to it by this name."}>
        <Input
          id="issuer-name"
          value={name}
          onChange={(e) => setName(e.target.value.trim())}
          disabled={!!entry}
          pattern={NAME_PATTERN}
          placeholder="letsencrypt"
          aria-invalid={!!errors.name}
          autoFocus={!entry}
        />
      </Field>

      <fieldset className="space-y-2">
        <legend className="mb-2 text-sm font-medium">Certificate authority</legend>
        <div role="radiogroup" aria-label="Certificate authority" className="grid gap-2 sm:grid-cols-2">
          {[...choices.map((p) => ({ id: p.id, label: p.label })), { id: CUSTOM, label: "Other ACME CA" }].map((c) => {
            const on = base === c.id;
            return (
              <button
                key={c.id}
                type="button"
                role="radio"
                aria-checked={on}
                onClick={() => setBase(c.id)}
                className={cn(
                  "flex items-center gap-2 rounded-lg border px-2 py-2 text-left text-sm transition-colors hover:bg-muted",
                  on && "border-foreground bg-muted",
                )}
              >
                <LogoTile src={CA_LOGO[c.id]} label={c.label} />
                <span className="min-w-0 flex-1 truncate font-medium">{c.label}</span>
                {c.id === "letsencrypt" && <Badge tone="brand">Recommended</Badge>}
              </button>
            );
          })}
        </div>
        {hasStaging && (
          <label className="mt-2 flex items-start gap-4 rounded-lg border px-4 py-2 text-sm">
            <input type="checkbox" checked={staging} onChange={(e) => setStaging(e.target.checked)} className="mt-1 size-4 accent-[#141414]" />
            <span>
              <span className="block font-medium">Use the staging directory</span>
              <span className="block text-xs text-muted-foreground">Untrusted test certificates with generous rate limits. Try a setup here first.</span>
            </span>
          </label>
        )}
      </fieldset>

      {local ? (
        <p className="rounded-lg bg-muted px-4 py-2 text-sm text-muted-foreground">
          Farrier signs certificates with its own private CA. Clients must trust its root, so use it for internal names only.
        </p>
      ) : (
        <>
          {needsDirectory && (
            <Field id="issuer-dir" label="ACME directory URL" error={errors.directory} hint={prevalidated ? "The endpoint's URL: farrier acm endpoint show <arn>. Key ID and HMAC: farrier acm eab credentials <arn>." : "From your CA's ACME settings page."}>
              <Input
                id="issuer-dir"
                value={directory}
                onChange={(e) => setDirectory(e.target.value)}
                placeholder="https://acme.example.com/directory"
                aria-invalid={!!errors.directory}
                className="font-mono"
              />
            </Field>
          )}

          <div className="grid gap-4 sm:grid-cols-2">
            <Field id="issuer-email" label="Account email" optional error={errors.email} hint="The CA's contact for this account.">
              <Input id="issuer-email" type="email" value={email} onChange={(e) => setEmail(e.target.value)} placeholder="pki@example.com" aria-invalid={!!errors.email} />
            </Field>
            {!prevalidated && <Field
              id="issuer-dns"
              label="DNS for validation"
              hint={
                <>
                  Automatic picks the account whose zone matches each name.{" "}
                  <Link href="/dashboard/integrations/dns" className="font-medium text-foreground underline-offset-4 hover:underline">
                    DNS accounts
                  </Link>
                </>
              }
            >
              <Select
                id="issuer-dns"
                value={dns}
                onValueChange={setDns}
                options={[
                  { value: "auto", label: "Automatic", description: "The account whose zone matches each name" },
                  ...(dnsAccounts ?? []).map((a) => ({ value: a.name, label: a.name, description: a.provider })),
                ]}
              />
            </Field>}
          </div>

          {showEab && (
            <div className="space-y-4 rounded-lg border p-4">
              <div>
                <p className="text-sm font-medium">External account binding</p>
                <p className="text-xs text-muted-foreground">
                  {needsEab ? "This CA links ACME to your paid account with an EAB key pair." : "Only if your CA asks for one."}
                </p>
              </div>
              <Field id="issuer-eab-kid" label="Key ID" optional={!needsEab} error={errors.eab_kid}>
                <Input id="issuer-eab-kid" value={eabKid} onChange={(e) => setEabKid(e.target.value)} spellCheck={false} className="font-mono" aria-invalid={!!errors.eab_kid} />
              </Field>
              <SecretInput id="issuer-eab-hmac" label="HMAC key" required={needsEab} state={hmac} onChange={setHmac} error={errors.eab_hmac_key} />
            </div>
          )}

          <details className="group rounded-lg border" open={!!(entry?.profile || entry?.preferred_chain)}>
            <summary className="flex cursor-pointer list-none items-center gap-2 px-4 py-2 text-sm font-medium">
              <ChevronRight className="size-4 text-muted-foreground transition-transform group-open:rotate-90" />
              Profile and chain
            </summary>
            <div className="grid gap-4 border-t p-4 sm:grid-cols-2">
              {base === "letsencrypt" && (
                <Field id="issuer-profile" label="Profile" hint="Shortlived suits automated endpoints only.">
                  <Select
                    id="issuer-profile"
                    // Radix reserves "" for "no value"; the CA-default profile is "" in the form state
                    value={profile || "default"}
                    onValueChange={(v) => setProfile(v === "default" ? "" : v)}
                    options={PROFILES.map((p) => ({ value: p.id || "default", label: p.label }))}
                  />
                </Field>
              )}
              <Field id="issuer-chain" label="Preferred chain" optional hint="The root's common name, when the CA offers alternates.">
                <Input id="issuer-chain" value={chain} onChange={(e) => setChain(e.target.value)} placeholder="ISRG Root X1" />
              </Field>
            </div>
          </details>
        </>
      )}

      <ErrorNotice error={serverError} />
      <FormActions busy={busy} label={entry ? "Save changes" : "Add authority"} busyLabel="Saving…" />
    </form>
  );
}

/* ------------------------------------------------------------------ page */

export function AuthoritiesView() {
  const { data, error, isLoading } = useIssuers();
  const { data: catalog } = useCatalog();
  const { can } = useAccess();
  const canWrite = can("PUT", "issuers/x");
  const canTest = can("POST", "issuers/x/test");
  const [editing, setEditing] = useState<Issuer | "new" | null>(null);
  const [deleting, setDeleting] = useState<Issuer | null>(null);
  const tests = useTests();
  const presets = catalog?.ca_presets ?? [];
  const add = (
    <Button onClick={() => setEditing("new")}>
      <Plus /> Add authority
    </Button>
  );

  return (
    <>
      <PageHeader
        title="Certificate authorities"
        description={`Where certificates come from. Endpoints pick one by name.${canWrite ? "" : " Only admins can change these."}`}
        actions={canWrite && data?.length ? add : undefined}
      />
      <ErrorNotice error={error} />
      <Card className="overflow-hidden">
        {isLoading ? (
          <TableSkeleton rows={3} />
        ) : !data?.length ? (
          <EmptyState icon={<ShieldCheck />} title="No certificate authorities" action={canWrite ? add : undefined}>
            Add Let&apos;s Encrypt or your commercial CA so Farrier can issue renewals.
          </EmptyState>
        ) : (
          <Table>
            <THead>
              <TR>
                <TH>Name</TH>
                <TH>Authority</TH>
                <TH>Directory</TH>
                <TH>DNS</TH>
                <TH>Profile</TH>
                <TH>Source</TH>
                <TH className="text-right">
                  <span className="sr-only">Actions</span>
                </TH>
              </TR>
            </THead>
            <TBody>
              {data.map((i) => {
                const result = tests.results[i.name];
                const label = presetLabel(i, presets);
                return [
                  <TR key={i.name}>
                    <TD className="font-medium">{i.name}</TD>
                    <TD>
                      <span className="flex items-center gap-2">
                        <LogoTile src={CA_LOGO[baseOf(i.preset ?? i.type)]} label={label} className="size-6" />
                        {label}
                        {i.preset?.endsWith("-staging") && <Badge tone="warning">Staging</Badge>}
                      </span>
                    </TD>
                    <TD className="font-mono text-xs text-muted-foreground">{i.type === "local_ca" ? "—" : hostOf(i.directory_url) ?? "—"}</TD>
                    <TD className="text-muted-foreground">{i.type === "local_ca" ? "—" : !i.dns || i.dns === "auto" ? "Automatic" : i.dns}</TD>
                    <TD className="text-muted-foreground">{i.profile ?? "—"}</TD>
                    <TD>
                      <SourceBadge source={i.source} file="issuers.json" />
                    </TD>
                    <TD>
                      <RowActions
                        name={i.name}
                        canWrite={canWrite}
                        canTest={canTest}
                        readOnly={i.source === "file"}
                        testing={result === "running"}
                        onTest={() => tests.run(i.name, () => api.testIssuer(i.name))}
                        onEdit={() => setEditing(i)}
                        onDelete={() => setDeleting(i)}
                      />
                    </TD>
                  </TR>,
                  result && result !== "running" && (
                    <tr key={`${i.name}-test`} className="border-b">
                      <td colSpan={7} className="px-6 pb-4 pt-0">
                        <TestOutcome result={result} onDismiss={() => tests.dismiss(i.name)} />
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
          title={editing && editing !== "new" ? `Edit ${editing.name}` : "Add certificate authority"}
          description="An ACME CA or Farrier's built-in private CA."
          className="max-w-xl"
        >
          {editing && (
            <IssuerForm
              key={editing === "new" ? "new" : editing.name}
              entry={editing === "new" ? null : editing}
              taken={(data ?? []).map((i) => i.name)}
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
          await api.deleteIssuer(deleting.name);
          await dropOwnedSecrets([deleting.eab_hmac_key], `issuer-${deleting.name}`);
          toast.success(`Deleted ${deleting.name}`);
        }}
      >
        <p>Endpoints that use this authority can no longer renew. Farrier refuses while any endpoint still names it.</p>
      </ConfirmDelete>
    </>
  );
}
