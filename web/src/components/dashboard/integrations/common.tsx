"use client";

import { useState } from "react";
import { CheckCircle2, FileLock2, KeyRound, Loader2, MoreHorizontal, Pencil, PlugZap, Trash2, X, XCircle } from "lucide-react";
import { toast } from "sonner";
import { ErrorNotice } from "@/components/dashboard/shell";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Dialog, DialogClose, DialogContent } from "@/components/ui/dialog";
import { Dropdown, DropdownContent, DropdownItem, DropdownSeparator, DropdownTrigger } from "@/components/ui/dropdown";
import { FieldHint, Input, Label, Textarea } from "@/components/ui/input";
import { api } from "@/lib/api";
import type { ConfigSource, SecretRef, TestResult } from "@/lib/types";
import { cn } from "@/lib/utils";

/* ------------------------------------------------------------------ names */

// names become URL path segments (and secret names), so the bridge's segment rule applies
export const NAME_PATTERN = "[A-Za-z0-9][A-Za-z0-9_\\-]{0,63}";
const NAME_RE = new RegExp(`^${NAME_PATTERN}$`);

export function nameError(name: string, taken: string[] = []): string | null {
  if (!name) return "Give it a name.";
  if (!NAME_RE.test(name)) return "Use letters, digits, - and _ (up to 64), starting with a letter or digit.";
  if (taken.includes(name)) return "That name is already used.";
  return null;
}

/* ----------------------------------------------------------------- layout */

export function Field({
  id,
  label,
  hint,
  error,
  optional,
  children,
  className,
}: {
  id: string;
  label: React.ReactNode;
  hint?: React.ReactNode;
  error?: string | null;
  optional?: boolean;
  children: React.ReactNode;
  className?: string;
}) {
  return (
    <div className={cn("space-y-2", className)}>
      <Label htmlFor={id} className="flex items-baseline gap-2">
        {label}
        {optional && <span className="text-xs font-normal text-muted-foreground">Optional</span>}
      </Label>
      {children}
      {error ? (
        <p id={`${id}-error`} className="text-xs text-critical-fg">
          {error}
        </p>
      ) : (
        hint && <FieldHint>{hint}</FieldHint>
      )}
    </div>
  );
}

export function FormActions({ busy, label, busyLabel }: { busy: boolean; label: string; busyLabel: string }) {
  return (
    <div className="flex justify-end gap-2 border-t pt-4">
      <DialogClose asChild>
        <Button type="button" variant="secondary">
          Cancel
        </Button>
      </DialogClose>
      <Button type="submit" disabled={busy}>
        {busy ? busyLabel : label}
      </Button>
    </div>
  );
}

/** Read-only marker for entries that come from a config file on the server. */
export function SourceBadge({ source, file }: { source: ConfigSource; file: string }) {
  return source === "file" ? (
    <Badge tone="neutral" title={`Edit ${file} on the Farrier server to change this entry.`}>
      <FileLock2 /> Managed in {file}
    </Badge>
  ) : (
    <Badge tone="outline">Dashboard</Badge>
  );
}

/** A provider or CA mark: its logo when we ship one, else a neutral initial tile. */
export function LogoTile({ src, label, className }: { src?: string | null; label: string; className?: string }) {
  return src ? (
    // eslint-disable-next-line @next/next/no-img-element -- tiny static marks, no optimisation needed
    <img src={src} alt="" className={cn("size-8 shrink-0 rounded-md border bg-white object-contain p-1", className)} />
  ) : (
    <span
      aria-hidden
      className={cn("flex size-8 shrink-0 items-center justify-center rounded-md border bg-muted text-sm font-semibold text-muted-foreground", className)}
    >
      {label.charAt(0).toUpperCase()}
    </span>
  );
}

export function Switch({ checked, onChange, disabled, label, id }: { checked: boolean; onChange: (v: boolean) => void; disabled?: boolean; label: string; id?: string }) {
  return (
    <button
      id={id}
      type="button"
      role="switch"
      aria-checked={checked}
      aria-label={label}
      disabled={disabled}
      onClick={() => onChange(!checked)}
      className={cn(
        "relative inline-flex h-5 w-9 shrink-0 items-center rounded-full border border-transparent transition-colors disabled:opacity-50",
        checked ? "bg-foreground" : "bg-input",
      )}
    >
      <span className={cn("size-4 rounded-full bg-background shadow-sm transition-transform", checked ? "translate-x-4" : "translate-x-0")} />
    </button>
  );
}

/* ---------------------------------------------------------------- secrets */

export interface SecretState {
  /** the reference saved today, when editing */
  existing: SecretRef | null;
  replacing: boolean;
  mode: "store" | "ref";
  value: string;
  ref: string;
}

export const secretState = (existing?: SecretRef | null): SecretState => ({
  existing: existing || null,
  replacing: false,
  mode: "store",
  value: "",
  ref: "",
});

export const SECRET_COPY = "Stored encrypted on the Farrier server. It can't be viewed again.";

/**
 * A write-only credential. New values go to the server's secret store; an existing one shows
 * as "Stored securely" and can only be replaced, never read back.
 */
export function SecretInput({
  id,
  label,
  required,
  help,
  state,
  onChange,
  error,
  multiline,
  placeholder,
}: {
  id: string;
  label: string;
  required: boolean;
  help?: string | null;
  state: SecretState;
  onChange: (s: SecretState) => void;
  error?: string | null;
  /** a pasted PEM or OpenSSH key: keeps its line breaks */
  multiline?: boolean;
  placeholder?: string;
}) {
  const set = (patch: Partial<SecretState>) => onChange({ ...state, ...patch });
  const kept = state.existing && !state.replacing;
  const external = state.existing && !state.existing.startsWith("vault:");

  return (
    <Field id={id} label={label} optional={!required} error={error} hint={kept ? help : state.mode === "store" ? SECRET_COPY : help}>
      {kept ? (
        <div className="flex h-9 items-center justify-between gap-2 rounded-md border bg-muted/50 pl-4 pr-1 text-sm">
          <span className="flex min-w-0 items-center gap-2">
            <KeyRound className="size-4 shrink-0 text-good-fg" aria-hidden />
            {external ? (
              <span className="truncate">
                Uses <code className="font-mono text-xs">{state.existing}</code>
              </span>
            ) : (
              "Stored securely"
            )}
          </span>
          <Button type="button" size="sm" variant="ghost" className="h-7" onClick={() => set({ replacing: true })}>
            Replace
          </Button>
        </div>
      ) : (
        <>
          <div className={cn("flex gap-2", multiline && state.mode === "store" && "flex-col items-end")}>
            {state.mode === "store" && multiline ? (
              <Textarea
                id={id}
                rows={5}
                autoComplete="off"
                spellCheck={false}
                value={state.value}
                onChange={(e) => set({ value: e.target.value })}
                aria-invalid={!!error}
                placeholder={placeholder ?? (state.existing ? "Paste the new value" : undefined)}
                className="text-xs"
              />
            ) : state.mode === "store" ? (
              <Input
                id={id}
                type="password"
                autoComplete="new-password"
                spellCheck={false}
                value={state.value}
                onChange={(e) => set({ value: e.target.value })}
                aria-invalid={!!error}
                placeholder={state.existing ? "Enter the new value" : undefined}
              />
            ) : (
              <Input
                id={id}
                spellCheck={false}
                value={state.ref}
                onChange={(e) => set({ ref: e.target.value })}
                aria-invalid={!!error}
                placeholder="env:CF_API_TOKEN or file:/run/secrets/token"
                className="font-mono"
              />
            )}
            {state.existing && (
              <Button type="button" variant="ghost" onClick={() => set({ replacing: false, value: "", ref: "" })}>
                Keep current
              </Button>
            )}
          </div>
          <button
            type="button"
            className="text-xs font-medium text-muted-foreground underline-offset-4 hover:text-foreground hover:underline"
            onClick={() => set({ mode: state.mode === "store" ? "ref" : "store" })}
          >
            {state.mode === "store" ? "Advanced: use an env:/file: reference" : "Store the value on the server instead"}
          </button>
        </>
      )}
    </Field>
  );
}

const EXTERNAL_REF = /^(env:[A-Za-z_][A-Za-z0-9_]*|file:\/.+)$/;

type SecretPlan = { ref: SecretRef | null; put?: { name: string; value: string }; error?: string };

/** What saving this field means: keep, reference, or store a new value under `{entity}-{field}`. */
export function planSecret(state: SecretState, required: boolean, secretName: string): SecretPlan {
  if (state.existing && !state.replacing) return { ref: state.existing };
  if (state.mode === "ref") {
    const ref = state.ref.trim();
    if (!ref) return required ? { ref: null, error: "Required." } : { ref: null };
    if (!EXTERNAL_REF.test(ref)) return { ref: null, error: "Start with env:NAME or file:/absolute/path." };
    return { ref };
  }
  if (!state.value) {
    if (state.existing) return { ref: null, error: "Enter the new value, or keep the current one." };
    return required ? { ref: null, error: "Required." } : { ref: null };
  }
  return { ref: `vault:${secretName}`, put: { name: secretName, value: state.value } };
}

/** Plan every secret field; null when any has an error (they are returned for inline display). */
export function planSecrets(
  fields: { key: string; required: boolean }[],
  states: Record<string, SecretState>,
  entity: string,
): { refs: Record<string, SecretRef | null>; puts: { name: string; value: string }[]; errors: Record<string, string> } {
  const refs: Record<string, SecretRef | null> = {};
  const puts: { name: string; value: string }[] = [];
  const errors: Record<string, string> = {};
  for (const f of fields) {
    const p = planSecret(states[f.key] ?? secretState(), f.required, `${entity}-${f.key}`);
    if (p.error) errors[f.key] = p.error;
    refs[f.key] = p.ref;
    if (p.put) puts.push(p.put);
  }
  return { refs, puts, errors };
}

/** Write new secret values before the config that references them. */
export async function storeSecrets(puts: { name: string; value: string }[]) {
  for (const p of puts) await api.putSecret(p.name, p.value);
}

/** After deleting an entry, drop the vault secrets it owned (best effort; in-use ones are refused). */
export async function dropOwnedSecrets(refs: (SecretRef | null | undefined)[], entity: string) {
  for (const ref of refs) {
    if (ref && ref.startsWith(`vault:${entity}-`)) await api.deleteSecret(ref.slice(6)).catch(() => undefined);
  }
}

/* ------------------------------------------------------------------ chips */

export function ChipsInput({
  id,
  value,
  onChange,
  placeholder,
  validate,
  invalid,
}: {
  id: string;
  value: string[];
  onChange: (v: string[]) => void;
  placeholder?: string;
  /** returns an error message for a bad entry */
  validate?: (v: string) => string | null;
  invalid?: boolean;
}) {
  const [text, setText] = useState("");
  const [err, setErr] = useState<string | null>(null);
  const commit = () => {
    const parts = text.split(/[\s,]+/).map((s) => s.trim()).filter(Boolean);
    if (!parts.length) return true;
    for (const p of parts) {
      const e = validate?.(p);
      if (e) {
        setErr(e);
        return false;
      }
    }
    onChange([...new Set([...value, ...parts])]);
    setText("");
    setErr(null);
    return true;
  };
  return (
    <div>
      <div
        className={cn(
          "flex min-h-9 w-full flex-wrap items-center gap-1 rounded-md border border-input bg-background px-2 py-1 shadow-xs focus-within:border-ring focus-within:ring-3 focus-within:ring-ring/20",
          (invalid || err) && "border-critical",
        )}
      >
        {value.map((v) => (
          <span key={v} className="inline-flex h-6 items-center gap-1 rounded-full bg-muted pl-2 pr-1 text-xs font-medium">
            {v}
            <button
              type="button"
              aria-label={`Remove ${v}`}
              className="rounded-full p-0.5 text-muted-foreground hover:bg-background hover:text-foreground"
              onClick={() => onChange(value.filter((x) => x !== v))}
            >
              <X className="size-3" />
            </button>
          </span>
        ))}
        <input
          id={id}
          value={text}
          placeholder={value.length ? undefined : placeholder}
          onChange={(e) => {
            setText(e.target.value);
            setErr(null);
          }}
          onKeyDown={(e) => {
            if (e.key === "Enter" || e.key === ",") {
              e.preventDefault();
              commit();
            } else if (e.key === "Backspace" && !text && value.length) {
              onChange(value.slice(0, -1));
            }
          }}
          onBlur={commit}
          className="h-7 min-w-32 flex-1 bg-transparent px-2 text-sm outline-none placeholder:text-muted-foreground/70"
        />
      </div>
      {err && <p className="mt-2 text-xs text-critical-fg">{err}</p>}
    </div>
  );
}

/* ------------------------------------------------------------ row actions */

/** Test first (it changes nothing), edit and delete behind a menu. File-managed rows only test. */
export function RowActions({
  name,
  canWrite,
  canTest,
  readOnly,
  testing,
  onTest,
  onEdit,
  onDelete,
}: {
  name: string;
  canWrite: boolean;
  canTest: boolean;
  readOnly: boolean;
  testing: boolean;
  onTest: () => void;
  onEdit: () => void;
  onDelete: () => void;
}) {
  return (
    <div className="flex items-center justify-end gap-1">
      {canTest && (
        <Button size="sm" variant="secondary" onClick={onTest} disabled={testing}>
          {testing ? <Loader2 className="animate-spin" /> : <PlugZap />} Test
        </Button>
      )}
      {canWrite && !readOnly && (
        <Dropdown>
          <DropdownTrigger asChild>
            <Button size="icon-sm" variant="ghost" aria-label={`More actions for ${name}`}>
              <MoreHorizontal />
            </Button>
          </DropdownTrigger>
          <DropdownContent>
            <DropdownItem onSelect={onEdit}>
              <Pencil /> Edit
            </DropdownItem>
            <DropdownSeparator />
            <DropdownItem danger onSelect={onDelete}>
              <Trash2 /> Delete
            </DropdownItem>
          </DropdownContent>
        </Dropdown>
      )}
    </div>
  );
}

/** Per-row test results, kept until the row is tested again or dismissed. */
export function useTests() {
  const [results, setResults] = useState<Record<string, TestResult | "running">>({});
  const run = async (name: string, fn: () => Promise<TestResult>) => {
    setResults((r) => ({ ...r, [name]: "running" }));
    let out: TestResult;
    try {
      out = await fn();
    } catch (e) {
      out = { ok: false, detail: (e as Error).message };
    }
    setResults((r) => ({ ...r, [name]: out }));
    if (out.ok) toast.success(`${name} works`, { description: out.detail });
    else toast.error(`${name} failed its test`, { description: out.detail });
  };
  const dismiss = (name: string) =>
    setResults((r) => {
      const next = { ...r };
      delete next[name];
      return next;
    });
  return { results, run, dismiss };
}

export function TestOutcome({ result, onDismiss, children }: { result: TestResult; onDismiss: () => void; children?: React.ReactNode }) {
  const Icon = result.ok ? CheckCircle2 : XCircle;
  return (
    <div
      role="status"
      className={cn(
        "flex items-start gap-2 rounded-md px-4 py-2 text-sm",
        result.ok ? "bg-good/8 text-good-fg" : "bg-critical/8 text-critical-fg",
      )}
    >
      <Icon className="mt-0.5 size-4 shrink-0" aria-hidden />
      <div className="min-w-0 flex-1 whitespace-normal">
        <p>
          <span className="font-medium">{result.ok ? "Test passed. " : "Test failed. "}</span>
          {result.detail}
        </p>
        {children}
      </div>
      <button type="button" onClick={onDismiss} aria-label="Dismiss test result" className="rounded p-0.5 opacity-70 hover:opacity-100">
        <X className="size-4" />
      </button>
    </div>
  );
}

/* ----------------------------------------------------------------- delete */

export function ConfirmDelete({
  open,
  onOpenChange,
  title,
  children,
  onConfirm,
}: {
  open: boolean;
  onOpenChange: (o: boolean) => void;
  title: string;
  children: React.ReactNode;
  onConfirm: () => Promise<void>;
}) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<Error | null>(null);
  return (
    <Dialog
      open={open}
      onOpenChange={(o) => {
        onOpenChange(o);
        if (o) setError(null);
      }}
    >
      <DialogContent title={title}>
        <div className="space-y-4 text-sm text-muted-foreground">{children}</div>
        <div className="mt-4">
          <ErrorNotice error={error} />
        </div>
        <div className="flex justify-end gap-2 pt-2">
          <DialogClose asChild>
            <Button variant="secondary">Cancel</Button>
          </DialogClose>
          <Button
            variant="danger"
            disabled={busy}
            onClick={async () => {
              setBusy(true);
              setError(null);
              try {
                await onConfirm();
                onOpenChange(false);
              } catch (e) {
                setError(e as Error);
              } finally {
                setBusy(false);
              }
            }}
          >
            <Trash2 /> {busy ? "Deleting…" : "Delete"}
          </Button>
        </div>
      </DialogContent>
    </Dialog>
  );
}

/** A small "admins only" note for page descriptions. */
export function readOnlyNote(canWrite: boolean) {
  return canWrite ? null : " Only admins can change these.";
}
