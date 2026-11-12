"use client";

import { useState } from "react";
import { ChevronRight } from "lucide-react";
import { toast } from "sonner";
import { CONNECTOR_LABEL } from "@/components/status";
import { Button } from "@/components/ui/button";
import { Dialog, DialogClose, DialogContent, DialogTrigger } from "@/components/ui/dialog";
import { FieldHint, Input, Label, Textarea } from "@/components/ui/input";
import { Select } from "@/components/ui/select";
import { api, useConnectors } from "@/lib/api";

const DAYS = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"];

function template(required: string[]) {
  return JSON.stringify(Object.fromEntries(required.map((k) => [k, /password|token|key$/.test(k) ? "env:" : ""])), null, 2);
}

export function AddEndpointDialog({ children }: { children: React.ReactNode }) {
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const { data: connectors } = useConnectors();
  const [connector, setConnector] = useState("manual");
  const [config, setConfig] = useState("{}");
  const [days, setDays] = useState<string[]>([]);

  const pickConnector = (kind: string) => {
    setConnector(kind);
    setConfig(template(connectors?.find((c) => c.kind === kind)?.required ?? []));
  };

  async function submit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setError(null);
    const f = new FormData(e.currentTarget);
    let connector_config: Record<string, unknown>;
    try {
      connector_config = JSON.parse(config || "{}");
    } catch {
      setError("Connector config must be valid JSON.");
      return;
    }
    const start = String(f.get("start") || "");
    setBusy(true);
    try {
      await api.addEndpoint({
        name: String(f.get("name")).trim(),
        host: String(f.get("host")).trim(),
        port: Number(f.get("port") || 443),
        sni: String(f.get("sni") || "") || null,
        connector,
        connector_config,
        issuer: String(f.get("issuer") || "default"),
        owner: String(f.get("owner") || "") || null,
        lead_days: Number(f.get("lead_days") || 0),
        window: days.length && start ? { days, start, hours: Number(f.get("hours") || 2) } : {},
      });
      toast.success("Endpoint added", { description: "Farrier will scan it and plan a renewal when one is due." });
      setOpen(false);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <Dialog
      open={open}
      onOpenChange={(o) => {
        setOpen(o);
        if (o) setError(null);
      }}
    >
      <DialogTrigger asChild>{children}</DialogTrigger>
      <DialogContent title="Add endpoint" description="A TLS listener for Farrier to watch and renew." className="max-w-xl">
        <form onSubmit={submit} className="space-y-4">
          <div className="grid gap-4 sm:grid-cols-2">
            <div className="space-y-2">
              <Label htmlFor="name">Name</Label>
              <Input id="name" name="name" required placeholder="vpn-fgt" pattern="[A-Za-z0-9._\-]+" autoFocus />
            </div>
            <div className="space-y-2">
              <Label htmlFor="owner">Owner</Label>
              <Input id="owner" name="owner" placeholder="network" />
            </div>
            <div className="space-y-2">
              <Label htmlFor="host">Host</Label>
              <Input id="host" name="host" required placeholder="vpn.example.com" />
            </div>
            <div className="space-y-2">
              <Label htmlFor="port">Port</Label>
              <Input id="port" name="port" type="number" min={1} max={65535} defaultValue={443} />
            </div>
          </div>

          <div className="space-y-2">
            <Label htmlFor="connector">Connector</Label>
            <Select
              id="connector"
              value={connector}
              onValueChange={pickConnector}
              options={(connectors ?? [{ kind: "manual", automated: false }]).map((c) => ({
                value: c.kind,
                label: CONNECTOR_LABEL[c.kind] ?? c.kind,
                description: c.automated ? "Renewed automatically" : "Change pack for a person",
              }))}
            />
          </div>

          <div className="space-y-2">
            <Label htmlFor="config">Connector config</Label>
            <Textarea id="config" rows={5} value={config} onChange={(e) => setConfig(e.target.value)} spellCheck={false} />
            <FieldHint>
              Reference secrets as <code className="font-mono">env:NAME</code> or <code className="font-mono">file:/path</code>. They are never stored inline or returned by the API.
            </FieldHint>
          </div>

          <details className="group rounded-lg border">
            <summary className="flex cursor-pointer list-none items-center gap-2 px-4 py-2 text-sm font-medium">
              <ChevronRight className="size-4 text-muted-foreground transition-transform group-open:rotate-90" />
              Change window, issuer and lead time
            </summary>
            <div className="space-y-4 border-t p-4">
              <fieldset className="space-y-2">
                <legend className="text-sm font-medium">Maintenance days (UTC)</legend>
                <div className="flex flex-wrap gap-2">
                  {DAYS.map((d) => {
                    const on = days.includes(d);
                    return (
                      <button
                        key={d}
                        type="button"
                        aria-pressed={on}
                        onClick={() => setDays((x) => (on ? x.filter((y) => y !== d) : [...x, d]))}
                        className={`h-8 min-w-11 rounded-md border px-2 text-xs font-medium capitalize ${on ? "border-brand bg-brand-soft text-brand-ink" : "text-muted-foreground hover:bg-muted"}`}
                      >
                        {d}
                      </button>
                    );
                  })}
                </div>
                <FieldHint>Leave empty to allow renewals at any time.</FieldHint>
              </fieldset>
              <div className="grid gap-4 sm:grid-cols-3">
                <div className="space-y-2">
                  <Label htmlFor="start">Window start</Label>
                  <Input id="start" name="start" type="time" defaultValue="02:00" />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="hours">Hours</Label>
                  <Input id="hours" name="hours" type="number" min={1} max={24} defaultValue={3} />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="lead_days">Lead days</Label>
                  <Input id="lead_days" name="lead_days" type="number" min={0} max={120} defaultValue={0} />
                </div>
              </div>
              <div className="grid gap-4 sm:grid-cols-2">
                <div className="space-y-2">
                  <Label htmlFor="issuer">Issuer</Label>
                  <Input id="issuer" name="issuer" defaultValue="default" />
                  <FieldHint>A key in issuers.json.</FieldHint>
                </div>
                <div className="space-y-2">
                  <Label htmlFor="sni">SNI</Label>
                  <Input id="sni" name="sni" placeholder="Defaults to host" />
                </div>
              </div>
            </div>
          </details>

          {error && (
            <p role="alert" className="rounded-md bg-critical/8 px-4 py-2 text-sm text-critical-fg">
              {error}
            </p>
          )}

          <div className="flex justify-end gap-2 pt-1">
            <DialogClose asChild>
              <Button type="button" variant="secondary">
                Cancel
              </Button>
            </DialogClose>
            <Button type="submit" disabled={busy}>
              {busy ? "Adding…" : "Add endpoint"}
            </Button>
          </div>
        </form>
      </DialogContent>
    </Dialog>
  );
}
