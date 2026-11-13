"use client";

import { useState } from "react";
import { ShieldAlert } from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent } from "@/components/ui/dialog";
import { FieldHint, Input, Label } from "@/components/ui/input";
import { Select } from "@/components/ui/select";
import { api } from "@/lib/api";

const REASONS = [
  { value: "superseded", label: "Superseded (routine)" },
  { value: "keyCompromise", label: "Key compromise" },
  { value: "cACompromise", label: "CA compromise or distrust" },
  { value: "cessationOfOperation", label: "No longer used" },
];

type Match = { endpoint_id: number; name: string; cert_issuer: string | null };

/**
 * The incident drill: renew every certificate from one CA, issuer or key type now, and optionally revoke the
 * old ones once nothing serves them. Always previews the matches before anything changes.
 */
export function ReplaceDialog() {
  const [open, setOpen] = useState(false);
  const [by, setBy] = useState<"ca" | "issuer" | "key_type">("ca");
  const [value, setValue] = useState("");
  const [reason, setReason] = useState("superseded");
  const [revoke, setRevoke] = useState(false);
  const [matches, setMatches] = useState<Match[] | null>(null);
  const [busy, setBusy] = useState(false);

  const filter = { [by]: value.trim() };
  const preview = async () => {
    setBusy(true);
    try {
      setMatches((await api.replace({ filter, dry_run: true })).matches ?? []);
    } catch (e) {
      toast.error("Could not list matches", { description: (e as Error).message });
    } finally {
      setBusy(false);
    }
  };
  const run = async () => {
    setBusy(true);
    try {
      const r = await api.replace({ filter, reason, revoke });
      toast.success(`${r.renewals?.length ?? 0} renewals started`, {
        description: revoke ? "Old certificates are revoked once nothing serves them." : undefined,
      });
      setOpen(false);
      setMatches(null);
    } catch (e) {
      toast.error("Replace failed", { description: (e as Error).message });
    } finally {
      setBusy(false);
    }
  };

  return (
    <>
      <Button variant="secondary" onClick={() => setOpen(true)}>
        <ShieldAlert /> Replace…
      </Button>
      <Dialog open={open} onOpenChange={(o) => { setOpen(o); if (!o) setMatches(null); }}>
        <DialogContent
          title="Replace certificates now"
          description="For a key compromise or a distrusted CA: renew every matching endpoint now, outside change windows."
          className="max-w-xl"
        >
          <div className="space-y-4">
            <div className="grid gap-3 sm:grid-cols-[12rem_1fr]">
              <div>
                <Label htmlFor="replace-by">Match by</Label>
                <Select id="replace-by" value={by} onValueChange={(v) => { setBy(v as typeof by); setMatches(null); }} options={[
                  { value: "ca", label: "Certificate's CA" },
                  { value: "issuer", label: "Farrier issuer" },
                  { value: "key_type", label: "Key type" },
                ]} />
              </div>
              <div>
                <Label htmlFor="replace-value">{by === "ca" ? "Text in the CA name" : by === "issuer" ? "Issuer name" : "Key type"}</Label>
                <Input id="replace-value" value={value} onChange={(e) => { setValue(e.target.value); setMatches(null); }}
                  placeholder={by === "ca" ? "R10, Entrust, Internal CA" : by === "issuer" ? "le" : "rsa2048"} className="mt-1" />
              </div>
            </div>
            <div className="grid gap-3 sm:grid-cols-2">
              <div>
                <Label htmlFor="replace-reason">Reason</Label>
                <Select id="replace-reason" value={reason} onValueChange={setReason} options={REASONS} />
              </div>
              <label className="flex items-end gap-2 pb-2 text-sm">
                <input type="checkbox" checked={revoke} onChange={(e) => setRevoke(e.target.checked)} className="size-4" />
                Revoke the old certificates once nothing serves them
              </label>
            </div>
            {matches && (
              <div className="max-h-48 overflow-auto rounded-md border p-2 text-sm" role="status">
                {matches.length === 0 ? (
                  <p className="text-muted-foreground">Nothing matches.</p>
                ) : (
                  <>
                    <p className="mb-1 font-medium">{matches.length} endpoints will be renewed now:</p>
                    <ul className="space-y-0.5">
                      {matches.map((m) => (
                        <li key={m.endpoint_id} className="flex justify-between gap-2">
                          <span>{m.name}</span>
                          <span className="truncate text-xs text-muted-foreground">{m.cert_issuer}</span>
                        </li>
                      ))}
                    </ul>
                  </>
                )}
              </div>
            )}
            <FieldHint>Discovered endpoints that nobody approved are skipped. Every step appears in Activity.</FieldHint>
            <div className="flex justify-end gap-2">
              {!matches ? (
                <Button onClick={preview} disabled={busy || !value.trim()}>Preview</Button>
              ) : (
                <Button variant="danger" onClick={run} disabled={busy || matches.length === 0}>
                  Replace {matches.length} now
                </Button>
              )}
            </div>
          </div>
        </DialogContent>
      </Dialog>
    </>
  );
}
