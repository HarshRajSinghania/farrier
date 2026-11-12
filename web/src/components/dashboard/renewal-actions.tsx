"use client";

import { useState } from "react";
import { Ban, Download, FileText, MoreHorizontal, RefreshCw, StepForward } from "lucide-react";
import { toast } from "sonner";
import { STATE_META } from "@/components/status";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent } from "@/components/ui/dialog";
import { Dropdown, DropdownContent, DropdownItem, DropdownSeparator, DropdownTrigger } from "@/components/ui/dropdown";
import { api } from "@/lib/api";
import { OPEN_STATES, type Renewal } from "@/lib/types";

async function run(label: string, fn: () => Promise<{ state?: string }>) {
  try {
    const r = await fn();
    const meta = r.state ? STATE_META[r.state as keyof typeof STATE_META] : undefined;
    toast.success(label, meta ? { description: `Now: ${meta.label}` } : undefined);
  } catch (e) {
    toast.error(`${label} failed`, { description: (e as Error).message });
  }
}

/**
 * One primary action per state, the rest behind a menu.
 * awaiting_manual → Download pack · failed/rolled_back → Retry · other open → Advance.
 */
export function RenewalActions({ renewal: r, compact }: { renewal: Renewal; compact?: boolean }) {
  const [busy, setBusy] = useState(false);
  const [runbook, setRunbook] = useState<string | null>(null);
  const isOpen = OPEN_STATES.includes(r.state);

  const wrap = (fn: () => Promise<unknown>) => async () => {
    setBusy(true);
    await fn();
    setBusy(false);
  };

  const retry = wrap(() => run(`Renewal restarted for ${r.name}`, () => api.renew(r.endpoint_id)));
  const advance = wrap(() => run(`Checked ${r.name}`, () => api.advance(r.id)));
  const cancel = wrap(() => run(`Cancelled renewal for ${r.name}`, () => api.cancel(r.id)));
  const openRunbook = wrap(async () => {
    try {
      setRunbook((await api.runbook(r.id)).markdown);
    } catch (e) {
      toast.error("No runbook", { description: (e as Error).message });
    }
  });

  let primary: React.ReactNode = null;
  if (r.state === "awaiting_manual") {
    primary = (
      <Button asChild size="sm" variant="secondary">
        <a href={api.packUrl(r.id)} download>
          <Download /> {compact ? "Pack" : "Change pack"}
        </a>
      </Button>
    );
  } else if (r.state === "failed" || r.state === "rolled_back") {
    primary = (
      <Button size="sm" variant="secondary" onClick={retry} disabled={busy}>
        <RefreshCw /> Retry
      </Button>
    );
  } else if (isOpen) {
    primary = (
      <Button size="sm" variant="secondary" onClick={advance} disabled={busy}>
        <StepForward /> Advance
      </Button>
    );
  }

  return (
    <div className="flex items-center gap-1">
      {primary}
      {(isOpen || r.state === "awaiting_manual") && (
        <Dropdown>
          <DropdownTrigger asChild>
            <Button size="icon-sm" variant="ghost" aria-label={`More actions for ${r.name}`}>
              <MoreHorizontal />
            </Button>
          </DropdownTrigger>
          <DropdownContent>
            {r.state === "awaiting_manual" && (
              <>
                <DropdownItem onSelect={openRunbook}>
                  <FileText /> View runbook
                </DropdownItem>
                <DropdownItem onSelect={advance}>
                  <StepForward /> Check if installed
                </DropdownItem>
                <DropdownSeparator />
              </>
            )}
            <DropdownItem danger onSelect={cancel}>
              <Ban /> Cancel renewal
            </DropdownItem>
          </DropdownContent>
        </Dropdown>
      )}
      <Dialog open={runbook !== null} onOpenChange={(o) => !o && setRunbook(null)}>
        <DialogContent title={`Runbook: ${r.name}`} description="Generated for this device. Follow it in your change window." className="max-w-2xl">
          <pre className="max-h-[60vh] overflow-auto whitespace-pre-wrap rounded-md border bg-muted p-4 font-mono text-xs leading-relaxed">
            {runbook}
          </pre>
        </DialogContent>
      </Dialog>
    </div>
  );
}
