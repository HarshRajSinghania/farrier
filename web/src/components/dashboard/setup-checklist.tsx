"use client";

import Link from "next/link";
import { useState, useSyncExternalStore } from "react";
import { ArrowRight, Check, X } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { useAlertRules, useDnsAccounts, useEndpoints, useIssuers, useNotifiers } from "@/lib/api";
import { useAccess } from "@/lib/auth/client";
import { cn } from "@/lib/utils";

const DISMISS_KEY = "farrier.setup.dismissed";
const noop = () => () => {};

type Step = { id: string; title: string; detail: string; done: boolean; href: string; cta: string; skip?: boolean };

/**
 * First-run guide on Overview: five steps in dependency order, each ticked from the real
 * configuration. Hidden for non-admins (they can't do the steps), once everything is done,
 * or when dismissed in this browser.
 */
export function SetupChecklist() {
  const { can } = useAccess();
  const { data: issuers } = useIssuers();
  const { data: dns } = useDnsAccounts();
  const { data: endpoints } = useEndpoints();
  const { data: channels } = useNotifiers();
  const { data: rules } = useAlertRules();
  const stored = useSyncExternalStore(noop, () => localStorage.getItem(DISMISS_KEY) === "1", () => true);
  const [dismissed, setDismissed] = useState(false);

  if (!can("PUT", "issuers/x") || stored || dismissed) return null;
  if (!issuers || !dns || !endpoints || !channels || !rules) return null; // appears once, complete, no flicker

  const publicCa = issuers.some((i) => i.type === "acme");
  const steps: Step[] = [
    {
      id: "ca",
      title: "Choose a certificate authority",
      detail: publicCa ? "A public CA is connected." : "The built-in private CA is ready. Add Let's Encrypt or another CA for public names.",
      done: true,
      href: "/dashboard/integrations/authorities",
      cta: publicCa ? "Review" : "Add a public CA",
    },
    {
      id: "dns",
      title: "Connect your DNS",
      detail: publicCa ? "Public CAs check a DNS record you control." : "Only needed for public CAs.",
      done: dns.length > 0,
      skip: !publicCa,
      href: "/dashboard/integrations/dns",
      cta: "Connect DNS",
    },
    {
      id: "endpoints",
      title: "Add endpoints",
      detail: "Scan a network range, or add an endpoint by hand.",
      done: endpoints.length > 0,
      href: endpoints.length > 0 ? "/dashboard/endpoints" : "/dashboard/discovery",
      cta: "Scan a range",
    },
    {
      id: "channel",
      title: "Add an alert channel",
      detail: "Slack, Teams, email, a webhook or an event bus.",
      done: channels.length > 0,
      href: "/dashboard/integrations/alerts?tab=channels",
      cta: "Add a channel",
    },
    {
      id: "rule",
      title: "Create an alert rule",
      detail: "For example: tell me when a certificate expires within 21 days.",
      done: rules.length > 0,
      href: "/dashboard/integrations/alerts",
      cta: "Create a rule",
    },
  ];
  const counted = steps.filter((s) => !s.skip);
  const finished = counted.filter((s) => s.done).length;
  if (finished === counted.length) return null;
  const next = steps.find((s) => !s.done && !s.skip);

  const dismiss = () => {
    setDismissed(true);
    try {
      localStorage.setItem(DISMISS_KEY, "1");
    } catch {}
  };

  return (
    <Card className="mb-8 overflow-hidden">
      <div className="flex items-start justify-between gap-4 px-6 pt-6">
        <div>
          <h2 className="text-lg font-semibold">Set up Farrier</h2>
          <p className="mt-1 text-sm text-muted-foreground">
            {finished} of {counted.length} done. Each step takes a minute.
          </p>
        </div>
        <Button variant="ghost" size="icon-sm" onClick={dismiss} aria-label="Hide setup guide" title="Hide setup guide">
          <X />
        </Button>
      </div>
      <div className="mx-6 mt-4 h-1.5 overflow-hidden rounded-full bg-muted" aria-hidden>
        <div className="h-full rounded-full bg-brand transition-[width] duration-500" style={{ width: `${(finished / counted.length) * 100}%` }} />
      </div>
      <ol className="mt-4 divide-y border-t">
        {steps.map((s, i) => {
          const current = s.id === next?.id;
          return (
            <li key={s.id} className={cn("flex flex-wrap items-center gap-4 px-6 py-4", current && "bg-brand-soft/40")}>
              <span
                className={cn(
                  "flex size-7 shrink-0 items-center justify-center rounded-full text-xs font-semibold",
                  s.done ? "bg-good/15 text-good-fg" : s.skip ? "bg-muted text-muted-foreground" : current ? "bg-foreground text-background" : "border text-muted-foreground",
                )}
                aria-label={s.done ? "Done" : s.skip ? "Not needed" : `Step ${i + 1}`}
              >
                {s.done ? <Check className="size-4" /> : i + 1}
              </span>
              <div className="min-w-0 flex-1 max-sm:basis-[calc(100%-3rem)]">
                <p className={cn("text-sm font-medium", (s.done || s.skip) && "text-muted-foreground")}>
                  {s.title}
                  {s.skip && <span className="ml-2 text-xs font-normal">· not needed</span>}
                </p>
                <p className="text-sm text-muted-foreground">{s.detail}</p>
              </div>
              {!s.skip && (current || s.id === "ca") && (
                <Button asChild size="sm" variant={current ? "primary" : "secondary"} className="max-sm:ml-11">
                  <Link href={s.href}>
                    {s.cta} <ArrowRight />
                  </Link>
                </Button>
              )}
            </li>
          );
        })}
      </ol>
    </Card>
  );
}
