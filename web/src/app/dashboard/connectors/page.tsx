"use client";

import Link from "next/link";
import { Bot, Hand } from "lucide-react";
import { ErrorNotice, PageHeader } from "@/components/dashboard/shell";
import { CONNECTOR_LABEL } from "@/components/status";
import { Badge } from "@/components/ui/badge";
import { Card } from "@/components/ui/card";
import { EmptyState, Skeleton } from "@/components/ui/misc";
import { useConnectors, useSummary } from "@/lib/api";

export default function ConnectorsPage() {
  const { data, error } = useConnectors();
  const { data: s } = useSummary();
  return (
    <>
      <PageHeader
        title="Connectors"
        description={
          <>
            How a certificate reaches each kind of device. Configure per endpoint;{" "}
            <Link href="/docs/connectors" className="text-brand-ink underline-offset-4 hover:underline">
              see the reference
            </Link>
            .
          </>
        }
      />
      <ErrorNotice error={error} />
      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
        {!data
          ? Array.from({ length: 6 }, (_, i) => <Skeleton key={i} className="h-44" />)
          : data.length === 0
            ? [<EmptyState key="none" className="col-span-full" title="No connectors loaded">The engine reported none. Check its logs.</EmptyState>]
            : data.map((c) => (
              <Card key={c.kind} className="flex flex-col p-6">
                <div className="flex items-start justify-between gap-4">
                  <div>
                    <p className="font-semibold">{CONNECTOR_LABEL[c.kind] ?? c.kind}</p>
                    <p className="font-mono text-xs text-muted-foreground">{c.kind}</p>
                  </div>
                  {c.automated ? (
                    <Badge tone="info">
                      <Bot /> Automated
                    </Badge>
                  ) : (
                    <Badge tone="warning">
                      <Hand /> Change pack
                    </Badge>
                  )}
                </div>
                <p className="mt-4 line-clamp-4 text-sm text-muted-foreground">{c.doc.split("\n\n")[0]}</p>
                <div className="mt-auto flex flex-wrap items-center gap-2 pt-4">
                  {c.required.map((r) => (
                    <code key={r} className="rounded border bg-muted px-2 py-1 font-mono text-xs">
                      {r}
                    </code>
                  ))}
                  <span className="tabular ml-auto text-xs text-muted-foreground">
                    {s?.by_connector[c.kind] ?? 0} endpoints
                  </span>
                </div>
              </Card>
            ))}
      </div>
    </>
  );
}
