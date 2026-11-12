"use client";

import Link from "next/link";
import { useMemo, useState } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { ArrowDownUp, Download, MoreHorizontal, Plus, RefreshCw, Search, Server, Trash2 } from "lucide-react";
import { toast } from "sonner";
import { ErrorNotice, PageHeader } from "@/components/dashboard/shell";
import { TableSkeleton } from "@/components/dashboard/widgets";
import { AddEndpointDialog } from "@/components/dashboard/add-endpoint";
import { ConnectorTag, ExpiryBadge, expiryLevel } from "@/components/status";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Dialog, DialogClose, DialogContent } from "@/components/ui/dialog";
import { Dropdown, DropdownContent, DropdownItem, DropdownSeparator, DropdownTrigger } from "@/components/ui/dropdown";
import { Input } from "@/components/ui/input";
import { EmptyState } from "@/components/ui/misc";
import { Segmented } from "@/components/ui/segmented";
import { Table, TBody, TD, TH, THead, TR } from "@/components/ui/table";
import { api, useEndpoints } from "@/lib/api";
import { useAccess } from "@/lib/auth/client";
import type { Endpoint } from "@/lib/types";
import { fmtDate, relativeTime, shortFp } from "@/lib/utils";

type Filter = "all" | "expiring" | "manual" | "automated" | "errors";
type SortKey = "days_left" | "name" | "connector";

const FILTERS: Record<Filter, (e: Endpoint) => boolean> = {
  all: () => true,
  expiring: (e) => ["expired", "critical", "warning"].includes(expiryLevel(e.days_left)),
  manual: (e) => !e.automated,
  automated: (e) => e.automated,
  errors: (e) => !!e.scan_error,
};

function SortTH({
  k,
  sort,
  onSort,
  children,
}: {
  k: SortKey;
  sort: { key: SortKey; asc: boolean };
  onSort: () => void;
  children: React.ReactNode;
}) {
  return (
    <TH aria-sort={sort.key === k ? (sort.asc ? "ascending" : "descending") : "none"}>
      <button type="button" className="inline-flex items-center gap-1 hover:text-foreground" onClick={onSort}>
        {children}
        <ArrowDownUp className="size-3 opacity-60" aria-hidden />
      </button>
    </TH>
  );
}

export function EndpointsView() {
  const params = useSearchParams();
  const router = useRouter();
  const { data, error, isLoading } = useEndpoints();
  const { can } = useAccess();
  const [query, setQuery] = useState(() => params.get("q") ?? "");
  const [sort, setSort] = useState<{ key: SortKey; asc: boolean }>({ key: "days_left", asc: true });
  const [confirm, setConfirm] = useState<Endpoint | null>(null);
  const filter: Filter = params.get("expiring") ? "expiring" : ((params.get("filter") as Filter) ?? "all");

  const setFilter = (f: Filter) => router.replace(f === "all" ? "?" : `?filter=${f}`, { scroll: false });

  const rows = useMemo(() => {
    const q = query.trim().toLowerCase();
    const list = (data ?? []).filter(
      (e) =>
        FILTERS[filter](e) &&
        (!q || [e.name, e.host, e.owner, e.connector, e.subject_cn].some((v) => v?.toLowerCase().includes(q))),
    );
    const dir = sort.asc ? 1 : -1;
    return list.sort((a, b) => {
      if (sort.key === "days_left") return ((a.days_left ?? 1e9) - (b.days_left ?? 1e9)) * dir;
      return String(a[sort.key]).localeCompare(String(b[sort.key])) * dir;
    });
  }, [data, filter, query, sort]);

  const counts = useMemo(
    () => Object.fromEntries(Object.entries(FILTERS).map(([k, f]) => [k, (data ?? []).filter(f).length])) as Record<Filter, number>,
    [data],
  );

  const sortProps = (k: SortKey) => ({ k, sort, onSort: () => setSort((s) => ({ key: k, asc: s.key === k ? !s.asc : true })) });

  return (
    <>
      <PageHeader
        title="Endpoints"
        description="Every TLS listener Farrier watches, sorted by what expires first."
        actions={
          <>
          <Button asChild variant="secondary">
            <a href="/api/farrier/inventory?format=csv" download>
              <Download /> Export CSV
            </a>
          </Button>
          {can("POST", "endpoints") && (
            <AddEndpointDialog>
              <Button>
                <Plus /> Add endpoint
              </Button>
            </AddEndpointDialog>
          )}
          </>
        }
      />
      <ErrorNotice error={error} />

      <div className="mb-4 flex flex-wrap items-center gap-2">
        <Segmented
          label="Filter endpoints"
          value={filter}
          onChange={setFilter}
          options={[
            { value: "all", label: "All", count: counts.all },
            { value: "expiring", label: "Expiring", count: counts.expiring },
            { value: "automated", label: "Automated", count: counts.automated },
            { value: "manual", label: "Manual", count: counts.manual },
            { value: "errors", label: "Scan errors", count: counts.errors },
          ]}
        />
        <div className="relative ml-auto w-full sm:w-64">
          <Search className="pointer-events-none absolute left-2 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" />
          <Input
            placeholder="Search name, host, owner…"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            className="pl-8"
            aria-label="Search endpoints"
          />
        </div>
      </div>

      <Card className="overflow-hidden">
        {isLoading ? (
          <TableSkeleton />
        ) : rows.length === 0 ? (
          <EmptyState
            icon={<Server />}
            title={data?.length ? "No endpoints match" : "No endpoints yet"}
            action={
              !data?.length && (
                <Button asChild>
                  <Link href="/dashboard/discovery">Scan a network range</Link>
                </Button>
              )
            }
          >
            {data?.length ? "Try a different filter or search." : "Scan a range to find what's being served, or add an endpoint by hand."}
          </EmptyState>
        ) : (
          <Table>
            <THead>
              <TR>
                <SortTH {...sortProps("name")}>Endpoint</SortTH>
                <SortTH {...sortProps("connector")}>Connector</SortTH>
                <SortTH {...sortProps("days_left")}>Expiry</SortTH>
                <TH className="hidden md:table-cell">Issuer</TH>
                <TH className="hidden lg:table-cell">Fingerprint</TH>
                <TH className="hidden xl:table-cell">Owner</TH>
                <TH className="hidden md:table-cell">Last seen</TH>
                <TH className="w-10">
                  <span className="sr-only">Actions</span>
                </TH>
              </TR>
            </THead>
            <TBody>
              {rows.map((e) => (
                <TR key={e.id}>
                  <TD>
                    <p className="font-medium">{e.name}</p>
                    <p className="font-mono text-xs text-muted-foreground">
                      {e.host}:{e.port}
                    </p>
                  </TD>
                  <TD>
                    <ConnectorTag kind={e.connector} automated={e.automated} />
                  </TD>
                  <TD>
                    <ExpiryBadge daysLeft={e.days_left} />
                    {e.not_after && <p className="mt-1 text-xs text-muted-foreground">{fmtDate(e.not_after)}</p>}
                  </TD>
                  <TD className="hidden max-w-48 truncate text-sm text-muted-foreground md:table-cell" title={e.cert_issuer ?? ""}>
                    {e.scan_error ? <span className="text-critical-fg">{e.scan_error}</span> : (e.cert_issuer?.match(/CN=([^,]+)/)?.[1] ?? e.cert_issuer ?? "—")}
                  </TD>
                  <TD className="hidden font-mono text-xs text-muted-foreground lg:table-cell">{shortFp(e.fingerprint)}</TD>
                  <TD className="hidden text-sm text-muted-foreground xl:table-cell">{e.owner ?? "—"}</TD>
                  <TD className="hidden text-xs text-muted-foreground md:table-cell">{relativeTime(e.observed_at)}</TD>
                  <TD>
                    <Dropdown>
                      <DropdownTrigger asChild>
                        <Button size="icon-sm" variant="ghost" aria-label={`Actions for ${e.name}`}>
                          <MoreHorizontal />
                        </Button>
                      </DropdownTrigger>
                      <DropdownContent>
                        <DropdownItem
                          onSelect={async () => {
                            try {
                              const r = await api.renew(e.id);
                              toast.success(`Renewal started for ${e.name}`, { description: `State: ${r.state.replace("_", " ")}` });
                            } catch (err) {
                              toast.error("Could not start renewal", { description: (err as Error).message });
                            }
                          }}
                        >
                          <RefreshCw /> Renew now
                        </DropdownItem>
                        <DropdownSeparator />
                        <DropdownItem danger onSelect={() => setConfirm(e)}>
                          <Trash2 /> Remove endpoint
                        </DropdownItem>
                      </DropdownContent>
                    </Dropdown>
                  </TD>
                </TR>
              ))}
            </TBody>
          </Table>
        )}
      </Card>
      {data && (
        <p className="mt-4 text-xs text-muted-foreground">
          Showing {rows.length} of {data.length} endpoints
        </p>
      )}

      <Dialog open={!!confirm} onOpenChange={(o) => !o && setConfirm(null)}>
        <DialogContent
          title={`Remove ${confirm?.name}?`}
          description="Farrier stops watching and renewing this endpoint and deletes its renewal history. The certificate on the device is not touched."
        >
          <div className="flex justify-end gap-2">
            <DialogClose asChild>
              <Button variant="secondary">Keep it</Button>
            </DialogClose>
            <Button
              variant="danger"
              onClick={async () => {
                const ep = confirm!;
                setConfirm(null);
                try {
                  await api.deleteEndpoint(ep.id);
                  toast.success(`Removed ${ep.name}`);
                } catch (err) {
                  toast.error("Could not remove endpoint", { description: (err as Error).message });
                }
              }}
            >
              Remove endpoint
            </Button>
          </div>
        </DialogContent>
      </Dialog>
    </>
  );
}
