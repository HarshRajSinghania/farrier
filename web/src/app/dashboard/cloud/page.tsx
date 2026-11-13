"use client";

import { useState } from "react";
import { RefreshCw } from "lucide-react";
import { ErrorNotice, PageHeader } from "@/components/dashboard/shell";
import { ExpiryBadge } from "@/components/status";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/misc";
import { Table, TBody, TD, TH, THead, TR } from "@/components/ui/table";
import { api, useCloudCertificates } from "@/lib/api";
import { relativeTime } from "@/lib/utils";

const SOURCE: Record<string, string> = {
  "aws-acm": "AWS ACM",
  "azure-keyvault": "Azure Key Vault",
  "gcp-certificate-manager": "Google Certificate Manager",
};

const EXAMPLE = `"cloud_inventory": {
  "aws_regions": ["eu-west-1", "us-east-1"],
  "azure_vaults": ["prod-kv"],
  "gcp_projects": ["my-project"]
}`;

export default function CloudPage() {
  const { data, error, mutate } = useCloudCertificates();
  const [busy, setBusy] = useState(false);
  const [failure, setFailure] = useState<Error | null>(null);

  const refresh = async () => {
    setBusy(true);
    setFailure(null);
    try {
      await mutate(await api.refreshCloud(), { revalidate: false });
    } catch (e) {
      setFailure(e as Error);
    } finally {
      setBusy(false);
    }
  };

  return (
    <>
      <PageHeader
        title="Cloud certificates"
        description="Certificates your load balancers, CDNs and gateways use, in AWS Certificate Manager, Azure Key Vault and Google Certificate Manager."
        actions={
          data?.configured && (
            <Button variant="secondary" onClick={refresh} disabled={busy}>
              <RefreshCw className={busy ? "animate-spin" : undefined} /> List again
            </Button>
          )
        }
      />
      <ErrorNotice error={error || failure} />
      {data?.errors.map((e) => (
        <p key={`${e.source}-${e.location}`} role="alert" className="mb-2 rounded-md bg-warning/10 px-4 py-2 text-sm text-warning-fg">
          {SOURCE[e.source] ?? e.source} {e.location}: {e.error}
        </p>
      ))}
      <Card>
        <CardContent className="pt-6">
          {!data ? (
            <Skeleton className="h-40" />
          ) : !data.configured ? (
            <div className="space-y-3 text-sm">
              <p>
                Add the accounts to list to <code className="font-mono text-xs">settings.json</code>. Farrier uses the
                platform identity of each cloud (IAM role, managed identity, workload identity) to read them.
              </p>
              <pre className="overflow-x-auto rounded-lg bg-muted p-4 font-mono text-xs">{EXAMPLE}</pre>
            </div>
          ) : data.certificates.length === 0 ? (
            <p className="text-sm text-muted-foreground">No certificates in the configured accounts.</p>
          ) : (
            <Table>
              <THead>
                <TR>
                  <TH>Certificate</TH>
                  <TH>Where</TH>
                  <TH>Expires</TH>
                  <TH>In use</TH>
                  <TH>Renewal</TH>
                </TR>
              </THead>
              <TBody>
                {data.certificates.map((c) => (
                  <TR key={c.id}>
                    <TD>
                      <p className="font-medium">{c.name}</p>
                      {c.domains.length > 0 && c.domains[0] !== c.name && (
                        <p className="max-w-80 truncate text-xs text-muted-foreground" title={c.domains.join(", ")}>
                          {c.domains.join(", ")}
                        </p>
                      )}
                    </TD>
                    <TD className="text-sm">
                      {SOURCE[c.source]} <span className="text-muted-foreground">· {c.location}</span>
                    </TD>
                    <TD>
                      <ExpiryBadge daysLeft={c.days_left} />
                    </TD>
                    <TD className="text-sm">{c.in_use === null ? "—" : c.in_use ? "Yes" : "No"}</TD>
                    <TD>
                      {c.managed ? <Badge tone="good">By the cloud</Badge> : <Badge tone="neutral">Imported</Badge>}
                    </TD>
                  </TR>
                ))}
              </TBody>
            </Table>
          )}
          {data?.listed_at && <p className="mt-4 text-xs text-muted-foreground">Listed {relativeTime(data.listed_at)}</p>}
        </CardContent>
      </Card>
    </>
  );
}
