"use client";

import { useState } from "react";
import { Network } from "lucide-react";
import { CopyButton } from "@/components/dashboard/certificate-view";
import { ConfirmDelete } from "@/components/dashboard/integrations/common";
import { ErrorNotice } from "@/components/dashboard/shell";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { FieldHint, Input, Label } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/misc";
import { Table, TBody, TD, TH, THead, TR } from "@/components/ui/table";
import { api, useRunners } from "@/lib/api";
import { useAccess } from "@/lib/auth/client";
import { relativeTime } from "@/lib/utils";

const GROUP = /^[a-z0-9][a-z0-9-]{0,62}$/;

/** Remote runner groups: create a group's token, see whether its runners are alive, revoke. */
export function RunnersCard() {
  const { data, error, mutate } = useRunners();
  const { can } = useAccess();
  const admin = can("POST", "runners/x/token");
  const [group, setGroup] = useState("");
  const [issued, setIssued] = useState<{ group: string; token: string } | null>(null);
  const [busy, setBusy] = useState(false);
  const [failure, setFailure] = useState<Error | null>(null);
  const [revoking, setRevoking] = useState<string | null>(null);

  const create = async (name: string) => {
    setBusy(true);
    setFailure(null);
    try {
      setIssued(await api.runnerToken(name));
      setGroup("");
      await mutate();
    } catch (e) {
      setFailure(e as Error);
    } finally {
      setBusy(false);
    }
  };

  return (
    <Card className="lg:col-span-2">
      <CardHeader>
        <div>
          <CardTitle>Remote runners</CardTitle>
          <CardDescription>
            For devices the engine can&apos;t reach (DMZ, OT, branch sites): a runner inside that network connects out over
            HTTPS and does the work there. Set <code className="font-mono text-xs">&quot;runner&quot;: &quot;group&quot;</code> in an
            endpoint&apos;s connector config.
          </CardDescription>
        </div>
      </CardHeader>
      <CardContent className="space-y-4">
        <ErrorNotice error={error || failure} />
        {!data ? (
          <Skeleton className="h-24" />
        ) : data.length === 0 ? (
          <p className="text-sm text-muted-foreground">No runner groups yet. Every endpoint is reached by the engine itself.</p>
        ) : (
          <Table>
            <THead>
              <TR>
                <TH>Group</TH>
                <TH>Endpoints</TH>
                <TH>Pending jobs</TH>
                <TH>Runner</TH>
                <TH className="text-right">
                  <span className="sr-only">Actions</span>
                </TH>
              </TR>
            </THead>
            <TBody>
              {data.map((g) => {
                return (
                  <TR key={g.group}>
                    <TD className="font-mono text-sm">{g.group}</TD>
                    <TD className="tabular">{g.endpoints}</TD>
                    <TD className="tabular">{g.pending_jobs}</TD>
                    <TD>
                      {!g.token ? (
                        <Badge tone="warning">No token</Badge>
                      ) : g.online ? (
                        <Badge tone="good">Online · {g.version ?? "?"}</Badge>
                      ) : (
                        <Badge tone={g.endpoints ? "critical" : "neutral"}>
                          {g.last_seen ? `Last seen ${relativeTime(g.last_seen)}` : "Never connected"}
                        </Badge>
                      )}
                    </TD>
                    <TD className="text-right">
                      {admin && (
                        <div className="flex justify-end gap-1">
                          <Button size="sm" variant="secondary" disabled={busy} onClick={() => create(g.group)}>
                            {g.token ? "New token" : "Create token"}
                          </Button>
                          {g.token && (
                            <Button size="sm" variant="ghost" onClick={() => setRevoking(g.group)}>
                              Revoke
                            </Button>
                          )}
                        </div>
                      )}
                    </TD>
                  </TR>
                );
              })}
            </TBody>
          </Table>
        )}

        {issued && (
          <div role="status" className="space-y-2 rounded-lg border border-warning/40 bg-warning/5 p-4 text-sm">
            <p className="font-medium">Token for {issued.group}: shown once</p>
            <div className="flex items-center gap-2">
              <code className="min-w-0 flex-1 truncate rounded bg-muted px-2 py-1 font-mono text-xs">{issued.token}</code>
              <CopyButton value={issued.token} label="Copy token" />
            </div>
            <p className="text-muted-foreground">
              On a host inside that network:{" "}
              <code className="font-mono text-xs">FARRIER_RUNNER_TOKEN=… farrier runner start --url https://&lt;engine address&gt;</code>
            </p>
            <Button size="sm" variant="ghost" onClick={() => setIssued(null)}>
              Done
            </Button>
          </div>
        )}

        {admin && (
          <form
            className="flex flex-wrap items-end gap-2"
            onSubmit={(e) => {
              e.preventDefault();
              if (GROUP.test(group)) void create(group);
            }}
          >
            <div className="min-w-48 flex-1">
              <Label htmlFor="runner-group">New group</Label>
              <Input id="runner-group" value={group} onChange={(e) => setGroup(e.target.value.toLowerCase())} placeholder="dmz-frankfurt" className="mt-1 font-mono" />
              {group && !GROUP.test(group) && <FieldHint>Lowercase letters, digits and dashes.</FieldHint>}
            </div>
            <Button type="submit" disabled={busy || !GROUP.test(group)}>
              <Network /> Create group token
            </Button>
          </form>
        )}
      </CardContent>

      <ConfirmDelete
        open={!!revoking}
        onOpenChange={(o) => !o && setRevoking(null)}
        title={`Revoke ${revoking ?? ""}'s token?`}
        onConfirm={async () => {
          if (revoking) await api.revokeRunner(revoking);
          setRevoking(null);
          await mutate();
        }}
      >
        Its runners stop at their next poll. Jobs already queued wait until a runner with a new token picks them up.
      </ConfirmDelete>
    </Card>
  );
}
