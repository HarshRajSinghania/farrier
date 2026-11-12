import type { Metadata } from "next";
import { DnsView } from "@/components/dashboard/integrations/dns-view";

export const metadata: Metadata = { title: "DNS accounts" };

export default function DnsPage() {
  return <DnsView />;
}
