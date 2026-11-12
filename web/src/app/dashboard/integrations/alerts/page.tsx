import type { Metadata } from "next";
import { Suspense } from "react";
import { AlertsView } from "@/components/dashboard/integrations/alerts-view";

export const metadata: Metadata = { title: "Alerts" };

export default function AlertsPage() {
  return (
    // the Rules / Channels tab lives in ?tab=, read with useSearchParams
    <Suspense>
      <AlertsView />
    </Suspense>
  );
}
