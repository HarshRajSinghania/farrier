import type { Metadata } from "next";
import { Suspense } from "react";
import { RenewalsView } from "@/components/dashboard/renewals-view";

export const metadata: Metadata = { title: "Renewals" };

export default function RenewalsPage() {
  return (
    <Suspense>
      <RenewalsView />
    </Suspense>
  );
}
