import type { Metadata } from "next";
import { Suspense } from "react";
import { EndpointsView } from "@/components/dashboard/endpoints-view";

export const metadata: Metadata = { title: "Endpoints" };

export default function EndpointsPage() {
  return (
    <Suspense>
      <EndpointsView />
    </Suspense>
  );
}
