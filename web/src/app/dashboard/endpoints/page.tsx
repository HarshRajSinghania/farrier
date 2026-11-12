import type { Metadata } from "next";
import { Suspense } from "react";
import { EndpointsView } from "@/components/dashboard/endpoints-view";

export const metadata: Metadata = { title: "Certificates" };

export default function EndpointsPage() {
  return (
    <Suspense>
      <EndpointsView />
    </Suspense>
  );
}
