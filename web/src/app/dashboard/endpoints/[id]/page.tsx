import type { Metadata } from "next";
import { Suspense } from "react";
import { CertificateView } from "@/components/dashboard/certificate-view";

export const metadata: Metadata = { title: "Certificate" };

export default function CertificatePage() {
  return (
    // the endpoint id is read in the client view with useParams
    <Suspense>
      <CertificateView />
    </Suspense>
  );
}
