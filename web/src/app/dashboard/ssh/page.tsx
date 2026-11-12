import type { Metadata } from "next";
import { Suspense } from "react";
import { SshView } from "@/components/dashboard/ssh-view";

export const metadata: Metadata = { title: "SSH keys" };

export default function SshPage() {
  return (
    // the Keys / Hosts / Access tab lives in ?tab=, read with useSearchParams
    <Suspense>
      <SshView />
    </Suspense>
  );
}
