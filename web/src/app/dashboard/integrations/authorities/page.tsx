import type { Metadata } from "next";
import { AuthoritiesView } from "@/components/dashboard/integrations/authorities-view";

export const metadata: Metadata = { title: "Certificate authorities" };

export default function AuthoritiesPage() {
  return <AuthoritiesView />;
}
