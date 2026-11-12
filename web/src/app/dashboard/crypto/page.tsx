import type { Metadata } from "next";
import { CryptoView } from "@/components/dashboard/crypto-view";

export const metadata: Metadata = { title: "Crypto & PQC" };

export default function CryptoPage() {
  return <CryptoView />;
}
