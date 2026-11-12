import type { Metadata } from "next";

// page.tsx is a client component, so its title lives here
export const metadata: Metadata = { title: "Forecast" };

export default function Layout({ children }: { children: React.ReactNode }) {
  return children;
}
