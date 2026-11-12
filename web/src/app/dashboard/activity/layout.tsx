import type { Metadata } from "next";

// page.tsx is a client component, so its title lives here
export const metadata: Metadata = { title: "Activity" };

export default function Layout({ children }: { children: React.ReactNode }) {
  return children;
}
