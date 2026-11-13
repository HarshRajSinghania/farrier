import type { Metadata } from "next";
import Link from "next/link";
import { SiteFooter } from "@/components/site/footer";
import { SiteHeader } from "@/components/site/header";
import { SOLUTIONS } from "@/lib/solutions";

export const metadata: Metadata = {
  title: "Solutions",
  description:
    "Certificate automation for F5, FortiGate, Palo Alto, AWS Certificate Manager, AWS Private CA, Google CAS and the 47-day certificate schedule.",
  alternates: { canonical: "/solutions/" },
};

export default function Solutions() {
  return (
    <div data-landing className="flex min-h-full flex-col bg-background">
      <SiteHeader />
      <main className="mx-auto w-full max-w-4xl flex-1 px-4 pt-32 pb-16 sm:px-6">
        <h1 className="text-[36px] font-semibold leading-[1.08] tracking-[-0.03em] sm:text-[52px]">Solutions</h1>
        <p className="mt-4 max-w-[65ch] text-lg text-muted-foreground">
          What Farrier automates, device by device and CA by CA.
        </p>
        <ul className="mt-12 grid gap-4 sm:grid-cols-2">
          {SOLUTIONS.map((s) => (
            <li key={s.slug}>
              <Link href={`/solutions/${s.slug}`} className="block h-full rounded-2xl border p-6 transition-colors hover:bg-muted">
                <h2 className="text-lg font-semibold">{s.title}</h2>
                <p className="mt-2 text-sm text-muted-foreground">{s.description}</p>
              </Link>
            </li>
          ))}
        </ul>
      </main>
      <SiteFooter />
    </div>
  );
}
