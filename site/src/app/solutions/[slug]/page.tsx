import type { Metadata } from "next";
import Link from "next/link";
import { notFound } from "next/navigation";
import { ArrowRight, Check } from "lucide-react";
import { JsonLd } from "@/components/site/json-ld";
import { SiteFooter } from "@/components/site/footer";
import { SiteHeader } from "@/components/site/header";
import { SOLUTIONS, solution } from "@/lib/solutions";
import { site } from "@/lib/site";

type Props = { params: Promise<{ slug: string }> };

export const dynamicParams = false;

export function generateStaticParams() {
  return SOLUTIONS.map(({ slug }) => ({ slug }));
}

export async function generateMetadata({ params }: Props): Promise<Metadata> {
  const s = solution((await params).slug);
  if (!s) return {};
  const path = `/solutions/${s.slug}/`;
  return {
    title: s.title,
    description: s.description,
    keywords: s.keywords,
    alternates: { canonical: path },
    openGraph: { type: "article", title: s.h1, description: s.description, url: path, siteName: site.name },
    twitter: { card: "summary_large_image", title: s.h1, description: s.description },
  };
}

export default async function SolutionPage({ params }: Props) {
  const s = solution((await params).slug);
  if (!s) notFound();
  const url = `${site.url}/solutions/${s.slug}/`;
  return (
    <div data-landing className="flex min-h-full flex-col bg-background">
      <JsonLd
        data={[
          {
            "@context": "https://schema.org",
            "@type": "FAQPage",
            mainEntity: s.faq.map(([q, a]) => ({ "@type": "Question", name: q, acceptedAnswer: { "@type": "Answer", text: a } })),
          },
          {
            "@context": "https://schema.org",
            "@type": "BreadcrumbList",
            itemListElement: [
              { "@type": "ListItem", position: 1, name: site.name, item: `${site.url}/` },
              { "@type": "ListItem", position: 2, name: "Solutions", item: `${site.url}/solutions/` },
              { "@type": "ListItem", position: 3, name: s.title, item: url },
            ],
          },
        ]}
      />
      <SiteHeader />
      <main className="mx-auto w-full max-w-4xl flex-1 px-4 pt-32 pb-16 sm:px-6">
        <nav aria-label="Breadcrumb" className="text-sm text-muted-foreground">
          <Link href="/solutions" className="hover:text-foreground">Solutions</Link> <span aria-hidden>/</span> {s.title}
        </nav>
        <h1 className="mt-4 text-[36px] font-semibold leading-[1.08] tracking-[-0.03em] text-balance sm:text-[52px]">{s.h1}</h1>
        <p className="mt-6 max-w-[65ch] text-lg text-muted-foreground">{s.problem}</p>
        <div className="mt-8 flex flex-wrap gap-2">
          <Link href="/docs/install" className="inline-flex h-11 items-center rounded-full bg-foreground px-5 text-[15px] font-semibold text-background hover:opacity-90">
            Install Farrier
          </Link>
          <Link href={s.docs.href} className="inline-flex h-11 items-center gap-1 rounded-full px-5 text-[15px] font-semibold ring-1 ring-inset ring-border hover:bg-muted">
            {s.docs.label} <ArrowRight className="size-4" />
          </Link>
        </div>

        <h2 className="mt-20 text-[28px] font-semibold tracking-[-0.02em]">How Farrier does it</h2>
        <ol className="mt-6 grid gap-4 sm:grid-cols-2">
          {s.steps.map((step, i) => (
            <li key={step.title} className="rounded-2xl border p-6">
              <p className="font-mono text-sm text-muted-foreground">{String(i + 1).padStart(2, "0")}</p>
              <h3 className="mt-2 text-lg font-semibold">{step.title}</h3>
              <p className="mt-2 text-muted-foreground">{step.body}</p>
            </li>
          ))}
        </ol>

        <ul className="mt-10 space-y-3">
          {s.points.map((p) => (
            <li key={p} className="flex gap-3">
              <Check className="mt-1 size-4 shrink-0 text-[#2563eb]" aria-hidden />
              <span>{p}</span>
            </li>
          ))}
        </ul>

        <h2 className="mt-20 text-[28px] font-semibold tracking-[-0.02em]">Questions</h2>
        <dl className="mt-6 divide-y border-y">
          {s.faq.map(([q, a]) => (
            <div key={q} className="py-5">
              <dt className="font-medium">{q}</dt>
              <dd className="mt-2 text-muted-foreground">{a}</dd>
            </div>
          ))}
        </dl>

        <h2 className="mt-20 text-[28px] font-semibold tracking-[-0.02em]">More from Farrier</h2>
        <ul className="mt-6 grid gap-2 sm:grid-cols-2">
          {SOLUTIONS.filter((o) => o.slug !== s.slug).map((o) => (
            <li key={o.slug}>
              <Link href={`/solutions/${o.slug}`} className="text-[#2563eb] hover:underline">{o.title}</Link>
            </li>
          ))}
        </ul>
      </main>
      <SiteFooter />
    </div>
  );
}
