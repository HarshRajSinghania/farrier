import { SiteFooter } from "@/components/site/footer";
import { SiteHeader } from "@/components/site/header";

export default function LegalLayout({ children }: { children: React.ReactNode }) {
  return (
    <>
      <SiteHeader />
      <main className="mx-auto w-full max-w-3xl flex-1 px-4 py-12 sm:px-6 lg:py-16">
        <article className="prose prose-zinc max-w-none dark:prose-invert prose-headings:tracking-tight prose-h1:text-3xl prose-h1:font-semibold prose-h2:mt-10 prose-h2:text-xl prose-h2:font-semibold prose-a:font-medium prose-a:text-foreground prose-a:underline-offset-4 prose-code:rounded prose-code:bg-muted prose-code:px-1 prose-code:py-1 prose-code:font-normal prose-code:before:content-none prose-code:after:content-none">
          {children}
        </article>
      </main>
      <SiteFooter cta={false} />
    </>
  );
}
