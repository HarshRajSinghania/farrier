import { DocsBreadcrumbs, DocsPager, DocsSidebar, DocsToc } from "@/components/docs/docs-chrome";
import { SiteFooter } from "@/components/site/footer";
import { SiteHeader } from "@/components/site/header";
import { buildDocsIndex } from "@/lib/docs-index";

// built once, at build time, from the MDX sources
const index = buildDocsIndex();

export default function DocsLayout({ children }: { children: React.ReactNode }) {
  return (
    <>
      <SiteHeader />
      <div className="mx-auto flex w-full max-w-7xl flex-col px-4 sm:px-6 lg:flex-row lg:gap-10">
        <DocsSidebar index={index} />
        <main className="min-w-0 flex-1 py-8 lg:py-10">
          <DocsBreadcrumbs />
          <article className="docs-prose prose prose-zinc max-w-[70ch] dark:prose-invert prose-p:leading-[1.6] prose-li:leading-[1.6] prose-headings:scroll-mt-20 prose-headings:tracking-tight prose-h1:text-4xl prose-h1:font-semibold prose-h2:mt-14 prose-h2:border-t prose-h2:pt-10 prose-h2:text-3xl prose-h2:font-semibold prose-h3:text-2xl prose-a:font-medium prose-a:text-foreground prose-a:underline prose-a:decoration-foreground/30 prose-a:underline-offset-4 hover:prose-a:decoration-foreground prose-code:rounded prose-code:bg-muted prose-code:px-2 prose-code:py-1 prose-code:text-[0.85em] prose-code:font-normal prose-code:before:content-none prose-code:after:content-none prose-th:text-left prose-table:text-sm">
            {children}
          </article>
          <div className="max-w-3xl">
            <DocsPager />
          </div>
        </main>
        <DocsToc />
      </div>
      <SiteFooter cta={false} />
    </>
  );
}
