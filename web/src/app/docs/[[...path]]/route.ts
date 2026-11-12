import type { NextRequest } from "next/server";
import { docsUrl } from "@/lib/docs";

// /docs/<page> sends the reader to the documentation (FARRIER_DOCS_URL, resolved per request).
// Dashboard links point here as plain <a> tags: a redirect off-site can't be prefetched.
export async function GET(_req: NextRequest, ctx: RouteContext<"/docs/[[...path]]">) {
  const { path = [] } = await ctx.params;
  return Response.redirect(docsUrl(path.join("/")), 307);
}
