/**
 * GET /auth/saml/metadata  This dashboard's SAML service provider metadata (entity id, ACS URL,
 * HTTP-POST binding) for the IdP admin to import. Also the default SP entity id.
 */
import { connection, NextResponse, type NextRequest } from "next/server";
import { authMode, samlConfig } from "@/lib/auth/config";
import { samlSp } from "@/lib/auth/flow";
import { spMetadata } from "@/lib/auth/saml";

export async function GET(req: NextRequest) {
  await connection(); // configuration comes from the runtime environment: never prerender this
  if (authMode() !== "saml") return new NextResponse("SAML is not configured", { status: 404 });
  const cfg = samlConfig();
  if (!cfg.ok) return new NextResponse(`SAML is misconfigured: ${cfg.error}`, { status: 500 });
  return new NextResponse(spMetadata(samlSp(req, cfg.config)), {
    headers: { "content-type": "application/samlmetadata+xml; charset=utf-8", "cache-control": "no-store" },
  });
}
