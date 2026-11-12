/** Liveness probe for containers and load balancers. Does not touch the Farrier API. */
export function GET() {
  return Response.json({ ok: true });
}
