"""Certificate details and cryptographic discovery API.

  GET  /api/endpoints/{id}/certificate   stored certificate facts, history, renewals, health grade
  GET  /api/crypto/assets                every probed asset (TLS, plus SSH when farrier.ssh provides them)
  GET  /api/crypto/summary               totals by PQC status, key algorithm and weak-crypto flag
  POST /api/crypto/scan  {targets}       admin: probe targets (discovery syntax and limits) and store results
  GET  /api/crypto/cbom                  CycloneDX 1.6 CBOM of every stored asset

Reads accept the read token; the shared auth dependency refuses POST with it. Everything is filtered to
the caller's projects (farrier.api.scope): a TLS asset belongs to its inventory endpoint's project, or to
the project it was scanned into; an SSH asset to its host's.
"""
from __future__ import annotations

from fastapi import Depends, HTTPException, Request
from pydantic import BaseModel

from farrier.api.scope import Guard
from farrier.core.discovery import expand_targets
from farrier.crypto import certificate, repository, service
from farrier.crypto.analysis import summarize
from farrier.crypto.cbom import build_cbom


class CryptoScanIn(BaseModel):
    targets: str
    project: str | None = None      # where newly found assets go


def mount(app, engine, auth, actor) -> None:
    S = engine.store
    dep = [Depends(auth)]
    guard = Guard(S)

    def visible(request: Request) -> list[dict]:
        assets = service.all_assets(S)
        sc = guard.of(request)
        if sc.all:
            return assets
        tls, _ = repository.owners(S)
        ssh = {f"ssh-{r['id']}": r["project_id"] for r in S.q("SELECT id, project_id FROM ssh_hosts")}
        owner = {**tls, **ssh}
        return [a for a in assets if a["id"] in owner and sc.has(owner[a["id"]])]

    @app.get("/api/endpoints/{eid}/certificate", dependencies=dep)
    def endpoint_certificate(eid: int, request: Request):
        return certificate.details(S, guard.endpoint(request, eid))

    @app.get("/api/crypto/assets", dependencies=dep)
    def crypto_assets(request: Request):
        return visible(request)

    @app.get("/api/crypto/summary", dependencies=dep)
    def crypto_summary(request: Request):
        return summarize(visible(request))

    @app.get("/api/crypto/cbom", dependencies=dep)
    def crypto_cbom(request: Request):
        if guard.of(request).all:
            return service.cbom(S)
        from farrier import __version__
        assets = visible(request)
        ids = {a["id"] for a in assets}
        return build_cbom(assets, {i: r for i, r in repository.raw_results(S) if i in ids}, version=__version__)

    @app.post("/api/crypto/scan", dependencies=dep)
    def crypto_scan(body: CryptoScanIn, request: Request):
        pid = guard.project_id(request, body.project)
        sc = guard.of(request)
        try:
            targets = expand_targets(body.targets, limit=service.MAX_TARGETS)
        except ValueError as e:
            raise HTTPException(400, str(e))
        if not targets:
            raise HTTPException(400, "no targets")
        if len(targets) > service.MAX_TARGETS:
            raise HTTPException(400, f"{len(targets)} targets; split the range (max {service.MAX_TARGETS} per request)")
        out = service.scan_targets(S, targets, timeout=float(engine.settings.get("scan_timeout", 5.0)),
                                   project_id=pid, allowed=None if sc.all else sc.has)
        S.log(f"crypto scan of {len(targets)} targets by {actor(request)}")
        return out
