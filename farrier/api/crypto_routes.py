"""Certificate details and cryptographic discovery API.

  GET  /api/endpoints/{id}/certificate   stored certificate facts, history, renewals, health grade
  GET  /api/crypto/assets                every probed asset (TLS, plus SSH when farrier.ssh provides them)
  GET  /api/crypto/summary               totals by PQC status, key algorithm and weak-crypto flag
  POST /api/crypto/scan  {targets}       admin: probe targets (discovery syntax and limits) and store results
  GET  /api/crypto/cbom                  CycloneDX 1.6 CBOM of every stored asset

Reads accept the read token; the shared auth dependency refuses POST with it.
"""
from __future__ import annotations

from fastapi import Depends, HTTPException, Request
from pydantic import BaseModel

from farrier.core.discovery import expand_targets
from farrier.crypto import certificate, service


class CryptoScanIn(BaseModel):
    targets: str


def mount(app, engine, auth, actor) -> None:
    S = engine.store
    dep = [Depends(auth)]

    @app.get("/api/endpoints/{eid}/certificate", dependencies=dep)
    def endpoint_certificate(eid: int):
        ep = S.endpoint(eid)
        if not ep:
            raise HTTPException(404)
        return certificate.details(S, ep)

    @app.get("/api/crypto/assets", dependencies=dep)
    def crypto_assets():
        return service.all_assets(S)

    @app.get("/api/crypto/summary", dependencies=dep)
    def crypto_summary():
        return service.summary(S)

    @app.get("/api/crypto/cbom", dependencies=dep)
    def crypto_cbom():
        return service.cbom(S)

    @app.post("/api/crypto/scan", dependencies=dep)
    def crypto_scan(body: CryptoScanIn, request: Request):
        try:
            targets = expand_targets(body.targets, limit=service.MAX_TARGETS)
        except ValueError as e:
            raise HTTPException(400, str(e))
        if not targets:
            raise HTTPException(400, "no targets")
        if len(targets) > service.MAX_TARGETS:
            raise HTTPException(400, f"{len(targets)} targets; split the range (max {service.MAX_TARGETS} per request)")
        out = service.scan_targets(S, targets, timeout=float(engine.settings.get("scan_timeout", 5.0)))
        S.log(f"crypto scan of {len(targets)} targets by {actor(request)}")
        return out
