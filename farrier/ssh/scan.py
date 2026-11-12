"""Host discovery (no login): probe targets, compute findings, store one row per reachable host:port."""
from __future__ import annotations

from collections.abc import Callable

from farrier.ssh import db
from farrier.ssh.findings import host_findings, offers_pqc, real_kex
from farrier.ssh.probe import ProbeResult, probe_many

Prober = Callable[[list[tuple[str, int]]], list[ProbeResult]]


def host_record(res: ProbeResult) -> dict:
    """The stored/served shape of one probe (without id, host, port, observed_at)."""
    kx = res.kexinit
    return {
        "host_keys": [{"type": k.type, "bits": k.bits, "fingerprint_sha256": k.fingerprint_sha256}
                      for k in res.host_keys],
        "kex": real_kex(kx.kex) if kx else [],
        "kex_extensions": [k for k in kx.kex if k not in real_kex(kx.kex)] if kx else [],
        "host_key_algorithms": kx.host_key if kx else [],
        "ciphers": kx.ciphers if kx else [],
        "macs": kx.macs if kx else [],
        "compression": kx.compression if kx else [],
        "findings": host_findings(res.banner, kx, res.host_keys),
        "host_key_method": res.method,
        "notes": res.notes,
    }


def save_probe(store, res: ProbeResult) -> int | None:
    """Store a probe. An unreachable target is stored only if the host was known before (so a scan of a
    whole range doesn't fill the inventory with empty rows)."""
    old = db.host_by_addr(store, res.host, res.port)
    if res.banner is None:
        if not old:
            return None
        data = {k: old.get(k) for k in host_record(res)} | {"accounts": old.get("accounts")}
        return db.save_host(store, res.host, res.port, old.get("banner"), data, bool(old.get("pqc_kex")), res.error)
    data = host_record(res)
    if old and old.get("accounts") is not None:
        data["accounts"] = old["accounts"]          # learned by collection; a probe can't see them
    pqc = bool(res.kexinit and offers_pqc(res.kexinit.kex))
    return db.save_host(store, res.host, res.port, res.banner.raw, data, pqc, res.error)


def scan(store, targets: list[tuple[str, int]], prober: Prober = probe_many) -> dict:
    results = prober(targets)
    saved = [hid for r in results if (hid := save_probe(store, r)) is not None]
    return {"scanned": len(targets), "ssh": sum(1 for r in results if r.banner), "saved": len(saved),
            "errors": [{"host": r.host, "port": r.port, "error": r.error} for r in results if r.error and r.banner is None
                       and len(targets) <= 64]}


def host_view(h: dict) -> dict:
    return {"id": h["id"], "host": h["host"], "port": h["port"], "banner": h.get("banner"),
            "host_keys": h.get("host_keys") or [], "kex": h.get("kex") or [], "ciphers": h.get("ciphers") or [],
            "macs": h.get("macs") or [], "host_key_algorithms": h.get("host_key_algorithms") or [],
            "compression": h.get("compression") or [], "pqc_kex": bool(h.get("pqc_kex")),
            "findings": h.get("findings") or [], "host_key_method": h.get("host_key_method"),
            "error": h.get("error"), "observed_at": h["observed_at"]}
