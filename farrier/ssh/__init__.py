"""Agentless SSH: host discovery without login, authorized-key inventory and removal with a stored
access profile, and SSH servers as cryptographic assets.

    probe.py            unauthenticated banner/KEXINIT/host-key probe (stdlib sockets + cryptography)
    wire.py, keys.py    SSH wire format and public keys (pure)
    authorized_keys.py  authorized_keys / sshd_config / passwd parsers (pure)
    findings.py         the findings table (pure)
    access.py           access profiles (dashboard config, secret references only)
    transport.py        commands over the system ssh client with pinned host keys
    collect.py          collection, TOFU pinning, removal
    scan.py, db.py      discovery persistence and storage
    schedule.py         leader-only periodic scan and collection
"""
from __future__ import annotations


def _strongest(host_keys: list[dict]) -> dict | None:
    from farrier.ssh.keys import PublicKey
    best = None
    for k in host_keys:
        pk = PublicKey(k["type"], k.get("bits") or 0, b"")
        if best is None or pk.strength > best.strength:
            best = pk
    # the crypto inventory names elliptic-curve keys "EC" (as X.509 does); one name per family across TLS and SSH
    return {"algorithm": "EC" if best.algorithm == "ECDSA" else best.algorithm, "size": best.bits} if best else None


def ssh_crypto_assets(store) -> list[dict]:
    """One asset per discovered SSH server, in the crypto inventory/CBOM shape."""
    from farrier.ssh import db
    from farrier.ssh.findings import PQC_KEX
    out = []
    for h in db.hosts(store):
        kex = h.get("kex") or []
        pqc = bool(h.get("pqc_kex"))
        hybrid = [k for k in kex if k in PQC_KEX]
        reasons = ([f"hybrid post-quantum key exchange offered: {', '.join(hybrid)}"] if pqc else
                   ["no post-quantum key exchange offered; recorded sessions are exposed to harvest-now-decrypt-later"])
        if h.get("host_keys"):
            reasons.append("host keys use classical signatures (" +
                           ", ".join(sorted({k["type"] for k in h["host_keys"]})) + ")")
        out.append({
            "id": f"ssh-{h['id']}", "kind": "ssh", "endpoint_id": None, "target": f"{h['host']}:{h['port']}",
            "protocol_versions": ["SSH-2.0"], "cipher_suites": h.get("ciphers") or [], "key_exchange": kex,
            "pqc_key_exchange": pqc, "cert_key": _strongest(h.get("host_keys") or []), "signature_algorithm": None,
            "pqc": {"status": "hybrid" if pqc else "vulnerable", "reasons": reasons},
            "weak": [f["detail"] for f in h.get("findings") or [] if f["severity"] in ("critical", "warning")],
            "observed_at": h["observed_at"],
        })
    return out


__all__ = ["ssh_crypto_assets"]
