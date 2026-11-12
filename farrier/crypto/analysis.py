"""Post-quantum readiness and weak-crypto findings from a probe result (pure; no I/O).

PQC status:
  ready       PQC key exchange negotiated AND a PQC or composite (hybrid) certificate signature
  hybrid      PQC key exchange negotiated, classical certificate
  vulnerable  classical key exchange only (harvest-now-decrypt-later exposure)
  unknown     never probed, or the probe could not complete
"""
from __future__ import annotations

from datetime import UTC, datetime

from farrier.crypto.algorithms import key_label, pqc_signature_name

STATUSES = ("ready", "hybrid", "vulnerable", "unknown")
WEAK_FLAGS = ("tls10", "tls11", "rsa_lt_2048", "sha1", "cbc", "3des", "rc4", "expired")


def _accepted(result: dict, version: str) -> bool:
    return bool((result.get("versions") or {}).get(version, {}).get("accepted"))


def protocol_versions(result: dict) -> list[str]:
    return [v for v in ("TLSv1.0", "TLSv1.1", "TLSv1.2", "TLSv1.3") if _accepted(result, v)]


def cipher_suites(result: dict) -> dict[str, str]:
    """Negotiated suite per accepted version."""
    return {v: c for v, info in (result.get("versions") or {}).items() if (c := info.get("cipher"))}


def _all_suites(result: dict) -> list[str]:
    return [*cipher_suites(result).values(), *([result["weak_cipher"]] if result.get("weak_cipher") else [])]


def key_exchange(result: dict) -> str | None:
    """The key exchange a modern client gets: the TLS 1.3 group, else what the TLS 1.2 suite implies."""
    if result.get("pqc", {}).get("selected"):
        return result["pqc"].get("group")
    if result.get("tls13_group"):
        return result["tls13_group"]
    for v in ("TLSv1.2", "TLSv1.1", "TLSv1.0"):
        suite = (result.get("versions") or {}).get(v, {}).get("cipher") or ""
        if suite:
            return "ECDHE" if "_ECDHE_" in suite else "DHE" if "_DHE_" in suite else "RSA" if "TLS_RSA_" in suite else None
    return None


def probed(result: dict | None) -> bool:
    return bool(result) and not result.get("error") and bool(protocol_versions(result))


def weak_flags(result: dict, now: datetime | None = None) -> list[str]:
    now = now or datetime.now(UTC)
    flags: list[str] = []
    if _accepted(result, "TLSv1.0"):
        flags.append("tls10")
    if _accepted(result, "TLSv1.1"):
        flags.append("tls11")
    cert = result.get("certificate") or {}
    key = cert.get("key") or {}
    if key.get("algorithm") == "RSA" and (key.get("size") or 0) < 2048:
        flags.append("rsa_lt_2048")
    if cert.get("sha1_signed") or cert.get("sha1_in_chain"):
        flags.append("sha1")
    suites = _all_suites(result)
    if any("_CBC_" in s and "3DES" not in s for s in suites):
        flags.append("cbc")
    if any("3DES" in s for s in suites):
        flags.append("3des")
    if any("RC4" in s for s in suites):
        flags.append("rc4")
    if cert.get("not_after") and datetime.fromisoformat(cert["not_after"]) < now:
        flags.append("expired")
    return flags


def classify(result: dict | None) -> dict:
    """{status, reasons} for one probe result."""
    if not result:
        return {"status": "unknown", "reasons": ["not scanned"]}
    if result.get("error"):
        return {"status": "unknown", "reasons": [f"probe failed: {result['error']}"]}
    if not protocol_versions(result):
        return {"status": "unknown", "reasons": ["no TLS version could be negotiated"]}
    reasons: list[str] = []
    pqc_kx = bool(result.get("pqc", {}).get("selected"))
    cert = result.get("certificate") or {}
    pqc_sig = bool(cert) and (pqc_signature_name(cert.get("signature_oid") or "") is not None)

    if pqc_kx:
        reasons.append(f"{result['pqc'].get('group')} key exchange accepted")
    else:
        kx = key_exchange(result)
        if not _accepted(result, "TLSv1.3"):
            reasons.append("TLS 1.3 not supported (no post-quantum key exchange possible)")
        reasons.append(f"{kx} key exchange only" if kx else "classical key exchange only")
    if cert:
        label = key_label(cert.get("key"))
        if pqc_sig:
            reasons.append(f"post-quantum certificate signature ({cert.get('signature_algorithm')})")
        else:
            reasons.append(f"{label} certificate" if label else "classical certificate")
    else:
        reasons.append("certificate not seen")
    flags = weak_flags(result)
    for flag, text in (("tls10", "TLS 1.0 accepted"), ("tls11", "TLS 1.1 accepted"),
                       ("rsa_lt_2048", "RSA key under 2048 bits"), ("sha1", "SHA-1 signature in chain"),
                       ("cbc", "CBC cipher suite accepted"), ("3des", "3DES cipher suite accepted"),
                       ("rc4", "RC4 cipher suite accepted"), ("expired", "certificate expired")):
        if flag in flags:
            reasons.append(text)

    status = ("ready" if pqc_sig else "hybrid") if pqc_kx else "vulnerable"
    return {"status": status, "reasons": reasons}


def asset_view(asset_id: int, result: dict, endpoint_id: int | None) -> dict:
    """The API shape of one stored TLS asset."""
    cert = result.get("certificate")
    key = (cert or {}).get("key")
    return {
        "id": asset_id, "kind": result.get("kind", "tls"), "endpoint_id": endpoint_id, "target": result["target"],
        "protocol_versions": protocol_versions(result), "cipher_suites": cipher_suites(result),
        "key_exchange": key_exchange(result), "pqc_key_exchange": bool(result.get("pqc", {}).get("selected")),
        "pqc_probe": {k: result.get("pqc", {}).get(k) for k in ("group", "outcome", "detail")},
        "cert_key": {"algorithm": key["algorithm"], "size": key.get("size")} if key else None,
        "signature_algorithm": (cert or {}).get("signature_algorithm"),
        "pqc": classify(result), "weak": weak_flags(result), "observed_at": result.get("observed_at"),
        "error": result.get("error"),
    }


def summarize(assets: list[dict]) -> dict:
    """Totals over asset views (TLS and, when present, SSH)."""
    by_status = dict.fromkeys(STATUSES, 0)
    by_key: dict[str, int] = {}
    weak = {"tls10": 0, "tls11": 0, "rsa_lt_2048": 0, "sha1": 0}
    for a in assets:
        status = (a.get("pqc") or {}).get("status", "unknown")
        by_status[status if status in by_status else "unknown"] += 1
        alg = (a.get("cert_key") or {}).get("algorithm") or "unknown"
        by_key[alg] = by_key.get(alg, 0) + 1
        for w in a.get("weak") or []:
            if w in weak:
                weak[w] += 1
    return {"total": len(assets), "by_status": by_status, "by_key_algorithm": dict(sorted(by_key.items())),
            "weak": weak}
