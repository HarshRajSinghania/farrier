"""Certificate details for one endpoint, from stored observations only (no live probe).

The PEM (and the chain the server sent) is stored once per fingerprint since migration 5; for
certificates observed before that, the fields only the PEM can give (serial, fingerprints other than
SHA-256, key size, signature algorithm, chain) come back as null.
"""
from __future__ import annotations

from cryptography import x509

from farrier.core import policy
from farrier.core.x509util import split_pem_chain
from farrier.crypto.algorithms import (
    common_name,
    fingerprints,
    is_self_signed,
    key_info,
    signature_name,
)
from farrier.db.store import parse_dt


def _cert_line(c: x509.Certificate) -> dict:
    return {"subject": c.subject.rfc4514_string(), "issuer": c.issuer.rfc4514_string(),
            "not_after": c.not_valid_after_utc.isoformat(), "key": key_info(c), "signature_algorithm": signature_name(c)}


def _key_from_label(label: str | None) -> dict | None:
    """Best effort from the stored key_type ('RSA-2048', 'EC-secp256r1', 'Ed25519PublicKey')."""
    if not label:
        return None
    alg, _, rest = label.partition("-")
    if alg == "RSA" and rest.isdigit():
        return {"algorithm": "RSA", "size": int(rest), "curve": None}
    if alg == "EC" and rest:
        digits = "".join(ch for ch in rest if ch.isdigit())[:3]     # secp384r1 -> 384
        return {"algorithm": "EC", "size": int(digits) if digits else None, "curve": rest}
    return {"algorithm": label.replace("PublicKey", ""), "size": None, "curve": None}


def history(store, endpoint_id: int, limit: int = 20) -> list[dict]:
    rows = store.q("""SELECT fingerprint, MAX(observed_at) AS observed_at, MAX(not_after) AS not_after,
                             MAX(issuer) AS issuer
                      FROM observations WHERE endpoint_id=? AND fingerprint IS NOT NULL
                      GROUP BY fingerprint ORDER BY MAX(observed_at) DESC LIMIT ?""", (endpoint_id, limit))
    return [{"observed_at": r["observed_at"], "fingerprint_sha256": r["fingerprint"], "not_after": r["not_after"],
             "issuer": r["issuer"]} for r in rows]


def renewals(store, endpoint_id: int, limit: int = 10) -> list[dict]:
    return store.q("""SELECT id, state, reason, scheduled_for, updated_at FROM renewals WHERE endpoint_id=?
                      ORDER BY id DESC LIMIT ?""", (endpoint_id, limit))


def health(store, endpoint_id: int) -> dict | None:
    return store.q1("SELECT grade, checked_at FROM health_results WHERE endpoint_id=?", (endpoint_id,))


def details(store, endpoint: dict) -> dict:
    eid = endpoint["id"]
    obs = store.latest_cert_observation(eid)
    out: dict = {"endpoint_id": eid, "subject": None, "common_name": None, "sans": [], "issuer": None, "serial": None,
                 "not_before": None, "not_after": None, "days_left": None, "key": None, "signature_algorithm": None,
                 "fingerprints": {"sha256": None, "sha1": None}, "chain": [], "self_signed": None,
                 "observed_at": None}
    if obs:
        na = parse_dt(obs["not_after"])
        out |= {"common_name": obs["subject_cn"], "sans": obs["sans"] or [], "issuer": obs["issuer"],
                "not_before": obs["not_before"], "not_after": obs["not_after"],
                "days_left": round(policy.days_left(na), 1) if na else None,
                "key": _key_from_label(obs["key_type"]), "observed_at": obs["observed_at"],
                "fingerprints": {"sha256": obs["fingerprint"], "sha1": None}}
        pems = store.certificate_pems(obs["fingerprint"])
        if pems:
            leaf = x509.load_pem_x509_certificate(pems["cert_pem"].encode())
            chain = [x509.load_pem_x509_certificate(p.encode()) for p in split_pem_chain(pems["chain_pem"] or "")]
            out |= {"subject": leaf.subject.rfc4514_string(), "common_name": common_name(leaf.subject) or obs["subject_cn"],
                    "issuer": leaf.issuer.rfc4514_string(), "serial": format(leaf.serial_number, "x"),
                    "key": key_info(leaf), "signature_algorithm": signature_name(leaf),
                    "fingerprints": fingerprints(leaf), "chain": [_cert_line(c) for c in chain],
                    "self_signed": is_self_signed(leaf)}
    out |= {"history": history(store, eid), "renewals": renewals(store, eid), "health": health(store, eid)}
    return out
