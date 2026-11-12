"""Certificate key and signature facts, described the same way everywhere (pure; no I/O)."""
from __future__ import annotations

import hashlib
from typing import TypedDict

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa
from cryptography.x509.oid import NameOID

# FIPS 204 ML-DSA and FIPS 205 SLH-DSA (NIST CSOR), and composite ML-DSA (draft-ietf-lamps-pq-composite-sigs)
ML_DSA_OIDS = {"2.16.840.1.101.3.4.3.17": "ML-DSA-44", "2.16.840.1.101.3.4.3.18": "ML-DSA-65",
               "2.16.840.1.101.3.4.3.19": "ML-DSA-87"}
SLH_DSA_OIDS = {f"2.16.840.1.101.3.4.3.{n}": f"SLH-DSA-{i}" for i, n in enumerate(range(20, 32))}
COMPOSITE_PREFIXES = ("1.3.6.1.5.5.7.6.", "2.16.840.1.114027.80.8.1.")
COMPOSITE_RANGE = range(37, 55)    # id-MLDSA44-RSA2048-PSS-SHA256 ... in the 1.3.6.1.5.5.7.6 arc


class KeyInfo(TypedDict):
    algorithm: str
    size: int | None
    curve: str | None


def pqc_signature_name(oid: str) -> str | None:
    """The PQC or composite (hybrid) signature algorithm an OID names, else None."""
    if oid in ML_DSA_OIDS:
        return ML_DSA_OIDS[oid]
    if oid in SLH_DSA_OIDS:
        return SLH_DSA_OIDS[oid]
    if oid.startswith(COMPOSITE_PREFIXES[1]):
        return f"composite-{oid.rsplit('.', 1)[1]}"
    if oid.startswith(COMPOSITE_PREFIXES[0]):
        tail = oid[len(COMPOSITE_PREFIXES[0]):]
        if tail.isdigit() and int(tail) in COMPOSITE_RANGE:
            return f"composite-{tail}"
    return None


def key_info(cert: x509.Certificate) -> KeyInfo:
    oid = getattr(cert, "public_key_algorithm_oid", None)
    if oid is not None and (pq := pqc_signature_name(oid.dotted_string)):
        return {"algorithm": pq, "size": None, "curve": None}
    try:
        pub = cert.public_key()
    except Exception:  # noqa: BLE001 - a key type this cryptography build cannot load
        name = (oid._name if oid is not None and oid._name != "Unknown OID" else
                oid.dotted_string if oid is not None else "unknown")
        return {"algorithm": name, "size": None, "curve": None}
    if isinstance(pub, rsa.RSAPublicKey):
        return {"algorithm": "RSA", "size": pub.key_size, "curve": None}
    if isinstance(pub, ec.EllipticCurvePublicKey):
        return {"algorithm": "EC", "size": pub.curve.key_size, "curve": pub.curve.name}
    if isinstance(pub, ed25519.Ed25519PublicKey):
        return {"algorithm": "Ed25519", "size": 256, "curve": None}
    if isinstance(pub, ed448.Ed448PublicKey):
        return {"algorithm": "Ed448", "size": 456, "curve": None}
    if isinstance(pub, dsa.DSAPublicKey):
        return {"algorithm": "DSA", "size": pub.key_size, "curve": None}
    return {"algorithm": type(pub).__name__.replace("PublicKey", ""), "size": None, "curve": None}


def key_label(key: KeyInfo | dict | None) -> str | None:
    """'RSA-2048', 'EC-secp256r1', 'Ed25519', 'ML-DSA-65'."""
    if not key:
        return None
    if key.get("curve"):
        return f"{key['algorithm']}-{key['curve']}"
    if key["algorithm"] in ("RSA", "DSA") and key.get("size"):
        return f"{key['algorithm']}-{key['size']}"
    return key["algorithm"]


def signature_oid(cert: x509.Certificate) -> str:
    return cert.signature_algorithm_oid.dotted_string


def signature_name(cert: x509.Certificate) -> str:
    """e.g. sha256WithRSAEncryption, ecdsa-with-SHA384, ed25519, ML-DSA-65."""
    oid = cert.signature_algorithm_oid
    if pq := pqc_signature_name(oid.dotted_string):
        return pq
    if oid._name and oid._name != "Unknown OID":
        return oid._name
    try:
        h = cert.signature_hash_algorithm
    except Exception:  # noqa: BLE001 - unsupported algorithm
        h = None
    return h.name if h else oid.dotted_string


def is_sha1_signed(cert: x509.Certificate) -> bool:
    try:
        h = cert.signature_hash_algorithm
    except Exception:  # noqa: BLE001
        return False
    return isinstance(h, (hashes.SHA1, hashes.MD5))


def common_name(name: x509.Name) -> str | None:
    attrs = name.get_attributes_for_oid(NameOID.COMMON_NAME)
    return str(attrs[0].value) if attrs else None


def fingerprints(cert: x509.Certificate) -> dict[str, str]:
    der = cert.public_bytes(serialization.Encoding.DER)
    return {"sha256": hashlib.sha256(der).hexdigest(), "sha1": hashlib.sha1(der).hexdigest()}


def is_self_signed(cert: x509.Certificate) -> bool:
    if cert.issuer != cert.subject:
        return False
    try:
        cert.verify_directly_issued_by(cert)
        return True
    except Exception:  # noqa: BLE001 - unsupported key types or a bad signature
        return False


def cert_summary(cert: x509.Certificate) -> dict:
    """The certificate facts a crypto asset records."""
    return {"key": key_info(cert), "signature_algorithm": signature_name(cert),
            "signature_oid": signature_oid(cert), "sha1_signed": is_sha1_signed(cert) and not is_self_signed(cert),
            "not_before": cert.not_valid_before_utc.isoformat(), "not_after": cert.not_valid_after_utc.isoformat(), "fingerprint": fingerprints(cert)["sha256"],
            "subject": cert.subject.rfc4514_string(), "issuer": cert.issuer.rfc4514_string()}
