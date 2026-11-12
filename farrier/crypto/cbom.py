"""CycloneDX 1.6 Cryptography Bill of Materials (CBOM) from stored crypto assets (pure; no I/O).

Components are ``cryptographic-asset``s of four asset types:
  protocol                one per (target, accepted protocol version): TLS or SSH, with cipher suites
  algorithm               key exchange groups, certificate signature algorithms, certificate key algorithms
  certificate             one per served certificate (by SHA-256 fingerprint)
  related-crypto-material the certificate's public key (size, algorithm)
Each protocol component carries farrier:* properties: target, endpoint id, PQC status and weak flags.
"""
from __future__ import annotations

import uuid
from datetime import UTC, datetime

from farrier.crypto import tls_wire as W

SUITE_CODES = {name: code for code, name in W.SUITE_NAMES.items()}

# name -> (primitive, cryptoFunctions, classical security bits, NIST PQC level, extra algorithmProperties)
_ALGS: dict[str, tuple[str, list[str], int | None, int, dict]] = {
    "x25519": ("key-agree", ["keygen", "keyderive"], 128, 0, {"curve": "Curve25519"}),
    "x448": ("key-agree", ["keygen", "keyderive"], 224, 0, {"curve": "Curve448"}),
    "secp256r1": ("key-agree", ["keygen", "keyderive"], 128, 0, {"curve": "secp256r1"}),
    "secp384r1": ("key-agree", ["keygen", "keyderive"], 192, 0, {"curve": "secp384r1"}),
    "secp521r1": ("key-agree", ["keygen", "keyderive"], 256, 0, {"curve": "secp521r1"}),
    "ffdhe2048": ("key-agree", ["keygen", "keyderive"], 112, 0, {"parameterSetIdentifier": "2048"}),
    "ffdhe3072": ("key-agree", ["keygen", "keyderive"], 128, 0, {"parameterSetIdentifier": "3072"}),
    "ECDHE": ("key-agree", ["keygen", "keyderive"], None, 0, {}),
    "DHE": ("key-agree", ["keygen", "keyderive"], None, 0, {}),
    "RSA": ("pke", ["encrypt", "decrypt"], None, 0, {}),
    "X25519MLKEM768": ("kem", ["keygen", "encapsulate", "decapsulate"], 128, 3, {"parameterSetIdentifier": "768"}),
    "SecP256r1MLKEM768": ("kem", ["keygen", "encapsulate", "decapsulate"], 128, 3, {"parameterSetIdentifier": "768"}),
    "SecP384r1MLKEM1024": ("kem", ["keygen", "encapsulate", "decapsulate"], 192, 5, {"parameterSetIdentifier": "1024"}),
    "MLKEM768": ("kem", ["keygen", "encapsulate", "decapsulate"], None, 3, {"parameterSetIdentifier": "768"}),
    "MLKEM1024": ("kem", ["keygen", "encapsulate", "decapsulate"], None, 5, {"parameterSetIdentifier": "1024"}),
    "ML-DSA-44": ("signature", ["sign", "verify"], None, 2, {"parameterSetIdentifier": "44"}),
    "ML-DSA-65": ("signature", ["sign", "verify"], None, 3, {"parameterSetIdentifier": "65"}),
    "ML-DSA-87": ("signature", ["sign", "verify"], None, 5, {"parameterSetIdentifier": "87"}),
}


def _ref(*parts) -> str:
    return "crypto/" + "/".join(str(p) for p in parts)


class _Builder:
    def __init__(self) -> None:
        self.components: dict[str, dict] = {}

    def add(self, ref: str, name: str, props: dict, extra: dict | None = None) -> str:
        if ref not in self.components:
            self.components[ref] = {"type": "cryptographic-asset", "bom-ref": ref, "name": name,
                                    "cryptoProperties": props, **(extra or {})}
        return ref

    def algorithm(self, name: str | None, *, primitive: str | None = None, oid: str | None = None,
                  functions: list[str] | None = None, size: int | None = None) -> str | None:
        if not name:
            return None
        known = _ALGS.get(name)
        prim, funcs, classical, nist, extra = known or (primitive or "unknown", functions or ["unknown"], None, 0, {})
        ap: dict = {"primitive": primitive or prim, "executionEnvironment": "unknown",
                    "implementationPlatform": "unknown", "certificationLevel": ["none"],
                    "cryptoFunctions": funcs, "nistQuantumSecurityLevel": nist, **extra}
        if classical:
            ap["classicalSecurityLevel"] = classical
        if size and "parameterSetIdentifier" not in ap and "curve" not in ap:
            ap["parameterSetIdentifier"] = str(size)
        props: dict = {"assetType": "algorithm", "algorithmProperties": ap}
        if oid:
            props["oid"] = oid
        return self.add(_ref("algorithm", name if not size else f"{name}-{size}"), name if not size else f"{name}-{size}",
                        props)


def _key_name(key: dict) -> str:
    return key["algorithm"] if not key.get("curve") else f"{key['algorithm']}-{key['curve']}"


def _tls(b: _Builder, asset: dict, raw: dict | None) -> None:
    cert_ref = None
    cert = (raw or {}).get("certificate")
    if cert:
        key = cert.get("key") or {}
        sig_ref = b.algorithm(cert.get("signature_algorithm"), primitive="signature", oid=cert.get("signature_oid"),
                              functions=["sign", "verify"])
        key_alg_ref = b.algorithm(_key_name(key), primitive="signature", functions=["sign", "verify"],
                                  size=key.get("size") if key.get("algorithm") in ("RSA", "DSA") else None) \
            if key else None
        pk_ref = None
        if key:
            pk_ref = b.add(_ref("key", cert["fingerprint"]), f"public key of {cert.get('subject') or cert['fingerprint'][:16]}",
                           {"assetType": "related-crypto-material",
                            "relatedCryptoMaterialProperties": {"type": "public-key", "algorithmRef": key_alg_ref,
                                                                "size": key.get("size"), "format": "SubjectPublicKeyInfo"}})
        cp = {"subjectName": cert.get("subject"), "issuerName": cert.get("issuer"),
              "notValidBefore": cert.get("not_before"), "notValidAfter": cert.get("not_after"),
              "signatureAlgorithmRef": sig_ref, "subjectPublicKeyRef": pk_ref,
              "certificateFormat": "X.509", "certificateExtension": "crt"}
        cert_ref = b.add(_ref("certificate", cert["fingerprint"]), cert.get("subject") or cert["fingerprint"],
                         {"assetType": "certificate", "certificateProperties": {k: v for k, v in cp.items() if v}},
                         {"properties": [{"name": "farrier:sha256", "value": cert["fingerprint"]}]})
    kx_ref = b.algorithm(asset.get("key_exchange"))
    for version in asset.get("protocol_versions") or []:
        suite = (asset.get("cipher_suites") or {}).get(version)
        suites = []
        if suite:
            code = SUITE_CODES.get(suite)
            suites.append({"name": suite, "algorithms": [r for r in (kx_ref,) if r and version == "TLSv1.3"],
                           **({"identifiers": [f"0x{code >> 8:02X}", f"0x{code & 0xFF:02X}"]} if code is not None else {})})
        _protocol(b, asset, "tls", version.removeprefix("TLSv"), suites,
                  [r for r in (kx_ref if version == "TLSv1.3" else None, cert_ref) if r])


def _protocol(b: _Builder, asset: dict, ptype: str, version: str, suites: list[dict], refs: list[str]) -> None:
    pqc = asset.get("pqc") or {}
    properties = [{"name": "farrier:target", "value": asset["target"]},
                  {"name": "farrier:pqc_status", "value": pqc.get("status", "unknown")},
                  {"name": "farrier:pqc_key_exchange", "value": str(bool(asset.get("pqc_key_exchange"))).lower()}]
    if asset.get("endpoint_id") is not None:
        properties.append({"name": "farrier:endpoint_id", "value": str(asset["endpoint_id"])})
    properties += [{"name": "farrier:weak", "value": w} for w in asset.get("weak") or []]
    properties += [{"name": "farrier:pqc_reason", "value": r} for r in pqc.get("reasons") or []]
    pp: dict = {"type": ptype, "version": version}
    if suites:
        pp["cipherSuites"] = suites
    if refs:
        pp["cryptoRefArray"] = refs
    b.add(_ref("protocol", ptype, asset["target"], version), f"{ptype.upper()} {version} @ {asset['target']}",
          {"assetType": "protocol", "protocolProperties": pp}, {"properties": properties})


def _ssh(b: _Builder, asset: dict) -> None:
    refs = [r for r in (b.algorithm(asset.get("key_exchange")),
                        b.algorithm(asset.get("signature_algorithm"), primitive="signature",
                                    functions=["sign", "verify"])) if r]
    key = asset.get("cert_key")
    if key and key.get("algorithm"):
        refs.append(b.algorithm(key["algorithm"], primitive="signature", functions=["sign", "verify"],
                                size=key.get("size") if key["algorithm"] in ("RSA", "DSA") else None))
    versions = asset.get("protocol_versions") or ["2.0"]
    for v in versions:
        _protocol(b, asset, "ssh", str(v).removeprefix("SSH-").removeprefix("SSHv"), [], [r for r in refs if r])


def build_cbom(assets: list[dict], tls_results: dict[int, dict] | None = None, *,
               version: str = "0", now: datetime | None = None) -> dict:
    """``assets`` are API-shaped assets (TLS and SSH); ``tls_results`` maps a TLS asset id to its raw probe
    result, which adds certificate components."""
    b = _Builder()
    tls_results = tls_results or {}
    for a in assets:
        if a.get("kind") == "ssh":
            _ssh(b, a)
        else:
            _tls(b, a, tls_results.get(a.get("id")))
    return {
        "bomFormat": "CycloneDX", "specVersion": "1.6", "serialNumber": f"urn:uuid:{uuid.uuid4()}", "version": 1,
        "metadata": {"timestamp": (now or datetime.now(UTC)).isoformat(timespec="seconds"),
                     "tools": {"components": [{"type": "application", "name": "farrier", "version": version}]},
                     "properties": [{"name": "farrier:assets", "value": str(len(assets))}]},
        "components": list(b.components.values()),
    }
