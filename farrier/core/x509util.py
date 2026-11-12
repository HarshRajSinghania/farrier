"""Key, CSR and certificate helpers."""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtensionOID, NameOID


def generate_key(kind: str = "ec256"):
    if kind == "ec256":
        return ec.generate_private_key(ec.SECP256R1())
    if kind == "ec384":
        return ec.generate_private_key(ec.SECP384R1())
    if kind in ("rsa2048", "rsa3072", "rsa4096"):
        return rsa.generate_private_key(public_exponent=65537, key_size=int(kind[3:]))
    raise ValueError(f"unknown key type {kind}")


def key_to_pem(key) -> str:
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()


def load_key(pem: str):
    return serialization.load_pem_private_key(pem.encode(), password=None)


def build_csr(key, common_name: str, sans: list[str]) -> str:
    names = list(dict.fromkeys([common_name, *sans]))
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(n) for n in names]), critical=False)
        .sign(key, hashes.SHA256())
    )
    return csr.public_bytes(serialization.Encoding.PEM).decode()


@dataclass
class CertInfo:
    fingerprint: str
    subject_cn: str
    sans: list[str] = field(default_factory=list)
    issuer: str = ""
    serial: str = ""
    not_before: datetime | None = None
    not_after: datetime | None = None
    key_type: str = ""
    # the DER as served, and the intermediates the server sent after it (stored once per fingerprint)
    der: bytes | None = field(default=None, repr=False, compare=False)
    chain_der: list[bytes] = field(default_factory=list, repr=False, compare=False)

    @property
    def lifetime_days(self) -> int:
        return round((self.not_after - self.not_before).total_seconds() / 86400)


def _cn(name: x509.Name) -> str:
    attrs = name.get_attributes_for_oid(NameOID.COMMON_NAME)
    return attrs[0].value if attrs else name.rfc4514_string()


def cert_info(cert: x509.Certificate) -> CertInfo:
    try:
        sans = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value.get_values_for_type(
            x509.DNSName)
    except x509.ExtensionNotFound:
        sans = []
    pub = cert.public_key()
    if isinstance(pub, rsa.RSAPublicKey):
        kt = f"RSA-{pub.key_size}"
    elif isinstance(pub, ec.EllipticCurvePublicKey):
        kt = f"EC-{pub.curve.name}"
    else:
        kt = type(pub).__name__
    return CertInfo(
        fingerprint=hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest(),
        subject_cn=_cn(cert.subject),
        sans=list(sans),
        issuer=_cn(cert.issuer),
        serial=format(cert.serial_number, "x"),
        not_before=cert.not_valid_before_utc,
        not_after=cert.not_valid_after_utc,
        key_type=kt,
    )


def parse_pem(pem: str) -> CertInfo:
    return cert_info(x509.load_pem_x509_certificate(pem.encode()))


def parse_der(der: bytes, chain_der: list[bytes] | None = None) -> CertInfo:
    info = cert_info(x509.load_der_x509_certificate(der))
    info.der, info.chain_der = der, list(chain_der or [])
    return info


def der_to_pem(der: bytes) -> str:
    return x509.load_der_x509_certificate(der).public_bytes(serialization.Encoding.PEM).decode()


def split_pem_chain(pem: str) -> list[str]:
    marker = "-----END CERTIFICATE-----"
    parts = [p.strip() + "\n" + marker + "\n" for p in pem.split(marker) if "BEGIN CERTIFICATE" in p]
    return [p.lstrip() for p in parts]


def key_matches_cert(key_pem: str, cert_pem: str) -> bool:
    key = load_key(key_pem)
    cert = x509.load_pem_x509_certificate(cert_pem.encode())
    fmt = (serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return key.public_key().public_bytes(*fmt) == cert.public_key().public_bytes(*fmt)
