"""Test helpers shared by the function test suites. Never packaged."""

from __future__ import annotations

import copy
import datetime as dt
import hashlib
import json
from dataclasses import dataclass
from functools import cache
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[3]
SCHEMA_PATH = REPO_ROOT / "events" / "schema" / "renewal-event.schema.json"
EXAMPLES_DIR = REPO_ROOT / "events" / "examples"


@dataclass(frozen=True)
class Material:
    leaf_pem: str
    intermediate_pem: str
    key_pem: str
    fingerprint: str

    @property
    def fullchain(self) -> str:
        return self.leaf_pem + self.intermediate_pem


@cache
def material(cn: str = "www.example.com") -> Material:
    """A real leaf + intermediate + key, generated locally (EC P-256, fast)."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    now = dt.datetime.now(dt.UTC)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Farrier Test Intermediate")])
    ca = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    key = ec.generate_private_key(ec.SECP256R1())
    leaf = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
        .issuer_name(ca_name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=90))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(cn)]), critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    pem = serialization.Encoding.PEM
    return Material(
        leaf_pem=leaf.public_bytes(pem).decode(),
        intermediate_pem=ca.public_bytes(pem).decode(),
        key_pem=key.private_bytes(pem, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode(),
        fingerprint=hashlib.sha256(leaf.public_bytes(serialization.Encoding.DER)).hexdigest(),
    )


def example(name: str) -> dict[str, Any]:
    return json.loads((EXAMPLES_DIR / name).read_text())


def make_event(
    state: str = "done",
    *,
    tags: list[str] | None = None,
    fingerprint: str | None = None,
    chain_ref: str | None = "s3://farrier-certs/prod/2041/fullchain.pem",
    private_key_ref: str
    | None = "aws-sm:arn:aws:secretsmanager:eu-west-1:123456789012:secret:farrier/keys/2041-AbCdEf",
    renewal_id: int = 2041,
    event_id: str = "7b0c3f0e-2d7a-4a4b-9a55-0d6f4c3f2a10",
    endpoint_name: str = "www-lb",
) -> dict[str, Any]:
    ev = copy.deepcopy(example("renewal-done.json"))
    ev["id"] = event_id
    ev["type"] = f"dev.farrier.renewal.{state}"
    ev["subject"] = endpoint_name
    d = ev["data"]
    d["endpoint"]["name"] = endpoint_name
    d["endpoint"]["tags"] = ["prod"] if tags is None else tags
    d["renewal"]["state"] = state
    d["renewal"]["id"] = renewal_id
    if fingerprint is not None:
        d["renewal"]["fingerprint_sha256"] = fingerprint
    d["certificate"]["chain_ref"] = chain_ref
    d["private_key_ref"] = private_key_ref
    return ev


def eventbridge(ev: dict[str, Any]) -> dict[str, Any]:
    return {
        "version": "0",
        "id": "eb-0001",
        "detail-type": ev["type"],
        "source": "farrier",
        "account": "123456789012",
        "time": ev["time"],
        "region": "eu-west-1",
        "resources": [],
        "detail": ev,
    }


def assert_no_secrets(text: str, *secrets: str) -> None:
    """Fail if captured output contains PEM material or any of ``secrets``."""
    assert "-----BEGIN" not in text, "PEM block leaked into output"
    assert "PRIVATE KEY" not in text, "private key marker leaked into output"
    for s in secrets:
        if s:
            body = "".join(s.split("\n")[1:3]) if s.startswith("-----BEGIN") else s
            assert body not in text, "secret value leaked into output"


class NoSleep:
    def __init__(self) -> None:
        self.calls: list[float] = []

    def __call__(self, seconds: float) -> None:
        self.calls.append(seconds)
