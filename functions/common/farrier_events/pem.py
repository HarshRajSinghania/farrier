"""Dependency-free PEM helpers: split a chain, fingerprint the leaf.

Fingerprints match the event's ``fingerprint_sha256``: lowercase hex SHA-256
of the leaf certificate's DER encoding.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import re

from .errors import PermanentError

_CERT_BLOCK = re.compile(r"-----BEGIN CERTIFICATE-----\s*(?P<body>[A-Za-z0-9+/=\s]+?)\s*-----END CERTIFICATE-----")
_KEY_MARKER = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")


def split_certificates(pem: str) -> list[str]:
    """Each certificate in ``pem`` as a normalised PEM block, in order."""
    blocks = []
    for m in _CERT_BLOCK.finditer(pem):
        body = "".join(m["body"].split())
        lines = [body[i : i + 64] for i in range(0, len(body), 64)]
        blocks.append("-----BEGIN CERTIFICATE-----\n" + "\n".join(lines) + "\n-----END CERTIFICATE-----\n")
    return blocks


def der(pem_block: str) -> bytes:
    m = _CERT_BLOCK.search(pem_block)
    if not m:
        raise PermanentError("not a PEM certificate")
    try:
        return base64.b64decode("".join(m["body"].split()), validate=True)
    except binascii.Error:
        raise PermanentError("PEM certificate body is not valid base64") from None


def fingerprint_sha256(pem_block: str) -> str:
    return hashlib.sha256(der(pem_block)).hexdigest()


def contains_private_key(text: str) -> bool:
    return bool(_KEY_MARKER.search(text))


def leaf_and_chain(fullchain: str) -> tuple[str, str]:
    """Split a full chain (leaf first) into ``(leaf, intermediates)``.

    Refuses a "chain" object that also contains a private key: that object is
    stored somewhere with weaker controls than the secret store.
    """
    if contains_private_key(fullchain):
        raise PermanentError("chain object contains a private key; refusing to use it")
    certs = split_certificates(fullchain)
    if not certs:
        raise PermanentError("chain object contains no PEM certificates")
    return certs[0], "".join(certs[1:])


def verify_leaf(fullchain: str, expected_fingerprint: str) -> tuple[str, str]:
    """``leaf_and_chain`` plus a check that the leaf is the certificate the event announced.

    A mismatch means the chain object was overwritten or the event is stale;
    importing it would deploy the wrong certificate.
    """
    leaf, chain = leaf_and_chain(fullchain)
    if fingerprint_sha256(leaf) != expected_fingerprint:
        raise PermanentError("leaf certificate fingerprint does not match the event")
    return leaf, chain
