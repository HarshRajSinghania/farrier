"""Envelope encryption of the master key with a cloud KMS (FARRIER_MASTER_KEY_KMS).

    aws-kms:<key ARN>                                                        Encrypt / Decrypt
    gcp-kms:projects/<p>/locations/<l>/keyRings/<r>/cryptoKeys/<k>           encrypt / decrypt
    azure-kv:https://<vault>.vault.azure.net/keys/<name>[/<version>]         wrapKey / unwrapKey RSA-OAEP-256

``wrap`` returns a JSON-able blob (never the plaintext); ``unwrap`` takes it back. AWS and Google bind the
ciphertext to the purpose (encryption context / additional authenticated data), so a blob cannot be
swapped for another ciphertext made with the same key for something else.
"""
from __future__ import annotations

import base64
import re

from .cloud_auth import aws, azure, google
from .cloud_auth.http import CloudConfigError, json_body, request

PURPOSE = "farrier-master-key"
AWS_KEY = re.compile(r"^arn:aws[a-z-]*:kms:(?P<region>[a-z0-9-]+):\d{12}:(key|alias)/[A-Za-z0-9/_-]+$")
GCP_KEY = re.compile(r"^projects/[^/]+/locations/[^/]+/keyRings/[^/]+/cryptoKeys/[^/]+$")
SETTING = "FARRIER_MASTER_KEY_KMS"


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _unb64u(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _to_b64u(s: str) -> str:
    """Key Vault wants base64url; a ciphertext handed over as standard base64 is converted."""
    return s.strip().replace("+", "-").replace("/", "_").rstrip("=")


def parse(spec: str) -> tuple[str, str]:
    scheme, _, key = (spec or "").strip().partition(":")
    if scheme == "aws-kms" and AWS_KEY.match(key):
        return scheme, key
    if scheme == "gcp-kms" and GCP_KEY.match(key):
        return scheme, key
    if scheme == "azure-kv" and "/keys/" in key:
        from .secret_backends.azure import vault_origin
        vault_origin(key, SETTING)
        return scheme, key.rstrip("/")
    raise CloudConfigError(f"{SETTING} must be aws-kms:<key ARN>, gcp-kms:projects/.../cryptoKeys/<key> or "
                           "azure-kv:https://<vault>.vault.azure.net/keys/<name>")


def wrap(spec: str, plaintext: bytes, http=None) -> dict:
    scheme, key = parse(spec)
    what = f"{SETTING} wrap"
    if scheme == "aws-kms":
        j = aws.json_call("kms", "Encrypt", {"KeyId": key, "Plaintext": _b64(plaintext),
                                             "EncryptionContext": {"purpose": PURPOSE}},
                          region=AWS_KEY.match(key)["region"], what=what, http=http)
        return {"kms": spec, "ciphertext": j["CiphertextBlob"]}
    if scheme == "gcp-kms":
        tok = google.default_provider().token(google.CLOUD_PLATFORM)
        j = json_body(request("POST", f"https://cloudkms.googleapis.com/v1/{key}:encrypt", what=what, http=http,
                              headers={"Authorization": f"Bearer {tok}"},
                              json={"plaintext": _b64(plaintext), "additionalAuthenticatedData": _b64(PURPOSE.encode())}),
                      what)
        return {"kms": spec, "ciphertext": j["ciphertext"]}
    tok = azure.default_provider().token(azure.VAULT_SCOPE)
    j = json_body(request("POST", f"{key}/wrapkey", what=what, http=http, params={"api-version": "7.4"},
                          headers={"Authorization": f"Bearer {tok}"},
                          json={"alg": "RSA-OAEP-256", "value": _b64u(plaintext)}), what)
    return {"kms": spec, "kid": j["kid"], "ciphertext": j["value"]}


def unwrap(blob: dict, http=None) -> bytes:
    scheme, key = parse(blob["kms"])
    what = f"{SETTING} unwrap"
    if scheme == "aws-kms":
        j = aws.json_call("kms", "Decrypt", {"KeyId": key, "CiphertextBlob": blob["ciphertext"],
                                             "EncryptionContext": {"purpose": PURPOSE}},
                          region=AWS_KEY.match(key)["region"], what=what, http=http)
        return base64.b64decode(j["Plaintext"])
    if scheme == "gcp-kms":
        tok = google.default_provider().token(google.CLOUD_PLATFORM)
        j = json_body(request("POST", f"https://cloudkms.googleapis.com/v1/{key}:decrypt", what=what, http=http,
                              headers={"Authorization": f"Bearer {tok}"},
                              json={"ciphertext": blob["ciphertext"],
                                    "additionalAuthenticatedData": _b64(PURPOSE.encode())}), what)
        return base64.b64decode(j["plaintext"])
    kid = blob.get("kid") or key                 # the exact key version that wrapped it
    from .secret_backends.azure import vault_origin
    vault_origin(kid, "the wrapped master key's kid")
    tok = azure.default_provider().token(azure.VAULT_SCOPE)
    j = json_body(request("POST", f"{kid}/unwrapkey", what=what, http=http, params={"api-version": "7.4"},
                          headers={"Authorization": f"Bearer {tok}"},
                          json={"alg": "RSA-OAEP-256", "value": _to_b64u(blob["ciphertext"])}), what)
    return _unb64u(j["value"])
