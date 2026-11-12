"""Renewal events as CloudEvents 1.0 (structured JSON), per events/schema/renewal-event.schema.json.

    {specversion: "1.0", id: <uuid>, source: "farrier://<instance id>", type: "dev.farrier.renewal.<state>",
     time, subject: <endpoint name>, datacontenttype: "application/json",
     data: {schema_version: 1, endpoint: {id, name, host, port, connector, tags},
            renewal: {id, state, reason, not_after, fingerprint_sha256},
            certificate: {names, issuer, chain_ref} | null, private_key_ref}}

The instance id is FARRIER_INSTANCE_ID, else derived from the master key (stable across replicas that
share it, and reveals nothing about it). Events never carry key material: ``private_key_ref`` names a
secret in the cloud secret backend, ``chain_ref`` an object in the bucket.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import re
import uuid
from datetime import UTC, datetime

from farrier.db.store import parse_dt

STATES = ("planned", "issued", "deploying", "verifying", "done", "failed", "rolled_back", "awaiting_manual",
          "cancelled")
TYPE_PREFIX = "dev.farrier.renewal."
INSTANCE = re.compile(r"^[A-Za-z0-9._~-]{1,128}$")


def instance_id(data_dir) -> str:
    env = os.environ.get("FARRIER_INSTANCE_ID", "").strip()
    if env:
        if not INSTANCE.match(env):
            raise ValueError("FARRIER_INSTANCE_ID may only use A-Z a-z 0-9 . _ ~ - (it becomes farrier://<id>)")
        return env
    from farrier.security.vault import master_key
    return "farrier-" + hmac.new(master_key(data_dir), b"farrier-instance-id", hashlib.sha256).hexdigest()[:12]


def _ts(value) -> str | None:
    d = parse_dt(value) if isinstance(value, str) else value
    return d.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ") if d else None


def _certificate(renewal: dict, endpoint: dict, chain_ref: str | None) -> dict | None:
    if not renewal.get("cert_pem"):
        return None
    from farrier.core.x509util import parse_pem
    info = parse_pem(renewal["cert_pem"])
    names = [n for n in dict.fromkeys([info.subject_cn, *info.sans]) if n] or [endpoint.get("host") or "unknown"]
    return {"names": names, "issuer": info.issuer or "", "chain_ref": chain_ref}


def build(state: str, renewal: dict, endpoint: dict, instance: str, chain_ref: str | None = None,
          private_key_ref: str | None = None) -> dict | None:
    """The CloudEvent for a renewal entering ``state``; None for states outside the contract."""
    if state not in STATES or not renewal or not endpoint:
        return None
    fp = renewal.get("new_fingerprint") if renewal.get("cert_pem") else None
    return {
        "specversion": "1.0",
        "id": str(uuid.uuid4()),
        "source": f"farrier://{instance}",
        "type": TYPE_PREFIX + state,
        "time": _ts(datetime.now(UTC)),
        "subject": endpoint["name"],
        "datacontenttype": "application/json",
        "data": {
            "schema_version": 1,
            "endpoint": {"id": endpoint["id"], "name": endpoint["name"], "host": endpoint["host"],
                         "port": int(endpoint["port"]), "connector": endpoint["connector"],
                         "tags": list(endpoint.get("tags") or [])},
            "renewal": {"id": renewal["id"], "state": state, "reason": renewal.get("reason") or "due",
                        "not_after": _ts(renewal.get("not_after")) if fp else None,
                        "fingerprint_sha256": fp.lower() if fp else None},
            "certificate": _certificate(renewal, endpoint, chain_ref),
            "private_key_ref": private_key_ref,
        },
    }


def test_event(instance: str | None = None) -> dict:
    """What a channel test publishes: type dev.farrier.test (outside the renewal contract, so consumers
    that filter on dev.farrier.renewal.* ignore it)."""
    inst = instance or os.environ.get("FARRIER_INSTANCE_ID") or "farrier"
    return {"specversion": "1.0", "id": str(uuid.uuid4()), "source": f"farrier://{inst}", "type": "dev.farrier.test",
            "time": _ts(datetime.now(UTC)), "subject": "channel-test", "datacontenttype": "application/json",
            "data": {"schema_version": 1, "test": True}}
