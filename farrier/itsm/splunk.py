"""Splunk HTTP Event Collector (HEC), JSON events, no SDK.

    {"type": "splunk", "url": "https://splunk.acme.internal:8088/services/collector/event",
     "token": "vault:SPLUNK_HEC_TOKEN", "index": "pki", "source": "farrier", "sourcetype": "farrier:event",
     "verify_tls": true, "ca_file": "file:/etc/farrier/splunk-ca.pem"}

Every renewal event and alert-rule message is one HEC event; once a day the leader also sends an
inventory snapshot, one event per endpoint (kind "inventory") with its certificate fields. Batches are
newline-separated JSON event objects, at most 500 per request. Each event's ``event.id`` is
deterministic (renewal id + state, or endpoint id + day), so duplicates from a retry can be removed with
``dedup id`` in a search. TLS is verified by default; ca_file (a file: reference to a PEM bundle) trusts a
private CA.
"""
from __future__ import annotations

import json
import ssl
import time
from typing import ClassVar
from urllib.parse import urlparse

from farrier.itsm.base import Adapter, as_bool, field, require_ref, secret
from farrier.itsm.http import Http, ItsmError
from farrier.security.vault import resolve_secret

BATCH = 500


class Splunk(Adapter):
    kind = "splunk"
    label = "Splunk"
    telemetry_capable = True
    FIELDS: ClassVar[list[dict]] = [
        field("url", "HEC URL", required=True, help="https://<host>:8088/services/collector/event"),
        field("token", "HEC token", secret=True, required=True),
        field("index", "Index", help="Must be allowed for the token (default: the token's default index)"),
        field("source", "Source", help="Default farrier"),
        field("sourcetype", "Sourcetype", help="Default farrier:event"),
        field("verify_tls", "Verify TLS", help="true (default) or false"),
        field("ca_file", "CA bundle", secret=True, help="file:/path to a PEM bundle for a private CA"),
        field("inventory", "Daily inventory", help="true (default): one event per endpoint every day"),
    ]

    @classmethod
    def validate(cls, body: dict, allow_inline: bool = False) -> dict:
        u = urlparse(str(body.get("url", "")).strip())
        if u.scheme != "https" or not u.hostname or u.query:
            raise ValueError("url must be the https:// HEC event endpoint, e.g. "
                             "https://splunk.example.com:8088/services/collector/event")
        if not u.path or u.path == "/":
            body["url"] = f"https://{u.netloc}/services/collector/event"
        require_ref(body, "token", allow_inline)
        if body.get("ca_file") not in (None, "") and not str(body["ca_file"]).startswith("file:"):
            raise ValueError("ca_file must be a file:/path reference to a PEM bundle")
        body["verify_tls"] = as_bool(body.get("verify_tls"), True)
        body["inventory"] = as_bool(body.get("inventory"), True)
        return body

    @classmethod
    def target(cls, cfg: dict) -> str:
        host = urlparse(str(cfg.get("url"))).hostname
        return f"index {cfg['index']} on {host}" if cfg.get("index") else f"Splunk HEC on {host}"

    def __init__(self, cfg: dict, transport=None):
        super().__init__(cfg, transport)
        token = secret(cfg, "token")
        verify: bool | ssl.SSLContext = as_bool(cfg.get("verify_tls"), True)
        if verify and cfg.get("ca_file"):
            verify = ssl.create_default_context(cadata=resolve_secret(cfg["ca_file"]))
        self.verify = verify
        u = urlparse(cfg["url"])
        self.path = u.path
        self.http = Http(f"https://{u.netloc}", {"Authorization": f"Splunk {token}", "Content-Type": "application/json"},
                         verify=verify, secrets=[token], transport=transport)

    def _meta(self) -> dict:
        m = {"source": self.cfg.get("source") or "farrier", "sourcetype": self.cfg.get("sourcetype") or "farrier:event",
             "host": "farrier"}
        if self.cfg.get("index"):
            m["index"] = self.cfg["index"]
        return m

    def wrap(self, event: dict, at: float | None = None) -> dict:
        return {"time": round(at if at is not None else time.time(), 3), **self._meta(), "event": event}

    def send_events(self, events: list[dict]) -> None:
        for i in range(0, len(events), BATCH):
            body = "\n".join(json.dumps(e, separators=(",", ":"), default=str) for e in events[i:i + BATCH])
            r = self.http.post(self.path, content=body.encode(), idempotent=False)
            try:
                j = r.json()
            except ValueError:
                j = {}
            if j.get("code") not in (None, 0):
                raise ItsmError(f"Splunk HEC refused the batch: {j.get('text')} (code {j.get('code')})")

    def notify(self, p: dict) -> None:
        kind = "alert" if p.get("rule") else ("test" if p.get("event") == "test" else "renewal")
        eid = f"renewal-{p['renewal_id']}-{p['event']}" if p.get("renewal_id") else None
        ev = {"kind": kind, **({"id": eid} if eid else {}), **{k: v for k, v in p.items() if v is not None}}
        self.send_events([self.wrap(ev)])

    def check(self) -> str:
        try:
            self.http.get("/services/collector/health")
        except ItsmError as e:
            if e.status not in (400, 404):      # some proxies hide the health endpoint: the event below decides
                raise
        self.send_events([self.wrap({"kind": "test", "message": "Farrier channel test"})])
        return f"HEC accepted a test event{' for index ' + self.cfg['index'] if self.cfg.get('index') else ''}"
