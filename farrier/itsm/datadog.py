"""Datadog: events (API v2, or v1) for renewal events and alert-rule messages, and metric series (v2).

    {"type": "datadog", "site": "datadoghq.eu", "api_key": "vault:DD_API_KEY", "env": "prod",
     "events_api": "v2", "events": ["done", "failed", "rolled_back", "awaiting_manual"]}

Metrics, submitted once per tick by the leader (POST /api/v2/series):
  farrier.certificate.days_left   gauge, one series per enabled endpoint that has a certificate;
                                  tags endpoint:, connector:, issuer: (the endpoint's issuer config) and
                                  env: (an endpoint tag env:X / env=X, else the channel's env)
  farrier.renewals.failed         count of renewals that ended failed or rolled_back since the last submit
Events carry aggregation_key farrier-renewal-<id> (or farrier-alert-<rule>), so one renewal's events
group together in the event explorer.
"""
from __future__ import annotations

import re
from typing import ClassVar

from farrier.itsm.base import Adapter, field, require_ref, secret
from farrier.itsm.http import Http

SITES = {"datadoghq.com": "datadoghq.com", "us1": "datadoghq.com", "us3": "us3.datadoghq.com",
         "us3.datadoghq.com": "us3.datadoghq.com", "us5": "us5.datadoghq.com", "us5.datadoghq.com": "us5.datadoghq.com",
         "eu": "datadoghq.eu", "eu1": "datadoghq.eu", "datadoghq.eu": "datadoghq.eu", "ap1": "ap1.datadoghq.com",
         "ap1.datadoghq.com": "ap1.datadoghq.com", "ap2": "ap2.datadoghq.com", "ap2.datadoghq.com": "ap2.datadoghq.com",
         "gov": "ddog-gov.com", "ddog-gov.com": "ddog-gov.com"}
GAUGE, COUNT = 3, 1
ALERT_TYPE = {"failed": "error", "rolled_back": "error", "alert": "warning", "awaiting_manual": "warning",
              "done": "success"}
V2_STATUS = {"error": "error", "warning": "warn", "success": "ok", "info": "ok"}
_TAG_BAD = re.compile(r"[^a-z0-9_:./-]")
BATCH = 500


def tag(k: str, v) -> str:
    return f"{k}:{_TAG_BAD.sub('_', str(v).lower())}"[:200]


class Datadog(Adapter):
    kind = "datadog"
    label = "Datadog"
    telemetry_capable = True
    FIELDS: ClassVar[list[dict]] = [
        field("site", "Site", required=True, help="datadoghq.com, datadoghq.eu, us3.datadoghq.com, "
                                                  "us5.datadoghq.com, ap1.datadoghq.com or ddog-gov.com"),
        field("api_key", "API key", secret=True, required=True, help="Organization Settings > API Keys"),
        field("env", "Environment tag", help="Default env: tag for metrics (an endpoint tag env:X wins)"),
        field("events_api", "Events API", help="v2 (default) or v1"),
        field("metrics", "Metrics", help="true (default): submit certificate metrics every tick"),
    ]

    @classmethod
    def validate(cls, body: dict, allow_inline: bool = False) -> dict:
        from farrier.itsm.base import as_bool
        site = str(body.get("site", "")).strip().lower().removeprefix("https://").removeprefix("api.").rstrip("/")
        if site not in SITES:
            raise ValueError("site must be one of datadoghq.com, datadoghq.eu, us3.datadoghq.com, us5.datadoghq.com, "
                             "ap1.datadoghq.com, ddog-gov.com")
        body["site"] = SITES[site]
        require_ref(body, "api_key", allow_inline)
        if body.get("events_api") not in (None, "", "v1", "v2"):
            raise ValueError("events_api must be v1 or v2")
        body["metrics"] = as_bool(body.get("metrics"), True)
        return body

    @classmethod
    def target(cls, cfg: dict) -> str:
        return f"Datadog ({cfg.get('site')})"

    def __init__(self, cfg: dict, transport=None):
        super().__init__(cfg, transport)
        key = secret(cfg, "api_key")
        self.http = Http(f"https://api.{SITES.get(cfg['site'], cfg['site'])}",
                         {"DD-API-KEY": key, "Accept": "application/json", "Content-Type": "application/json"},
                         secrets=[key], transport=transport)

    def check(self) -> str:
        r = self.http.get("/api/v1/validate").json()
        if r.get("valid") is not True:
            from farrier.itsm.http import ItsmError
            raise ItsmError("Datadog did not accept the API key")
        return f"API key valid for {self.cfg['site']}"

    def notify(self, p: dict) -> None:
        from farrier.monitoring.notify import _text
        text = _text(p)
        title, _, rest = text.partition("\n")
        alert_type = ALERT_TYPE.get(p.get("event"), "info")
        tags = ["source:farrier", tag("event", p.get("event"))]
        for k in ("endpoint", "connector"):
            if p.get(k):
                tags.append(tag(k, p[k]))
        if p.get("rule"):
            tags.append(tag("rule", p["rule"]))
        agg = f"farrier-renewal-{p['renewal_id']}" if p.get("renewal_id") else \
            f"farrier-alert-{p.get('rule') or p.get('event')}"
        if self.cfg.get("events_api") == "v1":
            self.http.post("/api/v1/events", json={
                "title": title[:100], "text": rest or title, "alert_type": alert_type, "tags": tags,
                "aggregation_key": agg[:100], "source_type_name": "farrier"}, idempotent=False)
            return
        custom = {k: v for k, v in p.items() if v is not None and k not in ("dashboard_url",)}
        attrs = {"status": V2_STATUS[alert_type], "priority": "1" if alert_type == "error" else "3",
                 "custom": custom}
        if p.get("dashboard_url"):
            attrs["links"] = [{"category": "runbook", "title": "Farrier", "url": p["dashboard_url"]}]
        self.http.post("/api/v2/events", json={"data": {"type": "event", "attributes": {
            "category": "alert", "title": title[:500], "message": (rest or title)[:4000], "tags": tags,
            "aggregation_key": agg[:100], "attributes": attrs}}}, idempotent=False)

    def submit_series(self, series: list[dict]) -> None:
        for i in range(0, len(series), BATCH):
            # a repeated series point overwrites itself (same metric, tags and timestamp): safe to retry
            self.http.post("/api/v2/series", json={"series": series[i:i + BATCH]}, idempotent=True)
