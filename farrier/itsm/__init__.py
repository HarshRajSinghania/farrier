"""ITSM and observability channels: ServiceNow, Jira, Datadog, Splunk.

One adapter per product (farrier.itsm.<product>) behind farrier.itsm.base.Adapter, all on one httpx
client with timeouts and bounded retries (farrier.itsm.http). They are alert channels like Slack or
email (configured in the dashboard, secrets as references), plus:

  farrier.itsm.tickets    the ticket lifecycle for ServiceNow / Jira channels with "tickets": true
  farrier.itsm.telemetry  the leader's per-tick Datadog metrics and daily Splunk inventory
"""
from __future__ import annotations

from farrier.itsm.base import Adapter
from farrier.itsm.datadog import Datadog
from farrier.itsm.jira import Jira
from farrier.itsm.servicenow import ServiceNow
from farrier.itsm.splunk import Splunk

ADAPTERS: dict[str, type[Adapter]] = {a.kind: a for a in (ServiceNow, Jira, Datadog, Splunk)}
ITSM_TYPES = frozenset(ADAPTERS)


def adapter_for(cfg: dict, transport=None) -> Adapter:
    return ADAPTERS[cfg["type"]](cfg, transport=transport)


def is_ticketing(cfg: dict) -> bool:
    """A ServiceNow / Jira channel that runs the ticket lifecycle for renewals."""
    cls = ADAPTERS.get(cfg.get("type"))
    return bool(cls and cls.ticketing and cfg.get("tickets") in (True, "true", "1", "yes"))
