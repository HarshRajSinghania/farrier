"""The adapter interface every ITSM / observability product implements.

    Adapter            check() -> str           a safe, real call for the dashboard's Test button
                       notify(p)                a renewal event or alert-rule message (notify.payload)
    TicketAdapter      find(key) / open(spec) / comment(t, text) / resolve(t, text)
                                                the ticket lifecycle (farrier.itsm.tickets)
    TelemetryAdapter   telemetry(engine, now)   the leader's per-tick metrics / daily inventory

An adapter is built from one alert-channel config. Secret fields are references (vault:/env:/file:/
external) resolved here with farrier.security.vault.resolve_secret at the moment of use; the resolved
values are handed to the Http client only so it can scrub them from error text.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from dataclasses import field as dc_field
from typing import ClassVar

from farrier.security.vault import is_ref, resolve_secret

HOST = re.compile(r"^(?=.{1,253}$)[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$")
KEY_MARKERS = ("PRIVATE KEY", "passphrase.txt:")   # never in a ticket, event or log line


def field(key, label, secret=False, required=False, help=""):
    """A catalog field, the same shape as farrier.config.integrations._field."""
    return {"key": key, "label": label, "secret": secret, "required": required, "help": help}


def as_bool(v, default: bool) -> bool:
    if v in (None, ""):
        return default
    if isinstance(v, bool):
        return v
    s = str(v).strip().lower()
    if s in ("true", "1", "yes", "on"):
        return True
    if s in ("false", "0", "no", "off"):
        return False
    raise ValueError(f"{v!r} is not true or false")


def as_list(v) -> list[str]:
    if v in (None, ""):
        return []
    if isinstance(v, str):
        v = v.split(",")
    if not isinstance(v, list) or not all(isinstance(x, str) for x in v):
        raise ValueError("must be a list of strings (or a comma-separated string)")
    return [x.strip() for x in v if x.strip()]


def secret(cfg: dict, key: str) -> str | None:
    v = cfg.get(key)
    return None if v in (None, "") else resolve_secret(v)


def require_ref(body: dict, key: str, allow_inline: bool = False) -> None:
    if body.get(key) not in (None, "") and not is_ref(body[key]) and not allow_inline:
        raise ValueError(f"{key} is a secret: reference it as vault:NAME (or env:NAME / file:/path)")


def no_key_material(text: str) -> str:
    """Last line of defence: refuse to send text that looks like it carries key material."""
    for m in KEY_MARKERS:
        if m in text:
            raise ValueError("refusing to send text that contains key material")
    return text


@dataclass
class Ticket:
    ref: str                 # what people see: INC0012345 / CHG0030001 / OPS-42
    ext_id: str              # what the API addresses: sys_id / issue key
    table: str = ""          # ServiceNow table (incident, change_request); "issue" for Jira
    url: str | None = None


@dataclass
class TicketSpec:
    key: str                 # idempotency key (correlation_id / label): one ticket per (channel, renewal)
    kind: str                # "change" (a change pack to install) or "incident" (an automated renewal failed)
    summary: str
    description: str
    ci: dict = dc_field(default_factory=dict)      # {"name": endpoint name, "host": host} for a CMDB lookup
    extra: dict = dc_field(default_factory=dict)


class Adapter:
    kind = ""
    label = ""
    FIELDS: ClassVar[list[dict]] = []
    ticketing = False
    telemetry_capable = False

    def __init__(self, cfg: dict, transport=None):
        self.cfg = cfg
        self.transport = transport

    @classmethod
    def validate(cls, body: dict, allow_inline: bool = False) -> dict:
        """Normalise a dashboard body; raise ValueError with a message for the user."""
        return body

    @classmethod
    def target(cls, cfg: dict) -> str:
        return cls.label

    def check(self) -> str:
        raise NotImplementedError

    def notify(self, p: dict) -> None:
        raise NotImplementedError

    def close(self) -> None:
        http = getattr(self, "http", None)
        if http is not None:
            http.close()


class TicketAdapter(Adapter):
    ticketing = True

    def find(self, key: str, kind: str) -> Ticket | None:
        raise NotImplementedError

    def open(self, spec: TicketSpec) -> Ticket:
        raise NotImplementedError

    def comment(self, t: Ticket, text: str) -> None:
        raise NotImplementedError

    def resolve(self, t: Ticket, text: str) -> None:
        raise NotImplementedError

    def notify(self, p: dict) -> None:
        """Without the ticket lifecycle (or for alert-rule messages): one ticket per message."""
        from farrier.monitoring.notify import _text
        text = _text(p)
        first = text.splitlines()[0]
        lines = [text, ""] + [f"{k}: {v}" for k, v in p.items() if v is not None and k not in ("dashboard_url",)]
        kind = "incident" if p.get("event") in ("failed", "rolled_back", "alert") else "change"
        self.open(TicketSpec(key="", kind=kind, summary=first[:250], description=no_key_material("\n".join(lines)),
                             ci={"name": p.get("endpoint"), "host": p.get("host")}))
