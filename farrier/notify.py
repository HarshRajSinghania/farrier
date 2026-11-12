"""Notifications on renewal state changes: generic webhook, Slack, Microsoft Teams and email (SMTP, Amazon SES).

Configured in <data>/settings.json:

    "notifiers": [
      {"type": "slack",   "url": "env:FARRIER_SECRET_SLACK_WEBHOOK", "events": ["failed", "rolled_back", "awaiting_manual"]},
      {"type": "teams",   "url": "file:/run/secrets/teams_webhook"},
      {"type": "webhook", "url": "https://hooks.example.internal/farrier", "events": ["done", "failed"],
       "headers": {"Authorization": "env:FARRIER_SECRET_HOOK_TOKEN"}}
    ]

`url` and header values go through the same secret guardrails as connector configs. `events`
defaults to failed, rolled_back and awaiting_manual. Delivery runs on a background thread with a
5 second timeout, so a slow receiver never stalls a renewal; failures are written to the event log.
"""
from __future__ import annotations

import threading
from datetime import UTC, datetime

import httpx

from .vault import resolve_secret

DEFAULT_EVENTS = ("failed", "rolled_back", "awaiting_manual")
EVENTS = {"planned", "issued", "verifying", "awaiting_manual", "done", "failed", "rolled_back", "superseded", "cancelled", "test"}
TITLES = {
    "done": "renewed and verified",
    "failed": "renewal failed",
    "rolled_back": "rolled back: the new certificate never went live",
    "awaiting_manual": "needs a person: change pack ready",
    "superseded": "superseded by another certificate",
    "cancelled": "renewal cancelled",
    "test": "test notification",
}


def payload(event: str, renewal: dict | None, endpoint: dict | None, dashboard_url: str | None = None) -> dict:
    r, e = renewal or {}, endpoint or {}
    return {
        "event": event,
        "endpoint": e.get("name"),
        "host": e.get("host"),
        "port": e.get("port"),
        "connector": e.get("connector"),
        "owner": e.get("owner"),
        "renewal_id": r.get("id"),
        "error": r.get("error"),
        "ticket": r.get("ticket_ref"),
        "new_not_after": r.get("not_after"),
        "at": datetime.now(UTC).isoformat(timespec="seconds"),
        "dashboard_url": dashboard_url,
    }


def _text(p: dict) -> str:
    where = f"{p['endpoint']} ({p['host']}:{p['port']})" if p.get("endpoint") else "Farrier"
    line = f"Farrier · {where}: {TITLES.get(p['event'], p['event'])}"
    if p.get("error"):
        line += f"\n{p['error']}"
    if p.get("ticket"):
        line += f"\nTicket {p['ticket']}"
    if p.get("dashboard_url"):
        line += f"\n{p['dashboard_url']}"
    return line


def body_for(kind: str, p: dict) -> dict:
    if kind == "slack":
        return {"text": _text(p)}
    if kind == "teams":
        # Teams incoming webhooks and Power Automate "post to a channel" flows both accept text
        return {"text": _text(p).replace("\n", "  \n")}
    return p


# Email over SMTP works with any provider: Amazon SES, SendGrid, Mailgun, Postmark, Microsoft 365,
# Google Workspace or an internal relay. "ses" is a shortcut that only needs the AWS region.
#   {"type": "email", "host": "smtp.sendgrid.net", "port": 587, "username": "apikey",
#    "password": "env:FARRIER_SECRET_SMTP_PASSWORD", "from": "farrier@example.com", "to": ["pki@example.com"]}
#   {"type": "ses", "region": "eu-west-1", "username": "env:FARRIER_SECRET_SES_USER",
#    "password": "env:FARRIER_SECRET_SES_PASSWORD", "from": "farrier@example.com", "to": ["pki@example.com"]}
# tls: "starttls" (default, port 587), "ssl" (port 465) or "none" (an internal relay on 25; never with a password).
EMAIL_TYPES = {"email", "ses"}


def _email_target(cfg: dict) -> tuple[str, int, str]:
    if cfg.get("type") == "ses":
        region = str(cfg.get("region", "")).strip()
        if not region.replace("-", "").isalnum():
            raise ValueError("ses notifier needs a region such as eu-west-1")
        return f"email-smtp.{region}.amazonaws.com", int(cfg.get("port", 587)), "starttls"
    tls = cfg.get("tls", "starttls")
    return cfg["host"], int(cfg.get("port", 465 if tls == "ssl" else 587)), tls


def send_email(cfg: dict, p: dict) -> None:
    import smtplib
    import ssl
    from email.message import EmailMessage

    host, port, tls = _email_target(cfg)
    user = resolve_secret(cfg.get("username")) if cfg.get("username") else None
    password = resolve_secret(cfg.get("password")) if cfg.get("password") else None
    if password and tls == "none":
        raise ValueError("refusing to send SMTP credentials without TLS")
    to = cfg.get("to") or []
    to = [to] if isinstance(to, str) else to
    if not to or not cfg.get("from"):
        raise ValueError("email notifier needs from and to")

    msg = EmailMessage()
    first = _text(p).splitlines()[0]
    msg["Subject"] = first.replace("\r", " ").replace("\n", " ")[:200]   # no header injection
    msg["From"] = cfg["from"]
    msg["To"] = ", ".join(to)
    msg.set_content(_text(p) + "\n\n" + "\n".join(f"{k}: {v}" for k, v in p.items() if v is not None))

    ctx = ssl.create_default_context()  # verifies the server's certificate and hostname
    if tls == "ssl":
        server = smtplib.SMTP_SSL(host, port, timeout=10, context=ctx)
    else:
        server = smtplib.SMTP(host, port, timeout=10)
    with server:
        if tls == "starttls":
            server.starttls(context=ctx)
        if user and password:
            server.login(user, password)
        server.send_message(msg)


class Notifier:
    def __init__(self, configs: list[dict] | None, dashboard_url: str | None, log):
        self.configs = [c for c in (configs or []) if isinstance(c, dict)
                        and (c.get("url") or c.get("type") in EMAIL_TYPES)]
        self.dashboard_url = dashboard_url
        self.log = log  # store.log(message, endpoint_id, renewal_id, level=...)

    def wants(self, cfg: dict, event: str) -> bool:
        return event == "test" or event in (cfg.get("events") or DEFAULT_EVENTS)

    def send(self, event: str, renewal: dict | None = None, endpoint: dict | None = None, wait: bool = False) -> list[str]:
        targets = [c for c in self.configs if self.wants(c, event)]
        if not targets:
            return []
        p = payload(event, renewal, endpoint, self.dashboard_url)
        names = []
        threads = []
        for cfg in targets:
            kind = cfg.get("type", "webhook")
            names.append(kind)
            t = threading.Thread(target=self._deliver, args=(cfg, kind, p), daemon=True, name="farrier-notify")
            t.start()
            threads.append(t)
        if wait:
            for t in threads:
                t.join(6)
        return names

    def _deliver(self, cfg: dict, kind: str, p: dict):
        try:
            if kind in EMAIL_TYPES:
                send_email(cfg, p)
                return
            url = resolve_secret(cfg["url"])
            headers = {k: resolve_secret(v) for k, v in (cfg.get("headers") or {}).items()}
            r = httpx.post(url, json=body_for(kind, p), headers=headers, timeout=5)
            r.raise_for_status()
        except Exception as e:  # noqa: BLE001 - a notifier must never break a renewal
            # never log the URL: webhook URLs are secrets
            self.log(f"{kind} notification for {p['event']} failed: {type(e).__name__}", None, p.get("renewal_id"),
                     level="warning")
