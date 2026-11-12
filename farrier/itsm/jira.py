"""Jira Cloud (REST v3, Atlassian Document Format) and Jira Data Center / Server (REST v2), no SDK.

    {"type": "jira", "base_url": "https://acme.atlassian.net", "email": "pki-bot@acme.com",
     "api_token": "vault:JIRA_TOKEN", "project_key": "OPS", "issue_type": "Task",
     "labels": ["tls"], "done_transition": "Done", "tickets": true}

Cloud: email + api_token (basic auth). Data Center: pat (a personal access token, sent as Bearer).
Idempotency: each ticket carries the label ``<instance id>-renewal-<id>``; before creating, Farrier
searches for it (JQL), so a retry after a crash or a timeout finds the issue instead of opening another.
Closing runs the transition named ``done_transition`` (matched on the transition's name, or the status it
leads to); if the workflow has no such transition the issue gets a comment saying so and stays open.
"""
from __future__ import annotations

import base64
import re
from typing import ClassVar
from urllib.parse import urlparse

from farrier.itsm.base import (
    Ticket,
    TicketAdapter,
    TicketSpec,
    as_bool,
    as_list,
    field,
    require_ref,
    secret,
)
from farrier.itsm.http import Http, ItsmError

PROJECT = re.compile(r"^[A-Z][A-Z0-9_]{0,49}$")
LABEL = re.compile(r"^[^\s\"]{1,255}$")


def adf(text: str) -> dict:
    """Plain text as an Atlassian Document Format document: one paragraph per line."""
    content = []
    for line in text.splitlines():
        content.append({"type": "paragraph", "content": [{"type": "text", "text": line}]} if line
                       else {"type": "paragraph", "content": []})
    return {"type": "doc", "version": 1, "content": content or [{"type": "paragraph", "content": []}]}


class Jira(TicketAdapter):
    kind = "jira"
    label = "Jira"
    FIELDS: ClassVar[list[dict]] = [
        field("base_url", "Base URL", required=True, help="https://acme.atlassian.net or your Data Center URL"),
        field("email", "Email", help="Jira Cloud: the account the API token belongs to"),
        field("api_token", "API token", secret=True, help="Jira Cloud (id.atlassian.com > Security > API tokens)"),
        field("pat", "Personal access token", secret=True, help="Jira Data Center / Server, instead of email + token"),
        field("project_key", "Project key", required=True, help="e.g. OPS"),
        field("issue_type", "Issue type", help="Default Task"),
        field("labels", "Labels", help="Extra labels, comma-separated"),
        field("done_transition", "Done transition", help="Workflow transition that closes the issue (default Done)"),
        field("tickets", "Ticket lifecycle", help="true: one issue per manual renewal (opened when the change pack "
                                                  "is ready, commented on each state change, closed when verified live)"),
    ]

    @classmethod
    def validate(cls, body: dict, allow_inline: bool = False) -> dict:
        u = urlparse(str(body.get("base_url", "")).strip())
        if u.scheme != "https" or not u.hostname or u.query or u.fragment:
            raise ValueError("base_url must be an https:// URL such as https://acme.atlassian.net")
        body["base_url"] = f"https://{u.netloc}{u.path.rstrip('/')}"
        if not body.get("pat") and not (body.get("email") and body.get("api_token")):
            raise ValueError("set email + api_token (Jira Cloud) or pat (Data Center)")
        for k in ("api_token", "pat"):
            require_ref(body, k, allow_inline)
        key = str(body.get("project_key", "")).strip().upper()
        if not PROJECT.match(key):
            raise ValueError("project_key must be a Jira project key such as OPS")
        body["project_key"] = key
        labels = as_list(body.get("labels"))
        if not all(LABEL.match(x) for x in labels):
            raise ValueError("labels may not contain spaces or quotes")
        if labels:
            body["labels"] = labels
        else:
            body.pop("labels", None)
        body["tickets"] = as_bool(body.get("tickets"), False)
        return body

    @classmethod
    def target(cls, cfg: dict) -> str:
        return f"{cfg.get('project_key')} on {urlparse(str(cfg.get('base_url'))).hostname}"

    def __init__(self, cfg: dict, transport=None):
        super().__init__(cfg, transport)
        self.cloud = not cfg.get("pat")
        self.api = "/rest/api/3" if self.cloud else "/rest/api/2"
        headers = {"Accept": "application/json", "Content-Type": "application/json"}
        if self.cloud:
            token = secret(cfg, "api_token")
            basic = base64.b64encode(f"{cfg['email']}:{token}".encode()).decode()
            headers["Authorization"] = f"Basic {basic}"
            secrets = [token, basic]
        else:
            token = secret(cfg, "pat")
            headers["Authorization"] = f"Bearer {token}"
            secrets = [token]
        self.http = Http(cfg["base_url"], headers, secrets=secrets, transport=transport)

    def _body(self, text: str):
        return adf(text) if self.cloud else text

    def check(self) -> str:
        me = self.http.get(f"{self.api}/myself").json()
        who = me.get("displayName") or me.get("name") or "the integration user"
        return f"signed in to Jira as {who}"

    # ---- tickets ----------------------------------------------------------------------------------
    def find(self, key: str, kind: str) -> Ticket | None:
        if not key:
            return None
        jql = f'project = "{self.cfg["project_key"]}" AND labels = "{key}"'
        path = f"{self.api}/search/jql" if self.cloud else f"{self.api}/search"
        issues = self.http.get(path, params={"jql": jql, "fields": "key", "maxResults": "1"}).json().get("issues") or []
        return Ticket(issues[0]["key"], issues[0]["key"], "issue") if issues else None

    def open(self, spec: TicketSpec) -> Ticket:
        labels = ["farrier", *(self.cfg.get("labels") or [])] + ([spec.key] if spec.key else [])
        fields = {"project": {"key": self.cfg["project_key"]},
                  "issuetype": {"name": self.cfg.get("issue_type") or "Task"},
                  "summary": spec.summary[:250], "description": self._body(spec.description),
                  "labels": list(dict.fromkeys(labels))}
        r = self.http.post(f"{self.api}/issue", json={"fields": fields}, idempotent=False)
        key = r.json().get("key")
        if not key:
            raise ItsmError(f"POST {self.api}/issue: no issue key in the answer")
        return Ticket(key, key, "issue", f"{self.cfg['base_url']}/browse/{key}")

    def comment(self, t: Ticket, text: str) -> None:
        # a retried comment could post twice; comments are cheap and say the same thing, so allow it
        self.http.post(f"{self.api}/issue/{t.ext_id}/comment", json={"body": self._body(text)}, idempotent=False)

    def resolve(self, t: Ticket, text: str) -> None:
        want = (self.cfg.get("done_transition") or "Done").strip().lower()
        ts = self.http.get(f"{self.api}/issue/{t.ext_id}/transitions").json().get("transitions") or []
        match = next((x for x in ts if str(x.get("name", "")).lower() == want), None) or \
            next((x for x in ts if str((x.get("to") or {}).get("name", "")).lower() == want), None)
        if match is None:
            self.comment(t, text + f"\n\nFarrier could not close this issue: no transition named "
                                   f"\"{self.cfg.get('done_transition') or 'Done'}\" is available.")
            raise ItsmError(f"Jira {t.ref}: no transition named {self.cfg.get('done_transition') or 'Done'}")
        self.comment(t, text)
        self.http.post(f"{self.api}/issue/{t.ext_id}/transitions", json={"transition": {"id": match["id"]}},
                       idempotent=True)
