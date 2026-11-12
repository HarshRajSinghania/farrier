"""ServiceNow over the Table API (/api/now/table), no SDK.

    {"type": "servicenow", "instance": "acme.service-now.com", "auth": "basic",
     "username": "farrier.integration", "password": "vault:SNOW_PASSWORD",
     "table": "change_request", "assignment_group": "PKI", "category": "Security",
     "cmdb_ci_field": "name", "tickets": true}

auth: basic (username + password) or oauth (OAuth client credentials: client_id + client_secret against
/oauth_token.do; the token is cached in memory until shortly before it expires and refreshed on a 401).

Idempotency: every ticket Farrier opens carries correlation_id ``farrier:<instance id>:<renewal id>``
(a field of the task table, so of incident and change_request); before creating, Farrier looks it up, so a
retry after a crash or a timeout finds the ticket instead of opening a second one.

Notes go in work_notes. Closing: incident -> state 6 Resolved (close_code, close_notes), then 7 Closed
when resolve_state is "closed"; change_request -> state 0 Review, then 3 Closed when resolve_state is
"closed" (close_code "successful").
"""
from __future__ import annotations

import re
import threading
import time
from typing import ClassVar

from farrier.itsm.base import (
    HOST,
    Ticket,
    TicketAdapter,
    TicketSpec,
    as_bool,
    field,
    require_ref,
    secret,
)
from farrier.itsm.http import Http, ItsmError

TABLES = ("incident", "change_request")
STATES = {"incident": {"resolved": "6", "closed": "7"}, "change_request": {"review": "0", "closed": "3"}}
DEFAULT_RESOLVE = {"incident": "resolved", "change_request": "review"}
SAFE_QUERY_VALUE = re.compile(r"^[^\^\r\n=]{1,200}$")      # no encoded-query operators

_tokens: dict[tuple[str, str], tuple[str, float]] = {}     # (instance, client_id) -> (token, expires at)
_tokens_lock = threading.Lock()


class ServiceNow(TicketAdapter):
    kind = "servicenow"
    label = "ServiceNow"
    FIELDS: ClassVar[list[dict]] = [
        field("instance", "Instance", required=True, help="e.g. acme.service-now.com"),
        field("auth", "Authentication", help="basic (default): username + password; oauth: client credentials"),
        field("username", "Username", help="Basic auth: an integration user with itil (and cmdb_read) roles"),
        field("password", "Password", secret=True, help="Basic auth"),
        field("client_id", "OAuth client ID", help="OAuth: an Application Registry entry with client credentials"),
        field("client_secret", "OAuth client secret", secret=True, help="OAuth"),
        field("table", "Table", help="incident (default) or change_request"),
        field("assignment_group", "Assignment group", help="Group name (or sys_id)"),
        field("category", "Category", help="Optional category value"),
        field("cmdb_ci_field", "CMDB CI from", help="name or host: look up cmdb_ci by the endpoint's name or host "
                                                     "(best effort; left empty when there is no match)"),
        field("close_code", "Close code", help="Incident resolution code (default \"Solution provided\")"),
        field("resolve_state", "Resolve to", help="incident: resolved (default) or closed; change_request: review "
                                                  "(default) or closed"),
        field("tickets", "Ticket lifecycle", help="true: one ticket per manual renewal (opened when the change pack "
                                                  "is ready, noted on each state change, resolved when verified live)"),
    ]

    @classmethod
    def validate(cls, body: dict, allow_inline: bool = False) -> dict:
        inst = str(body.get("instance", "")).strip().removeprefix("https://").rstrip("/")
        if not HOST.match(inst):
            raise ValueError("instance must be a host name such as acme.service-now.com")
        body["instance"] = inst.lower()
        auth = body.setdefault("auth", "basic")
        if auth == "basic":
            if not body.get("username") or not body.get("password"):
                raise ValueError("basic auth needs username and password")
        elif auth == "oauth":
            if not body.get("client_id") or not body.get("client_secret"):
                raise ValueError("oauth needs client_id and client_secret")
        else:
            raise ValueError("auth must be basic or oauth")
        for k in ("password", "client_secret"):
            require_ref(body, k, allow_inline)
        table = body.setdefault("table", "incident")
        if table not in TABLES:
            raise ValueError("table must be incident or change_request")
        rs = body.get("resolve_state")
        if rs not in (None, "") and rs not in STATES[table]:
            raise ValueError(f"resolve_state for {table} must be one of {', '.join(STATES[table])}")
        if body.get("cmdb_ci_field") not in (None, "", "name", "host"):
            raise ValueError("cmdb_ci_field must be name or host")
        body["tickets"] = as_bool(body.get("tickets"), False)
        return body

    @classmethod
    def target(cls, cfg: dict) -> str:
        return f"{cfg.get('table', 'incident')} on {cfg.get('instance')}"

    def __init__(self, cfg: dict, transport=None):
        super().__init__(cfg, transport)
        self.instance = cfg["instance"]
        self.table = cfg.get("table") or "incident"
        base = f"https://{self.instance}"
        headers = {"Accept": "application/json", "Content-Type": "application/json"}
        secrets: list[str] = []
        refresh = None
        auth = None
        if cfg.get("auth", "basic") == "oauth":
            cid, csec = cfg["client_id"], secret(cfg, "client_secret")
            secrets.append(csec)
            refresh = lambda: {"Authorization": f"Bearer {self._token(cid, csec, force=True)}"}
            self._oauth = (cid, csec)
        else:
            pw = secret(cfg, "password")
            secrets.append(pw)
            auth = (cfg["username"], pw)
            self._oauth = None
        self.http = Http(base, headers, secrets=secrets, transport=transport, auth_refresh=refresh)
        if auth:
            self.http.client.auth = auth
        self._authed = auth is not None

    def _token(self, cid: str, csec: str, force: bool = False) -> str:
        key = (self.instance, cid)
        with _tokens_lock:
            tok = _tokens.get(key)
            if tok and not force and tok[1] > time.time() + 60:
                return tok[0]
        r = self.http.request("POST", "/oauth_token.do", idempotent=True, expect=(200,),
                              headers={"Content-Type": "application/x-www-form-urlencoded"},
                              data={"grant_type": "client_credentials", "client_id": cid, "client_secret": csec})
        j = r.json()
        if not j.get("access_token"):
            raise ItsmError(f"POST {self.instance}/oauth_token.do: no access_token in the answer")
        with _tokens_lock:
            _tokens[key] = (j["access_token"], time.time() + float(j.get("expires_in") or 1800))
        self.http._secrets.append(j["access_token"])
        return j["access_token"]

    def _auth(self) -> None:
        if not self._authed and self._oauth:
            self.http.headers["Authorization"] = f"Bearer {self._token(*self._oauth)}"
            self._authed = True

    def _get(self, path: str, params: dict) -> list[dict]:
        self._auth()
        return self.http.get(path, params=params).json().get("result") or []

    # ---- Test button ------------------------------------------------------------------------------
    def check(self) -> str:
        self._get("/api/now/table/sys_user", {"sysparm_limit": "1", "sysparm_fields": "sys_id"})
        return f"signed in to {self.instance}; the Table API answers"

    # ---- tickets ----------------------------------------------------------------------------------
    def _table_for(self, kind: str) -> str:
        return self.table if kind == "change" else "incident"

    def find(self, key: str, kind: str) -> Ticket | None:
        if not key:
            return None
        table = self._table_for(kind)
        rows = self._get(f"/api/now/table/{table}", {"sysparm_query": f"correlation_id={key}",
                                                     "sysparm_fields": "sys_id,number", "sysparm_limit": "1"})
        return Ticket(rows[0]["number"], rows[0]["sys_id"], table) if rows else None

    def _ci(self, spec: TicketSpec) -> str | None:
        """Best effort: the sys_id of the cmdb_ci whose name is the endpoint's name/host."""
        which = self.cfg.get("cmdb_ci_field")
        value = (spec.ci or {}).get(which) if which else None
        if not value or not SAFE_QUERY_VALUE.match(str(value)):
            return None
        try:
            rows = self._get("/api/now/table/cmdb_ci", {"sysparm_query": f"name={value}", "sysparm_fields": "sys_id",
                                                        "sysparm_limit": "1"})
        except ItsmError:
            return None
        return rows[0]["sys_id"] if rows else None

    def open(self, spec: TicketSpec) -> Ticket:
        self._auth()
        table = self._table_for(spec.kind)
        body = {"short_description": spec.summary[:160], "description": spec.description}
        if spec.key:
            body |= {"correlation_id": spec.key, "correlation_display": "Farrier"}
        for k in ("assignment_group", "category"):
            if self.cfg.get(k):
                body[k] = self.cfg[k]
        if (ci := self._ci(spec)):
            body["cmdb_ci"] = ci
        # display values let assignment_group be given by name
        r = self.http.post(f"/api/now/table/{table}", params={"sysparm_input_display_value": "true",
                                                               "sysparm_fields": "sys_id,number"},
                           json=body, idempotent=False)
        res = r.json().get("result") or {}
        if not res.get("sys_id"):
            raise ItsmError(f"POST {self.instance}/api/now/table/{table}: no sys_id in the answer")
        return Ticket(res.get("number") or res["sys_id"], res["sys_id"], table,
                      f"https://{self.instance}/nav_to.do?uri={table}.do?sys_id={res['sys_id']}")

    def _patch(self, t: Ticket, body: dict) -> None:
        self._auth()
        self.http.request("PATCH", f"/api/now/table/{t.table or self.table}/{t.ext_id}", json=body,
                          idempotent=True, params={"sysparm_fields": "sys_id"})

    def comment(self, t: Ticket, text: str) -> None:
        self._patch(t, {"work_notes": text})

    def resolve(self, t: Ticket, text: str) -> None:
        table = t.table or self.table
        target = self.cfg.get("resolve_state") if table == self.table else None
        target = target or DEFAULT_RESOLVE[table]
        if table == "incident":
            close = {"close_code": self.cfg.get("close_code") or "Solution provided", "close_notes": text}
            self._patch(t, {"state": STATES[table]["resolved"], "work_notes": text, **close})
            if target == "closed":
                self._patch(t, {"state": STATES[table]["closed"]})
        else:
            close = {"close_code": "successful", "close_notes": text}
            self._patch(t, {"state": STATES[table]["review"], "work_notes": text, **close})
            if target == "closed":
                self._patch(t, {"state": STATES[table]["closed"]})
