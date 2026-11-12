"""Model Context Protocol server: Farrier as tools for Claude, Gemini CLI, Codex and other MCP clients.

JSON-RPC 2.0 implemented directly (no SDK dependency), protocol 2025-06-18 with negotiation down to
2025-03-26 and 2024-11-05. Two transports:

  stdio            ``farrier mcp``: newline-delimited JSON on stdin/stdout, logs on stderr.
  Streamable HTTP  ``POST /mcp`` on the API server (JSON responses, no SSE stream; GET returns 405).
                   Requires a bearer token (the read token gets read tools only), validates ``Origin``
                   against DNS rebinding, and issues an ``Mcp-Session-Id`` bound to the token.

Write tools (``renew_endpoint``, ``cancel_renewal``) exist only for a session authenticated with the
admin token while ``FARRIER_MCP_ALLOW_WRITES=1``. For stdio, "authenticated with the admin token" means
``FARRIER_MCP_TOKEN`` equals ``FARRIER_API_TOKEN`` in the server's environment.

Tools never return private keys, sealed material, connector configs or settings. Every tool call is
written to the event log as ``mcp:<client name>``.
"""
from __future__ import annotations

import hashlib
import hmac
import io
import json
import os
import re
import secrets
import sys
import threading
import time
from collections import Counter, deque
from collections.abc import Callable
from typing import Any

from fastapi import Request

from farrier import __version__
from farrier.connectors import is_automated
from farrier.core import policy
from farrier.db.store import OPEN_STATES, parse_dt

PROTOCOL_VERSIONS = ("2025-06-18", "2025-03-26", "2024-11-05")
LATEST = PROTOCOL_VERSIONS[0]
ALL_STATES = ("planned", "issued", "deploying", "verifying", "awaiting_manual", "done", "failed", "rolled_back",
              "cancelled", "superseded")
PUBLIC_ENDPOINT_FIELDS = ("id", "name", "host", "port", "sni", "common_name", "sans", "key_type", "connector",
                          "issuer", "window", "lead_days", "owner", "tags", "enabled", "fingerprint", "subject_cn",
                          "cert_issuer", "not_before", "not_after", "observed_at", "scan_error")
_CLIENT = re.compile(r"[^A-Za-z0-9._@-]+")

PARSE_ERROR, INVALID_REQUEST, METHOD_NOT_FOUND, INVALID_PARAMS, INTERNAL_ERROR = -32700, -32600, -32601, -32602, -32603

INSTRUCTIONS = ("Farrier renews TLS certificates across an estate of servers and appliances. Use list_endpoints / "
                "expiring_certificates to see what is served and when it expires, renewal_status for work in "
                "flight, domain_health for a TLS report card on any host, and find_zombies for certificates that "
                "should not be alive. renew_endpoint and cancel_renewal change production and are only offered "
                "when the operator enabled writes.")


def _truthy(v: str | None) -> bool:
    return (v or "").strip().lower() in ("1", "true", "yes", "on")


def writes_allowed_by_env() -> bool:
    return _truthy(os.environ.get("FARRIER_MCP_ALLOW_WRITES"))


def client_label(name: str | None) -> str:
    return (_CLIENT.sub("-", name or "").strip("-")[:48]) or "unknown"


# ---- a small JSON Schema subset validator ----------------------------------------------------------
def validate(schema: dict, value: Any, path: str = "arguments") -> list[str]:
    errs: list[str] = []
    t = schema.get("type")
    types = {"object": dict, "array": list, "string": str, "boolean": bool}
    if t == "integer":
        if isinstance(value, bool) or not (isinstance(value, int) or (isinstance(value, float) and value.is_integer())):
            return [f"{path} must be an integer"]
    elif t == "number":
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            return [f"{path} must be a number"]
    elif t in types and not isinstance(value, types[t]):
        return [f"{path} must be {'an' if t[0] in 'aeiou' else 'a'} {t}"]
    if "enum" in schema and value not in schema["enum"]:
        errs.append(f"{path} must be one of {', '.join(map(str, schema['enum']))}")
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if "minimum" in schema and value < schema["minimum"]:
            errs.append(f"{path} must be >= {schema['minimum']}")
        if "maximum" in schema and value > schema["maximum"]:
            errs.append(f"{path} must be <= {schema['maximum']}")
    if isinstance(value, str):
        if "minLength" in schema and len(value) < schema["minLength"]:
            errs.append(f"{path} must be at least {schema['minLength']} characters")
        if "maxLength" in schema and len(value) > schema["maxLength"]:
            errs.append(f"{path} must be at most {schema['maxLength']} characters")
        if "pattern" in schema and not re.search(schema["pattern"], value):
            errs.append(f"{path} has an invalid format")
    if isinstance(value, dict):
        props = schema.get("properties", {})
        for r in schema.get("required", []):
            if r not in value:
                errs.append(f"{path}.{r} is required")
        for k, v in value.items():
            if k in props:
                errs += validate(props[k], v, f"{path}.{k}")
            elif schema.get("additionalProperties") is False:
                errs.append(f"{path}.{k} is not a known argument")
        for group in schema.get("x-oneRequired", []):
            if sum(1 for k in group if k in value) != 1:
                errs.append(f"{path}: give exactly one of {', '.join(group)}")
    if isinstance(value, list) and "items" in schema:
        for i, v in enumerate(value):
            errs += validate(schema["items"], v, f"{path}[{i}]")
    return errs


def _public(schema: dict) -> dict:
    """Strip private validator keywords before advertising a schema."""
    return {k: (_public(v) if isinstance(v, dict) else v) for k, v in schema.items() if not k.startswith("x-")}


class ToolError(Exception):
    """A business-level failure reported to the model as an isError result."""


# ---- sessions -----------------------------------------------------------------------------------
class Session:
    def __init__(self, role: str, token_digest: str | None = None, sid: str | None = None):
        self.id = sid
        self.role = role                     # "admin" | "read"
        self.token_digest = token_digest
        self.client_name = "unknown"
        self.client_version = None
        self.protocol = "2025-03-26"         # assumed until initialize says otherwise (spec default for HTTP)
        self.initialized = False
        self.created = self.last_used = time.time()
        self._calls: deque[float] = deque()

    @property
    def actor(self) -> str:
        return f"mcp:{client_label(self.client_name)}"

    def rate_ok(self, per_minute: int) -> bool:
        now = time.time()
        while self._calls and now - self._calls[0] > 60:
            self._calls.popleft()
        if len(self._calls) >= per_minute:
            return False
        self._calls.append(now)
        return True


# ---- the server ---------------------------------------------------------------------------------
class MCPServer:
    def __init__(self, engine, lock: threading.RLock | None = None, rate_per_minute: int = 120):
        self.engine = engine
        self.S = engine.store
        self.lock = lock or threading.RLock()
        self.rate = rate_per_minute
        self.tools = self._tools()

    # -- tool catalogue
    def _tools(self) -> dict[str, dict]:
        RO = {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False}
        T: dict[str, dict] = {}

        def tool(name, title, description, props=None, required=(), annotations=None, write=False, extra=None):
            def deco(fn: Callable):
                schema = {"type": "object", "properties": props or {}, "additionalProperties": False}
                if required:
                    schema["required"] = list(required)
                schema.update(extra or {})
                T[name] = {"name": name, "title": title, "description": description, "inputSchema": schema,
                           "annotations": {"title": title, **(annotations or RO)}, "write": write, "fn": fn}
                return fn
            return deco

        @tool("list_endpoints", "List endpoints",
              "Every TLS endpoint Farrier tracks with the certificate it serves now (subject, issuer, expiry, "
              "days left, last scan error). Optional case-insensitive filter on name/host/owner/tag.",
              {"filter": {"type": "string", "maxLength": 200, "description": "substring match"},
               "limit": {"type": "integer", "minimum": 1, "maximum": 2000, "default": 200}})
        def list_endpoints(a, s):
            f = (a.get("filter") or "").lower()
            rows = [self._ep(e) for e in self.S.endpoints()]
            if f:
                rows = [e for e in rows if f in " ".join(map(str, [e["name"], e["host"], e["owner"] or "",
                                                                  *e["tags"]])).lower()]
            limit = int(a.get("limit", 200))
            return {"total": len(rows), "endpoints": rows[:limit]}

        @tool("get_endpoint", "Get one endpoint",
              "One endpoint in detail: served certificate, recent renewals and recent events.",
              {"id": {"type": "integer", "minimum": 1, "description": "endpoint id"}}, required=("id",))
        def get_endpoint(a, s):
            eid = int(a["id"])
            e = next((x for x in self.S.endpoints() if x["id"] == eid), None)
            if not e:
                raise ToolError(f"no endpoint with id {eid}")
            ren = [r for r in self.S.renewals(limit=100000) if r["endpoint_id"] == eid][-10:]
            ev = self.S.q("SELECT at, level, renewal_id, message FROM events WHERE endpoint_id=? ORDER BY id DESC LIMIT 20",
                          (eid,))
            return {"endpoint": self._ep(e), "renewals": ren, "events": ev}

        @tool("expiring_certificates", "Expiring certificates",
              "Endpoints whose served certificate expires within `days` days (expired ones included), soonest first.",
              {"days": {"type": "integer", "minimum": 0, "maximum": 3650, "default": 30}})
        def expiring(a, s):
            days = int(a.get("days", 30))
            now = policy.utcnow()
            rows = []
            for e in self.S.endpoints():
                na = parse_dt(e["not_after"])
                if na and policy.days_left(na, now) <= days:
                    open_r = self.S.open_renewal(e["id"])
                    rows.append(self._ep(e) | {"open_renewal": open_r and {"id": open_r["id"], "state": open_r["state"],
                                                                           "scheduled_for": open_r["scheduled_for"]}})
            rows.sort(key=lambda r: r["days_left"])
            return {"days": days, "count": len(rows), "certificates": rows}

        @tool("renewal_status", "Renewal status",
              "Renewals by state, and the renewals in flight (or in `state`). Includes manual change packs waiting "
              "for a human and failures that need attention.",
              {"state": {"type": "string", "enum": ["open", *ALL_STATES], "default": "open"},
               "endpoint_id": {"type": "integer", "minimum": 1},
               "limit": {"type": "integer", "minimum": 1, "maximum": 1000, "default": 100}})
        def renewal_status(a, s):
            allr = self.S.renewals(limit=100000)
            st = a.get("state", "open")
            want = OPEN_STATES if st == "open" else (st,)
            rows = [r for r in allr if r["state"] in want and
                    ("endpoint_id" not in a or r["endpoint_id"] == int(a["endpoint_id"]))]
            return {"counts": dict(Counter(r["state"] for r in allr)), "state": st, "count": len(rows),
                    "renewals": rows[: int(a.get("limit", 100))]}

        @tool("domain_health", "Domain health check",
              "TLS report card for an inventory endpoint (endpoint_id) or any target (host, host:port, "
              "sni@ip:port): chain completeness and order, hostname match, expiry, lifetime vs the CA/B Forum "
              "maximum, key, signature algorithm, TLS versions, OCSP stapling, CAA, and whether it serves what "
              "Farrier deployed. Connects to the target over the network.",
              {"target": {"type": "string", "minLength": 1, "maxLength": 300},
               "endpoint_id": {"type": "integer", "minimum": 1},
               "caa": {"type": "boolean", "default": True, "description": "look up CAA records in public DNS"}},
              annotations={**RO, "idempotentHint": False, "openWorldHint": True},
              extra={"x-oneRequired": [["target", "endpoint_id"]]})
        def domain_health(a, s):
            from farrier.core.discovery import expand_targets
            from farrier.monitoring import health
            caa = bool(a.get("caa", True))
            if "endpoint_id" in a:
                ep = self.S.endpoint(int(a["endpoint_id"]))
                if not ep:
                    raise ToolError(f"no endpoint with id {a['endpoint_id']}")
                return health.check_endpoint(self.engine, ep, caa=caa)
            if s.role != "admin":
                # probing an arbitrary host is a server-side request; same rule as POST /api/health
                raise ToolError("read-only access can check inventory endpoints only: pass endpoint_id")
            try:
                targets = expand_targets(a["target"])
            except ValueError as e:
                raise ToolError(str(e)) from None
            if len(targets) != 1:
                raise ToolError("give exactly one host[:port] (ranges and lists are not accepted here)")
            return health.check_targets(self.engine, targets, caa=caa)[0]

        @tool("find_zombies", "Find zombie certificates",
              "Certificates that are alive but should not be, from stored observations: expired certs still "
              "served, nodes serving a certificate a verified renewal replaced, names served by another CA or "
              "issued outside Farrier, endpoints dead for N days, change packs never installed, unclaimed "
              "discovered endpoints.",
              {"dead_days": {"type": "integer", "minimum": 1, "maximum": 365, "default": 7},
               "pack_days": {"type": "integer", "minimum": 0, "maximum": 365, "default": 3}})
        def find_zombies(a, s):
            from farrier.monitoring import zombie
            return zombie.summarize(zombie.from_store(self.S, dead_days=int(a.get("dead_days", 7)),
                                                      pack_days=int(a.get("pack_days", 3))))

        @tool("forecast", "Renewal workload forecast",
              "Renewals per year/working day and manual hours under each step of the CA/B Forum lifetime schedule "
              "(200 days from 2026-03-15, 100 from 2027, 47 from 2029).",
              {"certs": {"type": "integer", "minimum": 1, "maximum": 10_000_000},
               "manual": {"type": "number", "minimum": 0, "maximum": 1, "description": "fraction needing a human"},
               "minutes": {"type": "number", "minimum": 1, "maximum": 1440, "default": 45},
               "lead": {"type": "integer", "minimum": 0, "maximum": 365, "default": 0}},
              required=("certs", "manual"), annotations={**RO, "openWorldHint": False})
        def forecast(a, s):
            return {"timeline": policy.forecast_timeline(int(a["certs"]), float(a["manual"]),
                                                         float(a.get("minutes", 45)), int(a.get("lead", 0)))}

        W = {"readOnlyHint": False, "destructiveHint": True, "idempotentHint": False, "openWorldHint": True}

        @tool("renew_endpoint", "Renew an endpoint now",
              "Start (or pull forward) a renewal for an endpoint and push it as far as it can go: issue, deploy, "
              "verify; manual endpoints get a change pack. Changes production.",
              {"id": {"type": "integer", "minimum": 1, "description": "endpoint id"}}, required=("id",),
              annotations=W, write=True)
        def renew_endpoint(a, s):
            eid = int(a["id"])
            if not self.S.endpoint(eid):
                raise ToolError(f"no endpoint with id {eid}")
            with self.lock:
                try:
                    rid = self.engine.force_renewal(eid, f"requested by {s.actor}")
                except ValueError as e:
                    raise ToolError(str(e)) from None
                state = self.engine.advance(rid)
            return {"renewal_id": rid, "state": state}

        @tool("cancel_renewal", "Cancel a renewal",
              "Cancel an open renewal (planned, issued, verifying or awaiting a manual install); its change pack "
              "and private key are deleted.",
              {"id": {"type": "integer", "minimum": 1, "description": "renewal id"}}, required=("id",),
              annotations={**W, "idempotentHint": True, "openWorldHint": False}, write=True)
        def cancel_renewal(a, s):
            with self.lock:
                try:
                    self.engine.cancel(int(a["id"]), f"cancelled by {s.actor}")
                except ValueError as e:
                    raise ToolError(f"renewal {a['id']}: {e}") from None
            return {"renewal_id": int(a["id"]), "state": "cancelled"}

        return T

    def _ep(self, e: dict) -> dict:
        out = {k: e.get(k) for k in PUBLIC_ENDPOINT_FIELDS}
        out["enabled"] = bool(out["enabled"])
        out["automated"] = is_automated(e["connector"])
        na = parse_dt(e.get("not_after"))
        out["days_left"] = round(policy.days_left(na), 1) if na else None
        return out

    def writes_enabled(self, s: Session) -> bool:
        return s.role == "admin" and writes_allowed_by_env()

    def visible_tools(self, s: Session) -> list[dict]:
        out = []
        for t in self.tools.values():
            if t["write"] and not self.writes_enabled(s):
                continue
            d = {k: t[k] for k in ("name", "title", "description", "annotations")}
            d["inputSchema"] = _public(t["inputSchema"])
            if s.protocol == "2024-11-05":  # titles arrived in 2025-06-18; older clients ignore unknown keys anyway
                d.pop("title")
            out.append(d)
        return out

    # -- JSON-RPC
    @staticmethod
    def _err(mid, code: int, message: str, data=None) -> dict:
        e = {"code": code, "message": message}
        if data is not None:
            e["data"] = data
        return {"jsonrpc": "2.0", "id": mid, "error": e}

    def handle(self, msg: Any, s: Session) -> dict | None:
        """One JSON-RPC message in, one response (or None for notifications and client responses) out."""
        if not isinstance(msg, dict) or msg.get("jsonrpc") != "2.0":
            mid = msg.get("id") if isinstance(msg, dict) else None
            return self._err(mid, INVALID_REQUEST, "not a JSON-RPC 2.0 message")
        if "method" not in msg:
            return None  # a response to a server request; we never send any
        method, mid, is_req = msg["method"], msg.get("id"), "id" in msg
        if is_req and not (isinstance(mid, (str, int)) and not isinstance(mid, bool)):
            return self._err(None, INVALID_REQUEST, "id must be a string or integer")
        params = msg.get("params") or {}
        if not isinstance(params, dict):
            return self._err(mid, INVALID_PARAMS, "params must be an object") if is_req else None
        s.last_used = time.time()
        if not is_req:
            if method == "notifications/initialized":
                s.initialized = True
            return None  # notifications/cancelled etc.: nothing to do
        try:
            if method == "initialize":
                return {"jsonrpc": "2.0", "id": mid, "result": self._initialize(params, s)}
            if method == "ping":
                return {"jsonrpc": "2.0", "id": mid, "result": {}}
            if method == "tools/list":
                return {"jsonrpc": "2.0", "id": mid, "result": {"tools": self.visible_tools(s)}}
            if method == "tools/call":
                return self._call(mid, params, s)
            return self._err(mid, METHOD_NOT_FOUND, f"method not found: {method}")
        except Exception as e:
            print(f"farrier mcp: {method} failed: {type(e).__name__}: {e}", file=sys.stderr)
            return self._err(mid, INTERNAL_ERROR, "internal error")

    def _initialize(self, params: dict, s: Session) -> dict:
        asked = params.get("protocolVersion")
        s.protocol = asked if asked in PROTOCOL_VERSIONS else LATEST
        info = params.get("clientInfo") if isinstance(params.get("clientInfo"), dict) else {}
        s.client_name = client_label(str(info.get("name", "")))
        s.client_version = str(info.get("version", ""))[:32] or None
        self.S.log(f"MCP session started by {s.actor} ({s.role} access, protocol {s.protocol}, "
                   f"writes {'enabled' if self.writes_enabled(s) else 'disabled'})")
        server_info = {"name": "farrier", "version": __version__}
        if s.protocol != "2024-11-05":
            server_info["title"] = "Farrier certificate renewal"
        return {"protocolVersion": s.protocol, "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": server_info, "instructions": INSTRUCTIONS}

    def _call(self, mid, params: dict, s: Session) -> dict:
        name, args = params.get("name"), params.get("arguments", {})
        if args is None:
            args = {}
        t = self.tools.get(name) if isinstance(name, str) else None
        shown = json.dumps(args, default=str, separators=(",", ":"))[:200] if isinstance(args, dict) else "?"
        eid = args.get("id") if name == "renew_endpoint" and isinstance(args, dict) else \
            args.get("endpoint_id") if isinstance(args, dict) else None
        eid = eid if isinstance(eid, int) and not isinstance(eid, bool) and self.S.endpoint(eid) else None
        if t is None or (t["write"] and not self.writes_enabled(s)):
            self.S.log(f"{s.actor} called unavailable MCP tool {str(name)[:64]!r}", level="warning")
            hint = "" if t is None else (": write tools need the admin token and FARRIER_MCP_ALLOW_WRITES=1")
            return self._err(mid, INVALID_PARAMS, f"Unknown tool: {str(name)[:64]}{hint}")
        if not s.rate_ok(self.rate):
            self.S.log(f"{s.actor} MCP rate limit hit calling {name}", level="warning")
            return self._result(mid, {"error": f"rate limit: at most {self.rate} tool calls per minute"}, error=True)
        if not isinstance(args, dict):
            return self._err(mid, INVALID_PARAMS, "arguments must be an object")
        errs = validate(t["inputSchema"], args)
        if errs:
            self.S.log(f"{s.actor} called MCP tool {name} with invalid arguments {shown}", eid, level="warning")
            return self._err(mid, INVALID_PARAMS, f"Invalid arguments for {name}: " + "; ".join(errs[:10]),
                             {"errors": errs[:20]})
        self.S.log(f"{s.actor} called MCP tool {name} {shown}", eid,
                   level="warning" if t["write"] else "info")
        try:
            out = t["fn"](args, s)
        except ToolError as e:
            return self._result(mid, {"error": str(e)}, error=True)
        except Exception as e:
            self.S.log(f"MCP tool {name} failed for {s.actor}: {type(e).__name__}: {e}", eid, level="error")
            return self._result(mid, {"error": f"{name} failed: {type(e).__name__}: {str(e)[:300]}"}, error=True)
        return self._result(mid, out)

    def _result(self, mid, data: dict, error: bool = False) -> dict:
        text = json.dumps(data, default=str, ensure_ascii=False)
        return {"jsonrpc": "2.0", "id": mid, "result": {
            "content": [{"type": "text", "text": text}],
            "structuredContent": json.loads(text), "isError": error}}

    def handle_payload(self, payload: Any, s: Session) -> Any:
        """A message or (pre-2025-06-18) a batch. Returns a response, a list of them, or None."""
        if isinstance(payload, list):
            if not payload:
                return self._err(None, INVALID_REQUEST, "empty batch")
            out = [r for r in (self.handle(m, s) for m in payload) if r is not None]
            return out or None
        return self.handle(payload, s)


def dumps(obj) -> str:
    # compact JSON never contains a raw newline (they are escaped inside strings), as stdio framing requires
    return json.dumps(obj, separators=(",", ":"), default=str, ensure_ascii=False)


# ---- stdio transport ----------------------------------------------------------------------------
def stdio_role() -> str:
    admin = os.environ.get("FARRIER_API_TOKEN")
    given = os.environ.get("FARRIER_MCP_TOKEN")
    return "admin" if admin and given and hmac.compare_digest(admin.encode(), given.encode()) else "read"


def run_stdio(engine, stdin=None, stdout=None, role: str | None = None) -> None:
    stdin = stdin or sys.stdin.buffer
    stdout = stdout or sys.stdout.buffer
    server = MCPServer(engine)
    session = Session(role or stdio_role())
    print(f"farrier mcp: stdio server ready ({session.role} access, writes "
          f"{'enabled' if server.writes_enabled(session) else 'disabled'})", file=sys.stderr)
    for raw in stdin:
        line = raw.decode("utf-8", "replace").strip() if isinstance(raw, bytes) else raw.strip()
        if not line:
            continue
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            resp = MCPServer._err(None, PARSE_ERROR, "parse error")
        else:
            resp = server.handle_payload(payload, session)
        if resp is not None:
            data = dumps(resp) + "\n"
            stdout.write(data if isinstance(stdout, io.TextIOBase) else data.encode("utf-8"))
            stdout.flush()


# ---- Streamable HTTP transport --------------------------------------------------------------------
LOOPBACK = {"localhost", "127.0.0.1", "[::1]", "::1"}


def origin_allowed(origin: str | None) -> bool:
    """No Origin (a non-browser client) is fine. A browser Origin must be a loopback page or be listed in
    FARRIER_MCP_ALLOWED_ORIGINS. The Host header is not trusted: under DNS rebinding it carries the attacker's
    name too, so "Origin matches Host" proves nothing."""
    if not origin:
        return True
    o = origin.strip().rstrip("/").lower()
    allowed = {x.strip().rstrip("/").lower() for x in os.environ.get("FARRIER_MCP_ALLOWED_ORIGINS", "").split(",")
               if x.strip()}
    if o in allowed:
        return True
    m = re.match(r"^https?://(\[[^\]]+\]|[^:/\[\]]+)(?::\d+)?$", o)
    return bool(m) and m.group(1) in LOOPBACK


class SessionStore:
    def __init__(self, max_sessions: int = 1000, idle_seconds: float = 12 * 3600):
        self._d: dict[str, Session] = {}
        self._lock = threading.Lock()
        self.max, self.idle = max_sessions, idle_seconds

    def create(self, role: str, digest: str) -> Session:
        with self._lock:
            self._expire()
            if len(self._d) >= self.max:
                oldest = min(self._d.values(), key=lambda x: x.last_used)
                self._d.pop(oldest.id, None)
            s = Session(role, digest, secrets.token_urlsafe(32))
            self._d[s.id] = s
            return s

    def get(self, sid: str) -> Session | None:
        with self._lock:
            self._expire()
            return self._d.get(sid)

    def drop(self, sid: str) -> bool:
        with self._lock:
            return self._d.pop(sid, None) is not None

    def _expire(self):
        now = time.time()
        for k in [k for k, v in self._d.items() if now - v.last_used > self.idle]:
            del self._d[k]


def mount(app, engine, lock=None, path: str = "/mcp", max_body: int = 1 << 20) -> MCPServer:
    """Add the Streamable HTTP endpoint to a FastAPI app. Tokens are read from the environment at mount time,
    like the REST API's."""
    from fastapi.responses import JSONResponse, Response

    server = MCPServer(engine, lock)
    sessions = SessionStore()
    app.state.mcp = server
    admin_token = os.environ.get("FARRIER_API_TOKEN")
    read_token = os.environ.get("FARRIER_API_READ_TOKEN")

    def role_for(request: Request) -> tuple[str | None, str | None]:
        header = request.headers.get("authorization", "")
        given = header[7:].strip() if header[:7].lower() == "bearer " else ""
        if not given:
            return None, None
        digest = hashlib.sha256(given.encode()).hexdigest()
        if admin_token and hmac.compare_digest(given.encode(), admin_token.encode()):
            return "admin", digest
        if read_token and hmac.compare_digest(given.encode(), read_token.encode()):
            return "read", digest
        return None, None

    def rpc_error(status: int, message: str, code: int = INVALID_REQUEST, headers=None):
        return JSONResponse({"jsonrpc": "2.0", "id": None, "error": {"code": code, "message": message}},
                            status_code=status, headers=headers)

    def gate(request: Request):
        if not origin_allowed(request.headers.get("origin")):
            return None, rpc_error(403, "origin not allowed")
        if not admin_token and not read_token:
            return None, rpc_error(401, "MCP over HTTP needs FARRIER_API_TOKEN or FARRIER_API_READ_TOKEN to be set",
                                   headers={"WWW-Authenticate": "Bearer"})
        role, digest = role_for(request)
        if role is None:
            return None, rpc_error(401, "missing or bad bearer token", headers={"WWW-Authenticate": "Bearer"})
        pv = request.headers.get("mcp-protocol-version")
        if pv and pv not in PROTOCOL_VERSIONS:
            return None, rpc_error(400, f"unsupported MCP-Protocol-Version {pv[:32]}")
        return (role, digest), None

    @app.post(path, include_in_schema=False)
    async def mcp_post(request: Request):
        ok, err = gate(request)
        if err:
            return err
        role, digest = ok
        body = await request.body()
        if len(body) > max_body:
            return rpc_error(413, "request too large")
        try:
            payload = json.loads(body)
        except (json.JSONDecodeError, UnicodeDecodeError):
            return rpc_error(400, "parse error", PARSE_ERROR)
        msgs = payload if isinstance(payload, list) else [payload]
        is_init = any(isinstance(m, dict) and m.get("method") == "initialize" for m in msgs)
        sid = request.headers.get("mcp-session-id")
        headers = {}
        if is_init:
            if len(msgs) != 1:
                return rpc_error(400, "initialize must not be batched")
            session = sessions.create(role, digest)
            headers["Mcp-Session-Id"] = session.id
        else:
            if not sid:
                return rpc_error(400, "missing Mcp-Session-Id header; send initialize first")
            session = sessions.get(sid)
            if session is None:
                return rpc_error(404, "unknown or expired session; initialize again")
            if not hmac.compare_digest(session.token_digest, digest):
                return rpc_error(403, "this session belongs to a different token")
            if isinstance(payload, list) and session.protocol == "2025-06-18":
                return rpc_error(400, "JSON-RPC batching is not part of protocol 2025-06-18")
        import anyio
        resp = await anyio.to_thread.run_sync(server.handle_payload, payload, session)
        if resp is None:
            return Response(status_code=202, headers=headers)
        return JSONResponse(resp, headers=headers)

    @app.get(path, include_in_schema=False)
    async def mcp_get(request: Request):
        _ok, err = gate(request)
        if err:
            return err
        return Response(status_code=405, headers={"Allow": "POST, DELETE"})

    @app.delete(path, include_in_schema=False)
    async def mcp_delete(request: Request):
        ok, err = gate(request)
        if err:
            return err
        sid = request.headers.get("mcp-session-id")
        s = sessions.get(sid) if sid else None
        if s is None or not hmac.compare_digest(s.token_digest, ok[1]):
            return rpc_error(404, "unknown session")
        sessions.drop(sid)
        return Response(status_code=204)

    return server
