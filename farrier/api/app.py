"""HTTP API + dashboard."""
from __future__ import annotations

import hmac
import io
import os
import re
import threading
import zipfile
from collections import Counter
from contextlib import asynccontextmanager
from datetime import timedelta

import httpx
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, StreamingResponse
from pydantic import BaseModel, Field

from farrier.api.scope import HEADER as SCOPE_HEADER
from farrier.api.scope import Guard, ScopeError
from farrier.api.scope import parse as parse_scope
from farrier.connectors import REGISTRY, is_automated, make_connector
from farrier.core import policy
from farrier.core.discovery import expand_targets, scan
from farrier.core.engine import Engine, NotApproved
from farrier.db.store import OPEN_STATES, parse_dt
from farrier.security.vault import REF_PREFIXES, SecretRefused, check_secret_refs


INDEX_HTML = """<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Farrier engine API</title>
<meta name="viewport" content="width=device-width, initial-scale=1"></head>
<body style="font-family:system-ui,sans-serif;max-width:40rem;margin:3rem auto;padding:0 1rem;line-height:1.5">
<h1>Farrier engine API</h1>
<p>This is the Farrier engine API. The dashboard is the web app (<code>web/</code>): <code>docker compose up</code>
runs both, or run <code>cd web &amp;&amp; FARRIER_API_URL=http://&lt;host&gt;:&lt;port&gt; npm run dev</code>
and open <code>http://localhost:3000/dashboard</code>.</p>
<ul><li><a href="/docs">OpenAPI reference</a> (<code>/docs</code>)</li>
<li><a href="https://github.com/gagankarthik/farrier">Project documentation</a></li></ul>
</body></html>
"""


class EndpointIn(BaseModel):
    name: str
    host: str
    port: int = 443
    sni: str | None = None
    common_name: str | None = None
    sans: list[str] = Field(default_factory=list)
    key_type: str = "ec256"
    connector: str = "manual"
    connector_config: dict = Field(default_factory=dict)
    issuer: str = "default"
    window: dict = Field(default_factory=dict)
    lead_days: int = 0
    owner: str | None = None
    tags: list[str] = Field(default_factory=list)
    enabled: bool = True
    project: str | None = None      # where a new endpoint goes (default: "default"); move one with /move


class DiscoverIn(BaseModel):
    targets: str
    project: str | None = None      # discovery: the project new endpoints land in


# Config keys that make Farrier run a command on its own host (or over SSH). Accepting them from the
# API would turn an API token into shell access, so they are refused unless the operator opts in.
# Inventory files imported with the CLI (`farrier import`) are trusted and may use them.
COMMAND_KEYS = {"test_command", "reload_command", "ssh", "dns_hook"}
ACTOR = re.compile(r"^[A-Za-z0-9._@-]{1,64}$")


def _command_keys(obj, path="") -> list[str]:
    found = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k in COMMAND_KEYS:
                found.append(f"{path}{k}")
            found += _command_keys(v, f"{path}{k}.")
    elif isinstance(obj, list):
        for v in obj:
            found += _command_keys(v, path)
    return found


# Config keys that hold credentials. Their values must be env:/file: references, never the secret itself,
# so a password or API key is never written to the database in plaintext or echoed back by a backup.
SECRET_KEY = re.compile(r"pass(word|phrase)?|secret|token|api[_-]?key|hmac|private[_-]?key|authorization|credential", re.IGNORECASE)


def _inline_secrets(obj, path="") -> list[str]:
    found = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(v, str) and v and SECRET_KEY.search(str(k)) and not v.startswith(REF_PREFIXES):
                found.append(f"{path}{k}")
            found += _inline_secrets(v, f"{path}{k}.")
    elif isinstance(obj, list):
        for v in obj:
            found += _inline_secrets(v, path)
    return found


def _same(a: str | None, b: str | None) -> bool:
    return bool(a) and bool(b) and hmac.compare_digest(a.encode(), b.encode())


def create_app(engine: Engine, tick_seconds: float | None = None) -> FastAPI:
    lock = threading.RLock()
    stop = threading.Event()

    def ticker():
        while not stop.wait(tick_seconds):
            try:
                with lock:
                    engine.tick()
            except Exception as e:  # noqa: BLE001
                engine.store.log(f"tick failed: {e}", level="error")

    @asynccontextmanager
    async def lifespan(_app):
        t = None
        if tick_seconds:
            t = threading.Thread(target=ticker, daemon=True, name="farrier-ticker")
            t.start()
        yield
        stop.set()

    app = FastAPI(title="Farrier", lifespan=lifespan)
    token = os.environ.get("FARRIER_API_TOKEN")             # admin: read and change
    read_token = os.environ.get("FARRIER_API_READ_TOKEN")   # optional: read only
    allow_commands = os.environ.get("FARRIER_ALLOW_API_COMMANDS", "").lower() in ("1", "true", "yes")
    allow_inline = os.environ.get("FARRIER_ALLOW_INLINE_SECRETS", "").lower() in ("1", "true", "yes")

    def auth(request: Request):
        """Every route depends on this. Reads accept either token; anything else needs the admin one.
        Then the project scope (farrier.api.scope): the dashboard's signed header, or full access."""
        _token_check(request)
        raw = request.headers.get(SCOPE_HEADER)
        if raw is not None:
            try:
                request.state.scope = parse_scope(raw, token, request.method, request.url.path,
                                                  engine.store.default_project_id())
            except ScopeError as e:
                raise HTTPException(401, str(e)) from None

    def _token_check(request: Request):
        if not token and not read_token:
            return  # loopback development: `serve` refuses a public bind without a token
        header = request.headers.get("authorization", "")
        given = header[7:] if header.startswith("Bearer ") else None
        if _same(given, token):
            return
        if request.method in ("GET", "HEAD") and _same(given, read_token):
            return
        if _same(given, read_token):
            raise HTTPException(403, "this token is read-only")
        raise HTTPException(401, "missing or bad bearer token")

    def secret_read(request: Request):
        """A read that hands out key material (change packs): the admin token only, never the read token."""
        if not token and not read_token:
            return
        header = request.headers.get("authorization", "")
        if not _same(header[7:] if header.startswith("Bearer ") else None, token):
            raise HTTPException(403, "change packs carry private keys; this needs the admin token")

    def actor(request: Request) -> str:
        """Who made a change, for the audit log. The dashboard forwards its signed-in user."""
        name = request.headers.get("x-farrier-actor", "")
        return name if ACTOR.match(name) else "api"

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        if request.url.path.startswith("/api/"):
            response.headers.setdefault("Cache-Control", "no-store")
        return response

    S = engine.store
    guard = Guard(S)
    scope_of = guard.of
    whole_install = [Depends(auth), Depends(guard.global_only)]   # changes that are not one project's

    @app.get("/healthz", include_in_schema=False)
    def healthz():
        """Liveness/readiness for load balancers and Kubernetes. Unauthenticated and reveals nothing."""
        S.q("SELECT 1")
        return {"ok": True}

    @app.get("/", include_in_schema=False)
    @app.get("/dashboard", include_in_schema=False)
    def index():
        # The dashboard is the separate Next.js app in web/. Unauthenticated, static, no data.
        return HTMLResponse(INDEX_HTML)

    @app.get("/api/summary", dependencies=[Depends(auth)])
    def summary(request: Request):
        now = policy.utcnow()
        sc = scope_of(request)
        eps = [e for e in S.endpoints() if sc.has_row(e)]
        buckets = Counter()
        for e in eps:
            na = parse_dt(e["not_after"])
            if na is None:
                buckets["unknown"] += 1
                continue
            d = (na - now).days
            buckets["expired" if d < 0 else "7d" if d < 7 else "30d" if d < 30 else "90d" if d < 90 else "later"] += 1
        auto = sum(1 for e in eps if is_automated(e["connector"]))
        manual_frac = (len(eps) - auto) / len(eps) if eps else 0.0
        renewals = S.renewals(limit=100000, scope=sc)
        states = Counter(r["state"] for r in renewals)

        # 90-day calendar: scheduled renewals + projected (not yet planned) due dates
        cal: dict[str, dict] = {}
        for i in range(90):
            day = (now + timedelta(days=i)).date().isoformat()
            cal[day] = {"date": day, "auto": 0, "manual": 0, "projected_auto": 0, "projected_manual": 0}
        open_eps = set()
        for r in renewals:
            if r["state"] in OPEN_STATES:
                open_eps.add(r["endpoint_id"])
                day = max(r["scheduled_for"][:10], now.date().isoformat())
                if day in cal:
                    cal[day]["auto" if is_automated(r["connector"]) else "manual"] += 1
        for e in eps:
            if e["id"] in open_eps or not e["not_after"] or not e["enabled"]:
                continue
            nb, na = parse_dt(e["not_before"]), parse_dt(e["not_after"])
            lifetime = min(max(1, (na - nb).days), policy.max_lifetime_days(now))
            due = na - timedelta(days=policy.renew_before_days(lifetime, e["lead_days"]))
            day = max(due.date().isoformat(), now.date().isoformat())
            if day in cal:
                cal[day]["projected_auto" if is_automated(e["connector"]) else "projected_manual"] += 1
        return {
            "now": now.isoformat(timespec="seconds"),
            "policy": {"max_lifetime_days": policy.max_lifetime_days(now), "dcv_reuse_days": policy.dcv_reuse_days(now),
                       "schedule": [{"from": d.isoformat(), "days": l, "dcv": v} for d, l, v in policy.SCHEDULE]},
            "endpoints": len(eps), "automated": auto, "manual": len(eps) - auto,
            "by_connector": Counter(e["connector"] for e in eps),
            "expiry": buckets, "renewal_states": states,
            "awaiting_manual": states.get("awaiting_manual", 0),
            "attention": sum(states.get(s, 0) for s in ("failed", "rolled_back")),
            "forecast": policy.forecast_timeline(max(len(eps), 1), manual_frac),
            "calendar": list(cal.values()),
        }

    @app.get("/api/forecast", dependencies=[Depends(auth)])
    def forecast(certs: int = 1000, manual: float = 0.4, minutes: float = 45, lead: int = 0):
        return {"timeline": policy.forecast_timeline(certs, manual, minutes, lead),
                "naive_2029": policy.forecast(certs, policy.SCHEDULE[-1][0], early=False).__dict__}

    @app.get("/api/endpoints", dependencies=[Depends(auth)])
    def endpoints(request: Request):
        out = []
        sc = scope_of(request)
        for e in S.endpoints():
            if not sc.has_row(e):
                continue
            e = {k: v for k, v in e.items() if k != "connector_config"} | {
                "automated": is_automated(e["connector"]),
                "days_left": round(policy.days_left(parse_dt(e["not_after"])), 1) if e["not_after"] else None}
            out.append(e)
        return out

    # connector configs reference credentials shared by the whole install: global admins only
    @app.post("/api/endpoints", dependencies=whole_install)
    def add_endpoint(ep: EndpointIn, request: Request):
        cmds = _command_keys(ep.connector_config)
        if cmds and not allow_commands:
            raise HTTPException(400, f"{', '.join(cmds)} would run commands on the Farrier host; set them in an "
                                     "inventory file imported with `farrier import`, or set FARRIER_ALLOW_API_COMMANDS=1")
        inline = _inline_secrets(ep.connector_config)
        if inline and not allow_inline:
            raise HTTPException(400, f"{', '.join(inline)} must reference a secret (env:NAME or file:/path), "
                                     "not contain it; set FARRIER_ALLOW_INLINE_SECRETS=1 to override")
        try:
            check_secret_refs(ep.connector_config)
            make_connector(ep.connector, ep.connector_config, engine.data_dir)  # validate config
        except SecretRefused as e:
            raise HTTPException(400, f"secret reference refused: {e}")
        except (ValueError, KeyError) as e:
            raise HTTPException(400, str(e))
        existing = S.q1("SELECT id, project_id FROM endpoints WHERE name=?", (ep.name,))
        pid = guard.project_id(request, ep.project)
        if existing and ep.project and S.project_id_of(existing) != pid:
            raise HTTPException(409, f"endpoint {ep.name} is in another project; "
                                     f"move it with POST /api/endpoints/{existing['id']}/move")
        body = ep.model_dump(exclude={"project"}) | {"enabled": int(ep.enabled)}
        if not existing:
            body["project_id"] = pid
        with lock:
            eid = S.upsert_endpoint(body)
            S.log(f"endpoint {ep.name} saved by {actor(request)}", eid)
            engine.observe(S.endpoint(eid))
        return {"id": eid}

    @app.delete("/api/endpoints/{eid}", dependencies=[Depends(auth)])
    def delete_endpoint(eid: int, request: Request):
        ep = guard.endpoint(request, eid, write=True)
        with lock:  # don't pull an endpoint out from under a running tick
            S.x("DELETE FROM endpoints WHERE id=?", (eid,))
            S.log(f"endpoint {ep['name']} removed by {actor(request)}")
        return {"ok": True}

    @app.post("/api/endpoints/{eid}/renew", dependencies=[Depends(auth)])
    def renew(eid: int, request: Request):
        guard.endpoint(request, eid, write=True)
        with lock:
            try:
                rid = engine.force_renewal(eid, f"requested by {actor(request)}")
            except NotApproved as e:
                raise HTTPException(409, str(e))
            state = engine.advance(rid)
        return {"renewal_id": rid, "state": state}

    @app.post("/api/endpoints/{eid}/approve", dependencies=[Depends(auth)])
    def approve(eid: int, request: Request):
        """Admin: let a discovered endpoint be renewed (its names came from whatever the host served)."""
        guard.endpoint(request, eid, write=True)
        with lock:
            engine.approve(eid, actor(request))
        return {"ok": True}

    @app.post("/api/discover", dependencies=[Depends(auth)])
    def discover(body: DiscoverIn, request: Request):
        pid = guard.project_id(request, body.project)
        sc = scope_of(request)
        try:
            targets = expand_targets(body.targets)
        except ValueError as e:
            raise HTTPException(400, str(e))
        if len(targets) > 4096:
            raise HTTPException(400, f"{len(targets)} targets; split the range (max 4096 per request)")
        results = scan(targets)
        with lock:
            reg = engine.register_scan(results, pid, None if sc.all else sc.has_row)
        return reg | {"scanned": len(targets), "with_tls": sum(1 for r in results if r.cert)}

    @app.get("/api/discover/ct", dependencies=[Depends(auth)])
    def discover_ct(domain: str):
        """Names with a valid public certificate under ``domain``, from Certificate Transparency logs (crt.sh)."""
        from farrier.core.ct import ct_names
        try:
            return ct_names(domain)
        except ValueError as e:
            raise HTTPException(400, str(e))
        except (RuntimeError, httpx.HTTPError) as e:
            raise HTTPException(502, f"Certificate Transparency search failed: {e}")

    @app.get("/api/renewals", dependencies=[Depends(auth)])
    def renewals(request: Request, state: str | None = None):
        return S.renewals(tuple(state.split(",")) if state else None, scope=scope_of(request))

    @app.post("/api/renewals/{rid}/advance", dependencies=[Depends(auth)])
    def advance(rid: int, request: Request):
        guard.renewal(request, rid, write=True)
        with lock:
            return {"state": engine.advance(rid)}

    @app.post("/api/renewals/{rid}/cancel", dependencies=[Depends(auth)])
    def cancel(rid: int, request: Request):
        if S.renewal(rid):
            guard.renewal(request, rid, write=True)
        with lock:
            try:
                engine.cancel(rid, f"cancelled by {actor(request)}")
            except ValueError as e:
                raise HTTPException(400, str(e))
        return {"state": "cancelled"}

    @app.get("/api/renewals/{rid}/pack", dependencies=[Depends(auth), Depends(secret_read)])
    def pack(rid: int, request: Request):
        r = S.renewal(rid) and guard.renewal(request, rid)
        if not r or r["state"] != "awaiting_manual":
            raise HTTPException(404, "no change pack for this renewal")
        ep = S.endpoint(r["endpoint_id"])
        from farrier.storage.packs import pack_store
        files = pack_store(engine.data_dir).read(rid)
        if not files:
            raise HTTPException(404, "change pack already cleaned up")
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
            for name, data in files.items():
                z.writestr(name, data)
        buf.seek(0)
        S.log("change pack downloaded", ep["id"], rid)
        safe = "".join(c if c.isalnum() or c in "-_." else "_" for c in ep["name"])
        return StreamingResponse(buf, media_type="application/zip",
                                 headers={"Content-Disposition": f'attachment; filename="{safe}-renewal-{rid}.zip"'})

    @app.get("/api/renewals/{rid}/runbook", dependencies=[Depends(auth)])
    def runbook(rid: int, request: Request):
        guard.renewal(request, rid)
        from farrier.storage.packs import pack_store
        text = pack_store(engine.data_dir).read_text(rid, "RUNBOOK.md")
        if text is None:
            raise HTTPException(404)
        return {"markdown": text}

    @app.get("/api/events", dependencies=[Depends(auth)])
    def events(request: Request, limit: int = 100, endpoint_id: int | None = None):
        sc = scope_of(request)
        # a scoped caller sees its endpoints' events only: install-wide ones (settings, deletions) are not theirs
        clause, args = sc.sql("e.project_id")
        if not sc.all:
            clause = " AND e.id IS NOT NULL" + clause
        if endpoint_id:
            return S.q(f"""SELECT ev.*, e.name FROM events ev LEFT JOIN endpoints e ON e.id = ev.endpoint_id
                           WHERE ev.endpoint_id=?{clause} ORDER BY ev.id DESC LIMIT ?""", (endpoint_id, *args, limit))
        return S.q(f"""SELECT ev.*, e.name FROM events ev LEFT JOIN endpoints e ON e.id = ev.endpoint_id
                       WHERE 1=1{clause} ORDER BY ev.id DESC LIMIT ?""", (*args, limit))

    @app.post("/api/tick", dependencies=whole_install)       # one cycle covers every project
    def tick():
        with lock:
            return engine.tick()

    @app.get("/api/connectors", dependencies=[Depends(auth)])
    def connectors():
        import sys
        return [{"kind": k, "automated": c.automated, "required": list(c.required),
                 "doc": (sys.modules[c.__module__].__doc__ or "").strip()} for k, c in REGISTRY.items()]

    # ---- observability ------------------------------------------------------------------------
    @app.get("/metrics", dependencies=[Depends(auth)], include_in_schema=False)
    def metrics(request: Request):
        """Prometheus text format. Names follow x509-certificate-exporter and cert-manager where they overlap."""
        from fastapi.responses import PlainTextResponse

        from farrier import __version__

        def esc(v) -> str:
            return str(v).replace("\\", "\\\\").replace("\n", "\\n").replace('"', '\\"')

        def lbl(**kv) -> str:
            return "{" + ",".join(f'{k}="{esc(v)}"' for k, v in kv.items()) + "}"

        now = policy.utcnow()
        out = []

        def metric(name, kind, help_, rows):
            out.append(f"# HELP {name} {help_}")
            out.append(f"# TYPE {name} {kind}")
            out.extend(f"{name}{labels} {value}" for labels, value in rows)

        sc = scope_of(request)
        eps = [e for e in S.endpoints() if sc.has_row(e)]
        base = [(e, lbl(endpoint=e["name"], host=e["host"], port=e["port"], connector=e["connector"],
                        automated=str(is_automated(e["connector"])).lower(), owner=e["owner"] or "")) for e in eps]
        with_cert = [(e, l) for e, l in base if e["not_after"]]
        metric("farrier_cert_not_after_timestamp_seconds", "gauge", "Expiry of the certificate the endpoint serves.",
               [(l, int(parse_dt(e["not_after"]).timestamp())) for e, l in with_cert])
        metric("farrier_cert_expires_in_seconds", "gauge", "Seconds until the served certificate expires (negative once expired).",
               [(l, int((parse_dt(e["not_after"]) - now).total_seconds())) for e, l in with_cert])
        metric("farrier_cert_expired", "gauge", "1 when the served certificate has expired.",
               [(l, int(parse_dt(e["not_after"]) < now)) for e, l in with_cert])
        metric("farrier_endpoint_up", "gauge", "1 when the last TLS handshake with the endpoint succeeded.",
               [(l, int(not e["scan_error"] and bool(e["fingerprint"]))) for e, l in base])
        counts = Counter(r["state"] for r in S.renewals(limit=100000, scope=sc))
        metric("farrier_renewals", "gauge", "Renewals by state.",
               [(lbl(state=st), n) for st, n in sorted(counts.items())])
        from farrier.monitoring.health import last_reports
        names = {e["id"]: e["name"] for e in eps}
        metric("farrier_health_check_failed", "gauge",
               "1 when a domain health check failed for the endpoint at its last health run (0 = pass or warn).",
               [(lbl(endpoint=names[eid], check=c["id"]), int(c["status"] == "fail"))
                for eid, rep in sorted(last_reports(S).items()) if eid in names for c in rep["checks"]])
        metric("farrier_build_info", "gauge", "Farrier version.", [(lbl(version=__version__), 1)])
        return PlainTextResponse("\n".join(out) + "\n", media_type="text/plain; version=0.0.4")

    @app.get("/api/inventory", dependencies=[Depends(auth)])
    def inventory(request: Request, format: str = "json"):
        """Every endpoint and the certificate it serves, for audits and CMDB imports."""
        import csv

        cols = ["name", "host", "port", "project", "connector", "owner", "subject_cn", "cert_issuer", "not_before",
                "not_after", "days_left", "fingerprint", "observed_at", "scan_error"]
        rows = []
        sc = scope_of(request)
        for e in S.endpoints():
            if not sc.has_row(e):
                continue
            na = parse_dt(e["not_after"]) if e["not_after"] else None
            rows.append({c: e.get(c) for c in cols} | {"days_left": round(policy.days_left(na), 1) if na else None})
        if format == "csv":
            buf = io.StringIO()
            w = csv.DictWriter(buf, fieldnames=cols)
            w.writeheader()
            for row in rows:
                # neutralise spreadsheet formulas in exported text
                w.writerow({k: ("'" + v if isinstance(v, str) and v and v[0] in "=+-@\t\r|%" else v) for k, v in row.items()})
            return StreamingResponse(iter([buf.getvalue()]), media_type="text/csv",
                                     headers={"Content-Disposition": 'attachment; filename="farrier-inventory.csv"'})
        return rows

    # ---- domain health, zombie certificates, MCP --------------------------------------------------
    @app.get("/api/endpoints/{eid}/health", dependencies=[Depends(auth)])
    def endpoint_health(eid: int, request: Request, caa: bool = True):
        """TLS report card for one endpoint; also feeds farrier_health_check_failed in /metrics."""
        from farrier.monitoring import health
        ep = guard.endpoint(request, eid)
        return health.check_endpoint(engine, ep, caa=caa)

    @app.post("/api/health", dependencies=whole_install)      # any target, judged against the whole inventory
    def targets_health(body: DiscoverIn, caa: bool = True):
        """Health for any targets, in discovery syntax (host, host:port, sni@ip:port, small CIDR ranges)."""
        from farrier.monitoring import health
        try:
            targets = expand_targets(body.targets, limit=64)
        except ValueError as e:
            raise HTTPException(400, str(e))
        if not targets:
            raise HTTPException(400, "no targets")
        if len(targets) > 64:
            raise HTTPException(400, f"{len(targets)} targets; health checks are limited to 64 per request")
        reports = health.check_targets(engine, targets, caa=caa)
        return {"count": len(reports), "reports": reports}

    @app.get("/api/zombies", dependencies=[Depends(auth)])
    def zombies(request: Request, dead_days: int = 7, pack_days: int = 3):
        """Certificates that are alive but should not be, from stored observations (no network)."""
        from farrier.monitoring import zombie
        found = zombie.from_store(S, dead_days=max(1, dead_days), pack_days=max(0, pack_days))
        sc = scope_of(request)
        if not sc.all:      # a scoped caller gets findings about its own endpoints only
            pids = {e["id"]: e["project_id"] for e in S.q("SELECT id, project_id FROM endpoints")}
            found = [f for f in found if f["endpoint_id"] in pids and sc.has(pids[f["endpoint_id"]])]
        return zombie.summarize(found)

    @app.post("/api/zombies/scan", dependencies=whole_install)  # compares targets with the whole inventory
    def zombies_scan(body: DiscoverIn, request: Request):
        """Active scan of targets (admin): adds not-in-inventory and unexpected-issuer findings. Writes nothing."""
        from farrier.monitoring import zombie
        try:
            targets = expand_targets(body.targets)
        except ValueError as e:
            raise HTTPException(400, str(e))
        if len(targets) > 4096:
            raise HTTPException(400, f"{len(targets)} targets; split the range (max 4096 per request)")
        results = scan(targets)
        S.log(f"zombie scan of {len(targets)} targets by {actor(request)}")
        found = zombie.from_scan(S, results) + zombie.from_store(S)
        return zombie.summarize(found) | {"scanned": len(targets), "with_tls": sum(1 for r in results if r.cert)}

    from farrier.api.mcp import mount as mount_mcp
    mount_mcp(app, engine, lock)

    from farrier.api.config_routes import mount as mount_config
    mount_config(app, engine, lock, auth, actor, allow_commands, allow_inline)

    from farrier.api.crypto_routes import mount as mount_crypto
    mount_crypto(app, engine, auth, actor)

    from farrier.api.ssh_routes import mount as mount_ssh
    mount_ssh(app, engine, auth, actor)

    from farrier.api.project_routes import mount as mount_projects
    mount_projects(app, engine, lock, auth, actor)

    from farrier.api.runner_routes import mount as mount_runners
    mount_runners(app, engine, whole_install, actor)

    @app.post("/api/notifiers/test", dependencies=whole_install)
    def test_notifiers():
        sent = engine.notifier.send("test", wait=True)
        if not sent:
            raise HTTPException(400, "no alert channels configured")
        return {"sent": sent}

    @app.get("/api/config", dependencies=[Depends(auth)])
    def get_config():
        """The effective configuration for the dashboard. Secrets appear only as their env:/file: reference."""
        from farrier.config import settings as config
        return config.view(engine)

    @app.put("/api/config/settings", dependencies=whole_install)
    async def put_settings(request: Request):
        """Change planner settings (admin): validated, saved to settings.json and applied live."""
        from farrier.config import settings as config
        try:
            changed = config.update_settings(engine, await request.json())
        except ValueError as e:
            raise HTTPException(400, str(e))
        S.log(f"settings changed by {actor(request)}: " + ", ".join(f"{k}={v}" for k, v in changed.items()))
        return {"changed": changed}

    return app
