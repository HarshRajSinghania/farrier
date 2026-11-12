"""Dashboard configuration API: secrets, CAs, DNS accounts, alert channels and alert rules.

Every write is admin-only (the shared auth dependency refuses non-GET with the read token), goes
through the same guardrails as endpoint configs (no inline secrets, no command keys), is logged to the
event log with its actor, bumps the config version and reloads this engine at once; other replicas
reload on their next tick. No route ever returns a secret value.

All of this is shared by every project, so changes need full access (a global admin, or the admin token
used directly); a project-scoped caller may read it, without the names of other projects' endpoints.
"""
from __future__ import annotations

from fastapi import Depends, HTTPException, Request

from farrier.api.scope import Guard
from farrier.config import integrations as I
from farrier.monitoring.alerts import validate_rule
from farrier.security.secrets_store import NAME


def mount(app, engine, lock, auth, actor, allow_commands: bool, allow_inline: bool) -> None:
    S = engine.store
    dep = [Depends(auth)]
    guard = Guard(S)
    admin = [Depends(auth), Depends(guard.global_only)]

    def check_project(name) -> None:
        if name is not None and not (isinstance(name, str) and S.project(name)):
            raise HTTPException(400, f"no project named {name}")

    def check_name(name: str) -> None:
        if not NAME.match(name):
            raise HTTPException(400, "name must be 1-64 of A-Z a-z 0-9 _ . - (starting with a letter or digit)")

    async def body_of(request: Request):
        try:
            return await request.json()
        except ValueError:
            raise HTTPException(400, "body must be JSON") from None

    def not_file(kind: str, name: str) -> None:
        owner = I.file_owner(engine, kind, name)
        if owner:
            raise HTTPException(409, f"managed in {owner}")

    def changed(message: str, request: Request) -> None:
        S.log(f"{message} by {actor(request)}")
        with lock:
            engine.reload_config()

    def run(fn, *a):
        try:
            return fn(*a)
        except (I.Invalid, ValueError) as e:
            raise HTTPException(400, str(e)) from None

    # ---- secrets -------------------------------------------------------------------------------------
    @app.get("/api/secrets", dependencies=dep)
    def list_secrets(request: Request):
        uses = I.used_by(engine)
        sc = guard.of(request)
        if not sc.all:      # endpoint names are project data
            mine = {f"endpoint:{e['name']}" for e in S.q("SELECT name, project_id FROM endpoints") if sc.has_row(e)}
            uses = {k: [u for u in v if not u.startswith("endpoint:") or u in mine] for k, v in uses.items()}
        return [r | {"used_by": uses.get(r["name"], [])} for r in engine.secrets.list()]

    @app.get("/api/secrets/backend", dependencies=dep)
    def secrets_backend():
        return engine.secrets.describe()

    @app.put("/api/secrets/{name}", dependencies=admin)
    async def put_secret(name: str, request: Request):
        check_name(name)
        body = await body_of(request)
        value = body.get("value") if isinstance(body, dict) else None
        if not isinstance(value, str) or not value:
            raise HTTPException(400, "value must be a non-empty string")
        new = run(engine.secrets.put, name, value)
        engine.items.bump()            # issuers resolve EAB secrets when they are built
        changed(f"secret {name} {'added' if new else 'replaced'}", request)
        return {"name": name}

    @app.delete("/api/secrets/{name}", dependencies=admin)
    def delete_secret(name: str, request: Request):
        if not engine.secrets.exists(name):
            raise HTTPException(404, f"no secret named {name}")
        uses = I.used_by(engine).get(name)
        if uses:
            raise HTTPException(409, f"secret {name} is used by {', '.join(uses)}")
        engine.secrets.delete(name)
        engine.items.bump()
        changed(f"secret {name} deleted", request)
        return {"ok": True}

    # ---- catalog -------------------------------------------------------------------------------------
    @app.get("/api/integrations/catalog", dependencies=dep)
    def catalog():
        return I.catalog(allow_commands)

    # ---- issuers -------------------------------------------------------------------------------------
    @app.get("/api/issuers", dependencies=dep)
    def list_issuers():
        return [I.issuer_view(n, src, c) for n, (src, c) in I.issuer_configs(engine).items()]

    @app.put("/api/issuers/{name}", dependencies=admin)
    async def put_issuer(name: str, request: Request):
        check_name(name)
        not_file("issuer", name)
        entry = run(I.validate_issuer, engine, name, await body_of(request), allow_commands, allow_inline)
        engine.items.put("issuer", name, entry, actor(request))
        changed(f"issuer {name} saved", request)
        return I.issuer_view(name, "ui", entry)

    @app.delete("/api/issuers/{name}", dependencies=admin)
    def delete_issuer(name: str, request: Request):
        cfgs = I.issuer_configs(engine)
        if name not in cfgs:
            raise HTTPException(404, f"no issuer named {name}")
        not_file("issuer", name)
        if cfgs[name][0] == "builtin":
            raise HTTPException(409, "the built-in local CA is used when no issuer is configured; add another "
                                     "issuer named default to replace it")
        users = [r["name"] for r in S.q("SELECT name FROM endpoints WHERE issuer=? ORDER BY name", (name,))]
        if users:
            raise HTTPException(409, f"issuer {name} is used by endpoints: {', '.join(users)}")
        # with no issuers.json the built-in local CA comes back, so only a file setup can run out
        if I.file_issuers(engine)[1] == "file" and not [n for n in cfgs if n != name]:
            raise HTTPException(409, f"{name} is the last issuer; add another one first")
        engine.items.delete("issuer", name)
        changed(f"issuer {name} deleted", request)
        return {"ok": True}

    @app.post("/api/issuers/{name}/test", dependencies=admin)
    def test_issuer(name: str, request: Request):
        try:
            out = I.test_issuer(engine, name)
        except KeyError:
            raise HTTPException(404, f"no issuer named {name}") from None
        S.log(f"issuer {name} tested by {actor(request)}: {'ok' if out['ok'] else 'failed'}")
        return out

    # ---- DNS accounts --------------------------------------------------------------------------------
    @app.get("/api/dns-accounts", dependencies=dep)
    def list_dns():
        return [I.dns_view(n, src, c) for n, (src, c) in I.dns_configs(engine).items()]

    @app.put("/api/dns-accounts/{name}", dependencies=admin)
    async def put_dns(name: str, request: Request):
        check_name(name)
        not_file("dns", name)
        body = I.keep_dns_refs(engine.items.get("dns", name), await body_of(request))
        acc = run(I.validate_dns, engine, name, body, allow_commands, allow_inline)
        engine.items.put("dns", name, acc, actor(request))
        changed(f"dns account {name} saved", request)
        return I.dns_view(name, "ui", acc)

    @app.delete("/api/dns-accounts/{name}", dependencies=admin)
    def delete_dns(name: str, request: Request):
        if name not in I.dns_configs(engine):
            raise HTTPException(404, f"no dns account named {name}")
        not_file("dns", name)
        users = [f"issuer:{n}" for n, (_, c) in I.issuer_configs(engine).items() if isinstance(c, dict) and c.get("dns") == name]
        users += [f"endpoint:{e['name']}" for e in S.q("SELECT name, connector_config FROM endpoints ORDER BY name")
                  if (e["connector_config"] or {}).get("dns_account") == name]
        if users:
            raise HTTPException(409, f"dns account {name} is used by {', '.join(users)}")
        engine.items.delete("dns", name)
        changed(f"dns account {name} deleted", request)
        return {"ok": True}

    @app.post("/api/dns-accounts/{name}/test", dependencies=admin)
    def test_dns(name: str, request: Request):
        try:
            out = I.test_dns(engine, name)
        except KeyError:
            raise HTTPException(404, f"no dns account named {name}") from None
        S.log(f"dns account {name} tested by {actor(request)}: {'ok' if out['ok'] else 'failed'}")
        return out

    # ---- alert channels ------------------------------------------------------------------------------
    @app.get("/api/notifiers", dependencies=dep)
    def list_notifiers():
        return [I.notifier_view(n, src, c) for n, (src, c) in I.notifier_configs(engine).items()]

    @app.put("/api/notifiers/{name}", dependencies=admin)
    async def put_notifier(name: str, request: Request):
        check_name(name)
        not_file("notifier", name)
        body = I.keep_secret_refs(engine.items.get("notifier", name), await body_of(request))
        if isinstance(body, dict):
            check_project(body.get("project") or None)
        cfg = run(I.validate_notifier, engine, name, body, allow_commands, allow_inline)
        engine.items.put("notifier", name, cfg, actor(request))
        changed(f"alert channel {name} saved", request)
        return I.notifier_view(name, "ui", cfg)

    @app.delete("/api/notifiers/{name}", dependencies=admin)
    def delete_notifier(name: str, request: Request):
        if name not in I.notifier_configs(engine):
            raise HTTPException(404, f"no alert channel named {name}")
        not_file("notifier", name)
        rules = [n for n, r in engine.alerts.rules().items() if name in (r.get("channels") or [])]
        if rules:
            raise HTTPException(409, f"alert channel {name} is used by alert rules: {', '.join(rules)}")
        engine.items.delete("notifier", name)
        changed(f"alert channel {name} deleted", request)
        return {"ok": True}

    @app.post("/api/notifiers/{name}/test", dependencies=admin)
    def test_notifier(name: str, request: Request):
        try:
            out = I.test_notifier(engine, name)
        except KeyError:
            raise HTTPException(404, f"no alert channel named {name}") from None
        S.log(f"alert channel {name} tested by {actor(request)}: {'ok' if out['ok'] else 'failed'}")
        return out

    # ---- alert rules ---------------------------------------------------------------------------------
    def rule_view(name: str, r: dict, fired: dict) -> dict:
        return {"name": name, "enabled": r.get("enabled", False), "when": r.get("when"), "filter": r.get("filter") or {},
                "channels": r.get("channels") or [], "cooldown_hours": r.get("cooldown_hours", 24),
                "last_fired_at": fired.get(name)}

    @app.get("/api/alert-rules", dependencies=dep)
    def list_rules():
        fired = engine.alerts.last_fired()
        return [rule_view(n, r, fired) for n, r in engine.alerts.rules().items()]

    @app.put("/api/alert-rules/{name}", dependencies=admin)
    async def put_rule(name: str, request: Request):
        check_name(name)
        rule = run(validate_rule, await body_of(request), set(I.notifier_configs(engine)))
        check_project(rule["filter"].get("project"))
        old = engine.items.get("alert_rule", name)
        engine.items.put("alert_rule", name, rule, actor(request))
        if old and (old.get("when"), old.get("filter")) != (rule["when"], rule["filter"]):
            engine.alerts.forget(name)          # a redefined rule starts with a clean slate
        changed(f"alert rule {name} saved", request)
        return rule_view(name, rule, engine.alerts.last_fired())

    @app.delete("/api/alert-rules/{name}", dependencies=admin)
    def delete_rule(name: str, request: Request):
        if not engine.items.delete("alert_rule", name):
            raise HTTPException(404, f"no alert rule named {name}")
        engine.alerts.forget(name)
        changed(f"alert rule {name} deleted", request)
        return {"ok": True}

    @app.post("/api/alert-rules/{name}/test", dependencies=admin)
    def test_rule(name: str, request: Request):
        try:
            out = engine.alerts.test(name)
        except KeyError:
            raise HTTPException(404, f"no alert rule named {name}") from None
        S.log(f"alert rule {name} tested by {actor(request)}: sent to {', '.join(out['sent']) or 'no channel'}")
        return out
