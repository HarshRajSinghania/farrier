"""SSH inventory API: host discovery, authorized keys, access profiles.

GETs accept the read token; everything else needs the admin token (the shared auth dependency). Every
change is written to the event log with its actor. No route returns a secret value: access profiles
show the private key's *reference* only.
"""
from __future__ import annotations

import base64
from collections import Counter

from fastapi import Depends, HTTPException, Request
from starlette.concurrency import run_in_threadpool

from farrier.ssh import access, collect, db, scan
from farrier.ssh.findings import SEVERITIES
from farrier.ssh.keys import parse_blob
from farrier.ssh.transport import HostKeyMismatch, TransportError

MAX_SCAN = 4096


def key_view(k: dict) -> dict:
    return {"id": k["id"], "host": k["host"], "port": k["port"], "user": k["username"], "path": k["path"],
            "line_no": k.get("line_no"), "type": k["type"], "bits": k["bits"], "fingerprint_sha256": k["fingerprint"],
            "comment": k.get("comment") or "", "options": k.get("options") or {}, "access": k["access"],
            "first_seen": k["first_seen"], "last_seen": k["last_seen"], "findings": k.get("findings") or []}


def mount(app, engine, auth, actor) -> None:
    S = engine.store
    dep = [Depends(auth)]

    async def body_of(request: Request) -> dict:
        raw = await request.body()
        if not raw:
            return {}
        try:
            body = await request.json()
        except ValueError:
            raise HTTPException(400, "body must be JSON") from None
        if not isinstance(body, dict):
            raise HTTPException(400, "body must be a JSON object")
        return body

    def profile_or_404(name: str) -> dict:
        p = engine.items.get(access.KIND, name)
        if p is None:
            raise HTTPException(404, f"no SSH access profile named {name}")
        return p

    # ---- discovery (no login) --------------------------------------------------------------------------
    @app.get("/api/ssh/hosts", dependencies=dep)
    def ssh_hosts():
        return [scan.host_view(h) for h in db.hosts(S)]

    @app.post("/api/ssh/scan", dependencies=dep)
    async def ssh_scan(request: Request):
        body = await body_of(request)
        try:
            targets = access.expand_hosts(body.get("targets") or "", 22)
        except access.Invalid as e:
            raise HTTPException(400, str(e)) from None
        if not targets:
            raise HTTPException(400, "no targets")
        if len(targets) > MAX_SCAN:
            raise HTTPException(400, f"{len(targets)} targets; split the range (max {MAX_SCAN} per request)")
        out = await run_in_threadpool(scan.scan, S, targets)
        S.log(f"ssh scan of {len(targets)} targets by {actor(request)}: {out['ssh']} answered")
        return out

    @app.post("/api/ssh/hosts/{hid}/trust", dependencies=dep)
    async def ssh_trust(hid: int, request: Request):
        """Pin the host keys the host presents now. ``fingerprints`` (optional) must list every key to
        pin; without it, the live keys must equal the ones the inventory last showed."""
        h = db.host(S, hid)
        if not h:
            raise HTTPException(404)
        body = await body_of(request)
        res = collect.default_prober(h["host"], h["port"])
        if not res.host_keys:
            raise HTTPException(502, f"could not read the host keys: {res.error or '; '.join(res.notes)}")
        live = {k.fingerprint_sha256 for k in res.host_keys}
        expected = set(body.get("fingerprints") or [k["fingerprint_sha256"] for k in h.get("host_keys") or []])
        if live != expected:
            raise HTTPException(409, "the host presents different keys than expected: " + ", ".join(sorted(live)))
        collect.trust_host(S, h["host"], h["port"], res.host_keys, actor(request))
        scan.save_probe(S, res)
        return {"pinned": [{"type": k.type, "fingerprint_sha256": k.fingerprint_sha256} for k in res.host_keys]}

    @app.get("/api/ssh/hosts/{hid}/pins", dependencies=dep)
    def ssh_pins(hid: int):
        h = db.host(S, hid)
        if not h:
            raise HTTPException(404)
        out = []
        for p in db.pins(S, h["host"], h["port"]):
            k = parse_blob(base64.b64decode(p["key_b64"]))
            out.append({"type": p["key_type"], "bits": k.bits, "fingerprint_sha256": p["fingerprint"],
                        "source": p["source"], "pinned_at": p["pinned_at"]})
        return out

    # ---- authorized keys ---------------------------------------------------------------------------------
    @app.get("/api/ssh/keys", dependencies=dep)
    def ssh_keys():
        return [key_view(k) for k in db.keys(S)]

    @app.post("/api/ssh/keys/{kid}/remove", dependencies=dep)
    async def ssh_key_remove(kid: int, request: Request):
        body = await body_of(request)
        dry_run = body.get("dry_run", False)
        if not isinstance(dry_run, bool):
            raise HTTPException(400, "dry_run must be true or false")
        try:
            return await run_in_threadpool(collect.remove_key, S, engine.items, kid, actor(request), dry_run,
                                           collect.default_transport, collect.default_prober)
        except KeyError:
            raise HTTPException(404, f"no SSH key {kid}") from None
        except collect.Conflict as e:
            raise HTTPException(409, str(e)) from None
        except HostKeyMismatch as e:
            raise HTTPException(502, f"host key mismatch: {e}") from None
        except (collect.CollectError, TransportError) as e:
            raise HTTPException(502, str(e)) from None

    @app.get("/api/ssh/approved-keys", dependencies=dep)
    def ssh_approved():
        return {"fingerprints": sorted(access.approved_fingerprints(engine.items))}

    @app.put("/api/ssh/approved-keys", dependencies=dep)
    async def ssh_put_approved(request: Request):
        try:
            body = access.validate_approved(await body_of(request))
        except access.Invalid as e:
            raise HTTPException(400, str(e)) from None
        engine.items.put(access.APPROVED_KIND, access.APPROVED_NAME, body, actor(request))
        collect.refresh_findings(S, engine.items)
        S.log(f"ssh approved keys set ({len(body['fingerprints'])}) by {actor(request)}")
        return body

    # ---- access profiles ---------------------------------------------------------------------------------
    @app.get("/api/ssh/access", dependencies=dep)
    def ssh_access_list():
        return [access.view(n, c) for n, c in access.profiles(engine.items).items()]

    @app.get("/api/ssh/access/{name}", dependencies=dep)
    def ssh_access_get(name: str):
        return access.view(name, profile_or_404(name))

    @app.put("/api/ssh/access/{name}", dependencies=dep)
    async def ssh_access_put(name: str, request: Request):
        if not access.NAME.match(name):
            raise HTTPException(400, "name must be 1-64 of A-Z a-z 0-9 _ . - (starting with a letter or digit)")
        body = await body_of(request)
        old = engine.items.get(access.KIND, name)
        if old and "private_key" not in body:
            body["private_key"] = old["private_key"]        # keep the reference when not re-sent
        try:
            cfg = access.validate(body)
        except access.Invalid as e:
            raise HTTPException(400, str(e)) from None
        engine.items.put(access.KIND, name, cfg, actor(request))
        S.log(f"ssh access profile {name} {'saved' if old else 'added'} by {actor(request)}")
        return access.view(name, cfg)

    @app.delete("/api/ssh/access/{name}", dependencies=dep)
    def ssh_access_delete(name: str, request: Request):
        if not engine.items.delete(access.KIND, name):
            raise HTTPException(404, f"no SSH access profile named {name}")
        S.log(f"ssh access profile {name} deleted by {actor(request)}")
        return {"ok": True}

    @app.post("/api/ssh/access/{name}/test", dependencies=dep)
    async def ssh_access_test(name: str, request: Request):
        """Log in to one host of the profile (``host`` in the body, default the first) and run ``true``."""
        p = profile_or_404(name)
        body = await body_of(request)
        hosts = access.expand_hosts(p["hosts"], p["port"])
        if body.get("host"):
            try:
                want = access.expand_hosts([str(body["host"])], p["port"])
            except access.Invalid as e:
                raise HTTPException(400, str(e)) from None
            if want[0] not in hosts:
                raise HTTPException(400, "host is not in this profile")
            hosts = want
        host, port = hosts[0]

        def run() -> dict:
            known = collect.verified_known_keys(S, host, port, p["known_hosts_policy"], collect.default_prober)
            t = collect.default_transport(p, host, port, known)
            try:
                r = t.run("true", timeout=30)
            finally:
                t.close()
            return {"ok": r.ok, "host": host, "port": port} | ({} if r.ok else {"error": f"exit {r.rc}: {r.stderr[-200:]}"})

        try:
            out = await run_in_threadpool(run)
        except (collect.CollectError, TransportError, KeyError, OSError) as e:
            out = {"ok": False, "host": host, "port": port, "error": f"{type(e).__name__}: {e}"}
        S.log(f"ssh access profile {name} tested on {host}:{port} by {actor(request)}: "
              f"{'ok' if out['ok'] else 'failed'}", level="info" if out["ok"] else "warning")
        return out

    @app.post("/api/ssh/collect", dependencies=dep)
    async def ssh_collect(request: Request):
        body = await body_of(request)
        only = body.get("access")
        if only is not None and not isinstance(only, str):
            raise HTTPException(400, "access must be a profile name")
        try:
            out = await run_in_threadpool(collect.collect, S, engine.items, only, collect.default_transport,
                                          collect.default_prober)
        except KeyError:
            raise HTTPException(404, f"no SSH access profile named {only}") from None
        S.log(f"ssh collection run by {actor(request)}: {out['ok']} of {out['hosts']} hosts, {out['keys']} keys")
        return out

    # ---- summary -----------------------------------------------------------------------------------------
    @app.get("/api/ssh/summary", dependencies=dep)
    def ssh_summary():
        hosts, keys = db.hosts(S), db.keys(S)
        sev = Counter(dict.fromkeys(SEVERITIES, 0))
        for item in hosts + keys:
            sev.update(f["severity"] for f in item.get("findings") or [])
        weak = sum(1 for h in hosts if any(f["id"].startswith("host-key-") for f in h.get("findings") or []))
        return {"hosts": len(hosts), "keys": len(keys), "by_severity": dict(sev), "weak_host_keys": weak,
                "pqc_kex_hosts": sum(1 for h in hosts if h.get("pqc_kex"))}
