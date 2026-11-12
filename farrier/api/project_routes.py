"""Teams and projects API.

  GET    /api/projects                  global admin: every project with its member groups and size
  GET    /api/projects/{name}           a project in the caller's scope
  PUT    /api/projects/{name}           global admin: create, or set title / member groups
  DELETE /api/projects/{name}           global admin: an empty project other than "default"
  POST   /api/endpoints/{id}/move       global admin: {project} moves an endpoint (and what hangs off it)

Membership is not a user database: ``members`` maps SSO groups to the project, read by the dashboard
when it builds each request's signed scope (farrier.api.scope). ``groups`` see the project with their
install-wide role; ``admin`` / ``operator`` / ``viewer`` groups get that role in this project only.
"""
from __future__ import annotations

import json
import re

from fastapi import Depends, HTTPException, Request

from farrier.api.scope import Guard
from farrier.db.store import DEFAULT_PROJECT, now_iso

NAME = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}$")
MEMBER_KEYS = ("groups", "admin", "operator", "viewer")


def validate_members(body) -> dict:
    if body is None:
        return {k: [] for k in MEMBER_KEYS}
    if not isinstance(body, dict) or set(body) - set(MEMBER_KEYS):
        raise ValueError(f"members may hold {', '.join(MEMBER_KEYS)}")
    out = {}
    for k in MEMBER_KEYS:
        v = body.get(k) or []
        if (not isinstance(v, list) or len(v) > 100
                or not all(isinstance(g, str) and g.strip() and len(g) <= 256 for g in v)):
            raise ValueError(f"members.{k} must be a list of up to 100 group names")
        out[k] = list(dict.fromkeys(g.strip() for g in v))
    return out


def view(p: dict, counts: dict[int, int] | None = None) -> dict:
    stored = p.get("members") if isinstance(p.get("members"), dict) else {}
    members = {k: list(stored.get(k) or []) for k in MEMBER_KEYS}
    out = {"id": p["id"], "name": p["name"], "title": p["title"] or p["name"], "members": members,
           "created_at": p["created_at"]}
    if counts is not None:
        out["endpoints"] = counts.get(p["id"], 0)
    return out


def mount(app, engine, lock, auth, actor) -> None:
    S = engine.store
    guard = Guard(S)
    dep = [Depends(auth)]
    admin = [Depends(auth), Depends(guard.global_only)]

    def counts() -> dict[int, int]:
        d = S.default_project_id()
        out: dict[int, int] = {}
        for r in S.q("SELECT project_id, COUNT(*) AS n FROM endpoints GROUP BY project_id"):
            pid = d if r["project_id"] is None else r["project_id"]
            out[pid] = out.get(pid, 0) + r["n"]
        return out

    def project_or_404(name: str) -> dict:
        p = S.project(name)
        if not p:
            raise HTTPException(404, f"no project named {name}")
        return p

    async def body_of(request: Request) -> dict:
        try:
            body = await request.json()
        except ValueError:
            raise HTTPException(400, "body must be JSON") from None
        if not isinstance(body, dict):
            raise HTTPException(400, "body must be a JSON object")
        return body

    @app.get("/api/projects", dependencies=admin)
    def list_projects():
        c = counts()
        return [view(p, c) for p in S.projects()]

    @app.get("/api/projects/{name}", dependencies=dep)
    def get_project(name: str, request: Request):
        p = project_or_404(name)
        sc = guard.of(request)
        if not sc.has(p["id"]):
            raise HTTPException(404, f"no project named {name}")
        out = view(p, counts())
        if not sc.all:
            out.pop("members")      # who else is in it is a global admin's business
        return out

    @app.put("/api/projects/{name}", dependencies=admin)
    async def put_project(name: str, request: Request):
        if not NAME.match(name):
            raise HTTPException(400, "name must be 1-63 of a-z 0-9 - (starting with a letter or digit)")
        body = await body_of(request)
        if set(body) - {"title", "members"}:
            raise HTTPException(400, "send {title?, members?}")
        title = body.get("title")
        if title is not None and (not isinstance(title, str) or not title.strip() or len(title) > 80):
            raise HTTPException(400, "title must be 1-80 characters")
        old = S.project(name)
        try:
            members = validate_members(body["members"]) if "members" in body else \
                validate_members((old or {}).get("members") or None)
        except ValueError as e:
            raise HTTPException(400, str(e)) from None
        title = title.strip() if title else ((old or {}).get("title") or name)
        with lock:
            if old:
                S.x("UPDATE projects SET title=?, members=? WHERE id=?", (title, json.dumps(members), old["id"]))
            else:
                S.x("INSERT INTO projects(name, title, members, created_at) VALUES (?,?,?,?)",
                    (name, title, json.dumps(members), now_iso()))
        S.log(f"project {name} {'saved' if old else 'created'} by {actor(request)}")
        return view(S.project(name), counts())

    @app.delete("/api/projects/{name}", dependencies=admin)
    def delete_project(name: str, request: Request):
        p = project_or_404(name)
        if name == DEFAULT_PROJECT:
            raise HTTPException(409, "the default project cannot be deleted")
        used = [t for t in ("endpoints", "ssh_hosts", "ssh_keys", "crypto_assets")
                if S.q1(f"SELECT COUNT(*) AS n FROM {t} WHERE project_id=?", (p["id"],))["n"]]
        used += [f"{kind} {n}" for kind in ("notifier", "ssh_access") for n, c in engine.items.all(kind).items()
                 if isinstance(c, dict) and c.get("project") == name]
        used += [f"alert rule {n}" for n, r in engine.items.all("alert_rule").items()
                 if (r.get("filter") or {}).get("project") == name]
        if used:
            raise HTTPException(409, f"project {name} is still used by {', '.join(used)}; move or remove them first")
        S.x("DELETE FROM projects WHERE id=?", (p["id"],))
        S.log(f"project {name} deleted by {actor(request)}")
        return {"ok": True}

    @app.post("/api/endpoints/{eid}/move", dependencies=admin)
    async def move_endpoint(eid: int, request: Request):
        """Renewals, observations, health and change packs follow the endpoint; so do crypto assets for its
        address."""
        ep = guard.endpoint(request, eid)
        body = await body_of(request)
        p = project_or_404(str(body.get("project") or ""))
        with lock:
            S.x("UPDATE endpoints SET project_id=? WHERE id=?", (p["id"], eid))
            S.x("UPDATE crypto_assets SET project_id=? WHERE kind='tls' AND host=? AND port=? AND "
                "IFNULL(sni,'')=IFNULL(?,'')", (p["id"], ep["host"], ep["port"], ep["sni"]))
        S.log(f"endpoint {ep['name']} moved from project {ep['project']} to {p['name']} by {actor(request)}", eid)
        return {"ok": True, "project": p["name"]}
