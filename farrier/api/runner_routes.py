"""Remote runner routes (farrier.core.runners).

For runners, authenticated by their group token (never the API token):
  POST /api/runner/poll           claim up to 5 jobs: {"jobs": [{id, kind, payload}]}
  POST /api/runner/jobs/{id}      report one job: {"ok": bool, "result": {...}}
These two are all a runner token opens, so they can be the only paths published to other networks.

For admins (the API token, whole install):
  GET    /api/runners                 groups: endpoints, pending jobs, last seen, runner version
  POST   /api/runners/{group}/token   create or replace a group's token (shown once)
  DELETE /api/runners/{group}/token   revoke it
"""
from __future__ import annotations

from fastapi import Depends, HTTPException, Request
from pydantic import BaseModel, Field


class PollIn(BaseModel):
    version: str | None = Field(default=None, max_length=40)
    limit: int = Field(default=5, ge=1, le=20)


class ResultIn(BaseModel):
    ok: bool
    result: dict = Field(default_factory=dict)


def mount(app, engine, whole_install, actor) -> None:
    runners = engine.runners

    def runner_group(request: Request) -> str:
        header = request.headers.get("authorization", "")
        group = runners.authenticate(header[7:] if header.startswith("Bearer ") else None)
        if not group:
            raise HTTPException(401, "missing or bad runner token")
        return group

    @app.post("/api/runner/poll", include_in_schema=False)
    def poll(body: PollIn, group: str = Depends(runner_group)):
        runners.seen(group, body.version)
        return {"group": group, "jobs": runners.claim(group, body.limit)}

    @app.post("/api/runner/jobs/{jid}", include_in_schema=False)
    def report(jid: int, body: ResultIn, group: str = Depends(runner_group)):
        if not runners.complete(group, jid, body.ok, body.result):
            raise HTTPException(409, "not a job leased to this runner group (finished, abandoned or not yours)")
        return {"ok": True}

    @app.get("/api/runners", dependencies=whole_install)
    def list_runners():
        return runners.groups()

    @app.post("/api/runners/{group}/token", dependencies=whole_install)
    def new_token(group: str, request: Request):
        try:
            token = runners.issue_token(group)
        except ValueError as e:
            raise HTTPException(400, str(e))
        engine.store.log(f"runner token for group {group} created by {actor(request)}")
        return {"group": group, "token": token}

    @app.delete("/api/runners/{group}/token", dependencies=whole_install)
    def revoke(group: str, request: Request):
        if not runners.revoke(group):
            raise HTTPException(404, "no token for this group")
        engine.store.log(f"runner token for group {group} revoked by {actor(request)}")
        return {"ok": True}
