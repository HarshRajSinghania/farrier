"""`farrier runner`: runs inside a segmented network and does the engine's network work there.

It connects out to the engine over HTTPS (nothing listens), claims jobs for its group, runs them with
Farrier's own connectors and scanners, and posts results. Device credentials in an endpoint's
connector_config are env:/file:/cloud references, resolved here, so they can live only on this host.

  FARRIER_RUNNER_TOKEN=frn.dmz.... farrier runner --url https://farrier-gw.example.com
"""
from __future__ import annotations

import base64
import sys
import tempfile
import time
from pathlib import Path

import httpx

from farrier import __version__
from farrier.connectors import Bundle, make_connector
from farrier.core.discovery import fetch_cert


def _observe(p: dict) -> dict:
    out = []
    for t in p["targets"]:
        try:
            c = fetch_cert(t["host"], t["port"], t.get("sni"), p.get("timeout", 5.0))
            out.append({"endpoint_id": t["endpoint_id"], "der": base64.b64encode(c.der).decode(),
                        "chain": [base64.b64encode(d).decode() for d in c.chain_der]})
        except Exception as e:  # noqa: BLE001 - every failure is an observation
            out.append({"endpoint_id": t["endpoint_id"], "error": f"{type(e).__name__}: {e}"[:300]})
    return {"observations": out}


def _verify(p: dict) -> dict:
    seen = None
    for i in range(3):
        try:
            seen = fetch_cert(p["host"], p["port"], p.get("sni"), p.get("timeout", 5.0)).fingerprint
        except Exception:  # noqa: BLE001
            seen = None
        if seen == p["fingerprint"]:
            break
        if i < 2:
            time.sleep(p.get("retry_seconds", 2.0))
    problems: list[str] = []
    if seen == p["fingerprint"] and p.get("deep"):
        from farrier.monitoring.health import verify_deployment
        v = verify_deployment(p["host"], p["port"], p.get("sni"), p["fingerprint"], p.get("names") or [],
                              addresses=p.get("vips"), resolve_all=p.get("resolve_all", False),
                              trust_pems=p.get("trust_pems"), timeout=p.get("timeout", 5.0))
        problems = [] if v["ok"] else list(v["problems"])
    return {"fingerprint": seen, "problems": problems}


def execute(job: dict, work_dir: Path) -> tuple[bool, dict]:
    """(ok, result) for one job; never raises."""
    p = job["payload"]
    local = {k: v for k, v in (p.get("config") or {}).items() if k != "runner"}   # resolve references here
    try:
        if job["kind"] == "observe":
            return True, _observe(p)
        if job["kind"] == "verify":
            return True, _verify(p)
        if job["kind"] == "deploy":
            return True, {"token": make_connector(p["connector"], local, work_dir).deploy(Bundle(**p["bundle"]))}
        if job["kind"] == "rollback":
            make_connector(p["connector"], local, work_dir).rollback(p["token"])
            return True, {}
        return False, {"error": f"this runner ({__version__}) does not know job kind {job['kind']!r}; upgrade it"}
    except Exception as e:  # noqa: BLE001 - reported to the engine, which decides
        return False, {"error": f"{type(e).__name__}: {e}"[:2000]}


def run(url: str, token: str, *, once: bool = False, interval: float = 5.0, verify_tls=True, http=None,
        work_dir: Path | None = None, log=print) -> int:
    """Poll forever (or once). Returns the number of jobs run."""
    c = http or httpx.Client(base_url=url.rstrip("/"), verify=verify_tls, timeout=60,
                             headers={"User-Agent": f"farrier-runner/{__version__}"})
    c.headers["Authorization"] = f"Bearer {token}"
    work = work_dir or Path(tempfile.mkdtemp(prefix="farrier-runner-"))
    done, backoff = 0, interval
    while True:
        try:
            r = c.post("/api/runner/poll", json={"version": __version__})
            if r.status_code == 401:
                raise SystemExit("farrier runner: the engine refused the token (revoked or mistyped)")
            r.raise_for_status()
            jobs = r.json()["jobs"]
            backoff = interval
        except httpx.HTTPError as e:
            log(f"farrier runner: engine unreachable ({type(e).__name__}); retrying in {backoff:.0f}s",
                file=sys.stderr)
            jobs, backoff = [], min(backoff * 2, 300)
        for job in jobs:
            ok, result = execute(job, work)
            log(f"job {job['id']} {job['kind']}: {'ok' if ok else result.get('error')}")
            try:
                c.post(f"/api/runner/jobs/{job['id']}", json={"ok": ok, "result": result}).raise_for_status()
            except httpx.HTTPError as e:   # the lease runs out and the engine treats the job as lost
                log(f"farrier runner: could not report job {job['id']} ({type(e).__name__})", file=sys.stderr)
            done += 1
        if once:
            return done
        if not jobs:
            time.sleep(backoff)   # shortcut: short polling every few seconds; long-polling if the job rate grows
