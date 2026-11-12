"""farrier CLI."""
from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import date
from pathlib import Path

from farrier.core import policy


def _engine(args):
    from farrier.core.engine import Engine
    return Engine(Path(args.data))


def cmd_serve(args):
    import uvicorn

    from farrier.api.app import create_app
    if args.host not in ("127.0.0.1", "localhost") and not os.environ.get("FARRIER_API_TOKEN"):
        sys.exit("refusing to listen on a non-loopback address without FARRIER_API_TOKEN set")
    import signal
    import time

    eng = _engine(args)
    # uvicorn handles SIGTERM itself (stop accepting, drain requests for --grace seconds, run the
    # app shutdown) and then re-raises the signal to whatever handler was installed before it.
    # Installing ours first means that re-raise lands here instead of killing the process, so we
    # can let the running renewal tick finish and hand the leader lease over cleanly.
    signal.signal(signal.SIGTERM, lambda *_: None)
    deadline = time.monotonic() + 2 * args.grace
    try:
        uvicorn.run(create_app(eng, tick_seconds=args.tick), host=args.host, port=args.port,
                    timeout_graceful_shutdown=args.grace)
    finally:
        if not eng.shutdown(timeout=deadline - time.monotonic()):
            print("farrier: renewal tick still running at shutdown deadline; exiting anyway "
                  "(its compare-and-set writes are safe to resume on another replica)", file=sys.stderr)
        eng.store.close()


def cmd_db_migrate(args):
    from farrier.db.dialects import redact_url
    from farrier.db.store import Store
    src = Store(Path(args.data), url=args.source)
    dst = Store(Path(args.data), url=args.to)
    print(f"copying {redact_url(src.url)} ({src.backend}) -> {redact_url(dst.url)} ({dst.backend})")
    counts = src.copy_to(dst, progress=lambda t, n, total: print(f"  {t:<13} {n}/{total}", end="\r"))
    print(" " * 40, end="\r")
    for t, n in counts.items():
        print(f"  {t:<13} {n} rows")
    print(f"done; schema version {dst.schema_version()}. Sealed keys were copied as ciphertext: every replica\n"
          f"needs the same master key (FARRIER_MASTER_KEY or {Path(args.data) / 'master.key'}).\n"
          f"Point FARRIER_DATABASE_URL at the new database and restart.")


def cmd_backup(args):
    from farrier.db.backup import backup
    from farrier.db.store import Store
    from farrier.storage import from_url
    url = backup(Store(Path(args.data)), from_url(args.to, Path(args.data)))
    print(f"backup written to {url}\nSealed keys and secrets stay sealed: restoring needs the same master key.")


def cmd_restore(args):
    from farrier.db.backup import restore, split_object_url
    from farrier.db.store import Store
    storage, key = split_object_url(args.source)
    data = storage.get(key)
    if data is None:
        sys.exit(f"no backup at {args.source}")
    dst = Store(Path(args.data), url=args.to)
    for t, n in restore(dst, data).items():
        print(f"  {t:<13} {n} rows")
    print("done. Every replica needs the master key the backup was sealed with.")


def cmd_demo(args):
    import uvicorn

    from farrier.api.app import create_app
    from farrier.demo import start
    eng, srv = start(Path(args.data), args.simulate_date)
    print(f"demo estate: {len(eng.store.endpoints())} endpoints served by SNI on 127.0.0.1:{srv.port}")
    eng.tick()
    print(f"api:         http://127.0.0.1:{args.port}/api  (OpenAPI docs at /docs)")
    print(f"dashboard:   cd web && FARRIER_API_URL=http://127.0.0.1:{args.port} npm run dev")
    uvicorn.run(create_app(eng, tick_seconds=args.tick), host="127.0.0.1", port=args.port, log_level="warning")


def cmd_scan(args):
    from farrier.core.discovery import expand_targets, scan
    results = scan(expand_targets(" ".join(args.targets)), timeout=args.timeout)
    now = policy.utcnow()
    for r in sorted(results, key=lambda r: (r.cert is None, r.cert and r.cert.not_after)):
        if r.cert:
            dl = policy.days_left(r.cert.not_after, now)
            print(f"{r.sni or r.host}:{r.port:<6} {dl:7.1f}d  {r.cert.lifetime_days:4d}d life  "
                  f"{r.cert.subject_cn}  [{r.cert.issuer}]")
        elif args.verbose:
            print(f"{r.host}:{r.port:<6} -- {r.error}")
    if args.register:
        out = _engine(args).register_scan(results)
        print(f"registered: {out['new']} new, {out['seen']} seen")


def cmd_tick(args):
    print(json.dumps(_engine(args).tick(), indent=2))


def cmd_import(args):
    eng = _engine(args)
    from farrier.connectors import make_connector
    items = json.loads(Path(args.file).read_text())
    for ep in items:
        make_connector(ep.get("connector", "manual"), ep.get("connector_config", {}), eng.data_dir)
        eid = eng.store.upsert_endpoint(ep)
        cert = eng.observe(eng.store.endpoint(eid))
        print(f"{ep['name']:<40} {'ok, ' + str(round(policy.days_left(cert.not_after))) + 'd left' if cert else 'no TLS'}")


def cmd_forecast(args):
    print(f"{args.certs} certificates, {args.manual:.0%} need a human, {args.minutes:.0f} min each\n")
    print(f"{'from':<12}{'max life':>9}{'renew every':>13}{'per year':>10}{'per work day':>14}{'manual h/yr':>13}{'FTE':>6}")
    for f in policy.forecast_timeline(args.certs, args.manual, args.minutes, args.lead):
        print(f"{f['on']:<12}{f['lifetime_days']:>8}d{f['interval_days']:>12}d{f['renewals_per_year']:>10}"
              f"{f['per_working_day']:>14}{f['manual_hours_per_year']:>13}{f['manual_fte']:>6}")
    naive = policy.forecast(args.certs, date(2029, 3, 15), early=False)
    print(f"\nnaive 47-day figure (renew on expiry day): {naive.renewals_per_year}/yr = "
          f"{naive.per_calendar_day}/calendar day = {naive.per_working_day}/working day")


def cmd_mcp(args):
    """MCP over stdio for Claude Desktop/Code, Gemini CLI, Codex. stdout carries only protocol messages."""
    from farrier.api.mcp import run_stdio
    run_stdio(_engine(args))


def main(argv=None):
    p = argparse.ArgumentParser(prog="farrier", description="Certificate renewal for machines ACME can't reach.")
    p.add_argument("--data", default=os.environ.get("FARRIER_DATA", "./farrier-data"))
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("serve", help="run the API, dashboard and background renewal loop")
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=8740)
    s.add_argument("--tick", type=float, default=300, help="seconds between scan/plan/advance cycles")
    s.add_argument("--grace", type=float, default=float(os.environ.get("FARRIER_SHUTDOWN_GRACE", "20")),
                   help="seconds to drain requests on SIGTERM; the running tick gets as long again")
    s.set_defaults(fn=cmd_serve)

    s = sub.add_parser("db", help="database maintenance")
    dbsub = s.add_subparsers(dest="db_cmd", required=True)
    m = dbsub.add_parser("migrate", help="copy every table from the current database to a new one")
    m.add_argument("--to", required=True, help="destination URL, e.g. postgresql://farrier@db/farrier"
                   "?sslmode=verify-full (password via FARRIER_DATABASE_PASSWORD or env:/file: reference)")
    m.add_argument("--from", dest="source", default=None,
                   help="source URL (default: FARRIER_DATABASE_URL, else the SQLite file in --data)")
    m.set_defaults(fn=cmd_db_migrate)

    s = sub.add_parser("backup", help="export the database (JSON lines, sealed values stay sealed) to object storage")
    s.add_argument("--to", required=True, help="storage URL: s3://bucket/prefix, gs://bucket/prefix, "
                   "azblob://account/container/prefix or file:///path")
    s.set_defaults(fn=cmd_backup)

    s = sub.add_parser("restore", help="load a backup into an empty database")
    s.add_argument("--from", dest="source", required=True, help="URL of the backup object written by farrier backup")
    s.add_argument("--to", default=None, help="destination database URL (default: FARRIER_DATABASE_URL, else the "
                   "SQLite file in --data); must be empty")
    s.set_defaults(fn=cmd_restore)

    s = sub.add_parser("demo", help="spin up a simulated estate of real TLS endpoints and open the dashboard")
    s.add_argument("--port", type=int, default=8740)
    s.add_argument("--tick", type=float, default=20)
    s.add_argument("--simulate-date", help="issue certs as if on this date, e.g. 2029-03-15 for 47-day life")
    s.set_defaults(fn=cmd_demo)

    s = sub.add_parser("scan", help="handshake with targets and report what certs they serve")
    s.add_argument("targets", nargs="+", help="host[:port], 10.0.0.0/24:443|8443, sni@ip:port")
    s.add_argument("--register", action="store_true", help="add unknown endpoints to the inventory")
    s.add_argument("--timeout", type=float, default=3.0)
    s.add_argument("-v", "--verbose", action="store_true")
    s.set_defaults(fn=cmd_scan)

    s = sub.add_parser("tick", help="run one scan/plan/advance cycle")
    s.set_defaults(fn=cmd_tick)

    s = sub.add_parser("import", help="import endpoints from a JSON inventory file")
    s.add_argument("file")
    s.set_defaults(fn=cmd_import)

    s = sub.add_parser("forecast", help="renewal workload under the CA/B Forum schedule")
    s.add_argument("--certs", type=int, default=1000)
    s.add_argument("--manual", type=float, default=0.4, help="fraction needing a human (0-1)")
    s.add_argument("--minutes", type=float, default=45, help="hands-on minutes per manual renewal")
    s.add_argument("--lead", type=int, default=0, help="change lead time in days")
    s.set_defaults(fn=cmd_forecast)

    s = sub.add_parser("mcp", help="run the Model Context Protocol server on stdio (for AI agents)")
    s.set_defaults(fn=cmd_mcp)

    args = p.parse_args(argv)
    if args.cmd == "demo" and "--data" not in (argv if argv is not None else sys.argv)             and not os.environ.get("FARRIER_DATA"):
        args.data = "./farrier-demo"
    args.fn(args)


if __name__ == "__main__":
    main()
