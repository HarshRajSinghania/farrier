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
    base = f"http://{args.host}:{args.port}"
    print(f"farrier engine API on {base}/api (OpenAPI at {base}/docs); dashboard: `docker compose up` runs both, "
          f"or cd web && FARRIER_API_URL={base} npm run dev", flush=True)
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
    for t, n in restore(dst, data, allow_unsigned=args.allow_unsigned).items():
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
    results = scan(expand_targets(" ".join(args.targets), limit=1 << 18), timeout=args.timeout)
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


NOT_FOUND = 4       # exit code for "no such endpoint", the CLI's 404


def _emit(args, obj, text) -> None:
    """``--json`` prints the payload the matching API route returns; otherwise the lines ``text()`` yields."""
    if args.json:
        print(json.dumps(obj, indent=2, default=str))
    else:
        for line in text():
            print(line)


def _endpoint(eng, ref: str) -> dict:
    """An inventory endpoint by name, or by id when ``ref`` is a number."""
    ep = eng.store.endpoint(int(ref)) if ref.isdigit() else None
    ep = ep or next((e for e in eng.store.endpoints() if e["name"] == ref), None)
    if not ep:
        print(f"farrier: no endpoint named or numbered {ref!r}", file=sys.stderr)
        sys.exit(NOT_FOUND)
    return ep


def cmd_version(args):
    from farrier import __version__
    print(f"farrier {__version__}")


def cmd_ssh_scan(args):
    from farrier.ssh import access, db, scan
    try:
        targets = access.expand_hosts(args.targets, 22)
    except access.Invalid as e:
        sys.exit(f"farrier: {e}")
    if not targets:
        sys.exit("farrier: no targets")
    eng = _engine(args)
    out = scan.scan(eng.store, targets)
    eng.store.log(f"ssh scan of {len(targets)} targets by cli: {out['ssh']} answered")
    hosts = [scan.host_view(h) for t in targets if (h := db.host_by_addr(eng.store, *t))]

    def text():
        yield f"{'host':<24}{'banner':<34}{'host keys':<32}{'pqc kex':>8}{'findings':>9}"
        for h in hosts:
            keys = ", ".join(f"{k['type']} {k['bits']}" for k in h["host_keys"]) or "-"
            yield (f"{h['host'] + ':' + str(h['port']):<24}{(h['banner'] or h['error'] or '-')[:33]:<34}"
                   f"{keys[:31]:<32}{'yes' if h['pqc_kex'] else 'no':>8}{len(h['findings']):>9}")
        for e in out["errors"]:
            yield f"{e['host']}:{e['port']}  -- {e['error']}"
        yield f"{out['scanned']} scanned, {out['ssh']} answered SSH, {out['saved']} stored"
    _emit(args, out | {"hosts": hosts}, text)


def cmd_ssh_keys(args):
    from farrier.api.ssh_routes import key_view
    from farrier.ssh import db
    keys = [key_view(k) for k in db.keys(_engine(args).store)]

    def text():
        if not keys:
            yield "no authorized keys collected yet (add an SSH access profile, then run a collection)"
        for k in keys:
            yield (f"{k['id']:>5}  {k['user']}@{k['host']}:{k['port']}  {k['type']} {k['bits']}  "
                   f"{k['fingerprint_sha256']}  {k['comment']}")
            for f in k["findings"]:
                yield f"       {f['severity']:<8} {f['detail']}"
    _emit(args, keys, text)


def cmd_crypto_scan(args):
    from farrier.core.discovery import expand_targets
    from farrier.crypto import repository, service
    from farrier.crypto.probe import target_label
    try:
        targets = expand_targets(" ".join(args.targets), limit=service.MAX_TARGETS)
        if not targets:
            sys.exit("farrier: no targets")
        eng = _engine(args)
        timeout = args.timeout if args.timeout is not None else float(eng.settings.get("scan_timeout", 5.0))
        out = service.scan_targets(eng.store, targets, timeout=timeout)
    except ValueError as e:
        sys.exit(f"farrier: {e}")
    eng.store.log(f"crypto scan of {len(targets)} targets by cli")
    wanted = {target_label(*t) for t in targets}
    assets = [a for a in repository.tls_assets(eng.store) if a["target"] in wanted]

    def text():
        for a in assets:
            yield a["target"]
            if a["error"]:
                yield f"  error:        {a['error']}"
            yield f"  TLS versions: {', '.join(a['protocol_versions']) or '-'}"
            yield f"  key exchange: {a['key_exchange'] or '-'}{' (post-quantum)' if a['pqc_key_exchange'] else ''}"
            yield f"  PQC status:   {a['pqc']['status']}"
            for r in a["pqc"]["reasons"]:
                yield f"    - {r}"
        yield f"{out['scanned']} scanned, {out['stored']} stored"
    _emit(args, out | {"assets": assets}, text)


def cmd_crypto_summary(args):
    from farrier.crypto import service
    s = service.summary(_engine(args).store)

    def text():
        yield f"{s['total']} assets"
        yield "PQC status:    " + ", ".join(f"{k} {v}" for k, v in s["by_status"].items())
        yield "key algorithm: " + (", ".join(f"{k} {v}" for k, v in s["by_key_algorithm"].items()) or "-")
        yield "weak:          " + ", ".join(f"{k} {v}" for k, v in s["weak"].items())
    _emit(args, s, text)


def cmd_crypto_cbom(args):
    from farrier.crypto import service
    doc = json.dumps(service.cbom(_engine(args).store), indent=2)
    if args.output:
        Path(args.output).write_text(doc + "\n", encoding="utf-8")
        print(f"CycloneDX CBOM written to {args.output}", file=sys.stderr)
    else:
        print(doc)


def cmd_certs_show(args):
    from farrier.crypto import certificate
    eng = _engine(args)
    ep = _endpoint(eng, args.endpoint)
    d = certificate.details(eng.store, ep)

    def text():
        if not d["observed_at"]:
            yield f"{ep['name']}: no certificate observed yet (run farrier tick)"
            return
        key = d["key"] or {}
        rows = [("endpoint", f"{ep['name']} (id {ep['id']}, {ep['host']}:{ep['port']})"),
                ("subject", d["subject"] or d["common_name"]), ("SANs", ", ".join(d["sans"])),
                ("issuer", d["issuer"]), ("serial", d["serial"]),
                ("valid", f"{d['not_before']} -> {d['not_after']}"), ("days left", d["days_left"]),
                ("key", " ".join(str(v) for v in key.values() if v not in (None, ""))),
                ("signature", d["signature_algorithm"]), ("sha256", d["fingerprints"]["sha256"]),
                ("self-signed", d["self_signed"]), ("chain", f"{len(d['chain'])} certificate(s)"),
                ("renewals", len(d.get("renewals") or [])), ("health", (d.get("health") or {}).get("grade")),
                ("observed", d["observed_at"])]
        for k, v in rows:
            yield f"{k + ':':<13}{'-' if v in (None, '') else v}"
    _emit(args, d, text)


def cmd_endpoints_approve(args):
    eng = _engine(args)
    ep = _endpoint(eng, args.endpoint)
    eng.approve(ep["id"], "cli")
    _emit(args, {"ok": True, "endpoint_id": ep["id"]}, lambda: [f"{ep['name']} approved for renewal"])


def main(argv=None):
    from farrier import __version__
    p = argparse.ArgumentParser(prog="farrier", description="Agentless machine identity automation: TLS "
                                "certificates, SSH keys, cryptographic discovery and PQC readiness.")
    p.add_argument("--version", action="version", version=f"farrier {__version__}")
    p.add_argument("--data", default=os.environ.get("FARRIER_DATA", "./farrier-data"),
                   help="data directory (default: $FARRIER_DATA, else ./farrier-data)")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("serve", help="run the engine API (OpenAPI at /docs) and the background renewal loop; "
                       "the dashboard is the separate web app")
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
    s.add_argument("--allow-unsigned", action="store_true",
                   help="restore a backup without a valid signature (made before signing, or by another master "
                   "key); rows with connector commands still need FARRIER_ALLOW_API_COMMANDS=1")
    s.set_defaults(fn=cmd_restore)

    s = sub.add_parser("demo", help="serve a simulated estate of real TLS endpoints and run the API against it")
    s.add_argument("--port", type=int, default=8740)
    s.add_argument("--tick", type=float, default=20)
    s.add_argument("--simulate-date", help="issue certs as if on this date, e.g. 2029-03-15 for 47-day life")
    s.set_defaults(fn=cmd_demo)

    s = sub.add_parser("scan", help="handshake with TLS targets and report the certificates they serve")
    s.add_argument("targets", nargs="+", help="host[:port], 10.0.0.0/24:443|8443, sni@ip:port")
    s.add_argument("--register", action="store_true", help="add unknown endpoints to the inventory")
    s.add_argument("--timeout", type=float, default=3.0)
    s.add_argument("-v", "--verbose", action="store_true")
    s.set_defaults(fn=cmd_scan)

    s = sub.add_parser("tick", help="run one scan/plan/advance cycle on the data directory and print the result")
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

    s = sub.add_parser("version", help="print the version")
    s.set_defaults(fn=cmd_version)

    def js(x):
        x.add_argument("--json", action="store_true", help="machine-readable JSON output")
        return x

    s = sub.add_parser("ssh", help="SSH host discovery and authorized keys")
    ssub = s.add_subparsers(dest="ssh_cmd", required=True)
    x = js(ssub.add_parser("scan", help="probe SSH targets without logging in: banner, host keys, PQC key "
                           "exchange, findings; results are stored"))
    x.add_argument("targets", nargs="+", help="host[:port] or CIDR (default port 22)")
    x.set_defaults(fn=cmd_ssh_scan)
    js(ssub.add_parser("keys", help="list collected authorized keys with their findings")).set_defaults(fn=cmd_ssh_keys)

    s = sub.add_parser("crypto", help="cryptographic discovery and PQC readiness")
    csub = s.add_subparsers(dest="crypto_cmd", required=True)
    x = js(csub.add_parser("scan", help="probe TLS targets: versions, key exchange, PQC status; results are stored"))
    x.add_argument("targets", nargs="+", help="host[:port], 10.0.0.0/24:443|8443, sni@ip:port")
    x.add_argument("--timeout", type=float, default=None, help="seconds per handshake (default: scan_timeout setting)")
    x.set_defaults(fn=cmd_crypto_scan)
    js(csub.add_parser("summary", help="stored assets by PQC status, key algorithm and weak-crypto flag")
       ).set_defaults(fn=cmd_crypto_summary)
    x = csub.add_parser("cbom", help="CycloneDX 1.6 cryptography bill of materials of every stored asset (JSON)")
    x.add_argument("-o", "--output", help="write to this file instead of stdout")
    x.set_defaults(fn=cmd_crypto_cbom)

    s = sub.add_parser("certs", help="certificates in the inventory")
    csub = s.add_subparsers(dest="certs_cmd", required=True)
    x = js(csub.add_parser("show", help="certificate details of an endpoint: subject, SANs, key, chain, renewals "
                           f"(exit {NOT_FOUND} if there is no such endpoint)"))
    x.add_argument("endpoint", help="endpoint name or id")
    x.set_defaults(fn=cmd_certs_show)

    s = sub.add_parser("endpoints", help="inventory endpoints")
    esub = s.add_subparsers(dest="endpoints_cmd", required=True)
    x = js(esub.add_parser("approve", help="let a discovered endpoint be renewed (logged with actor cli)"))
    x.add_argument("endpoint", help="endpoint name or id")
    x.set_defaults(fn=cmd_endpoints_approve)

    def describe(parser):   # `farrier <cmd> --help` opens with the same one-liner the command list shows
        for action in parser._subparsers._group_actions if parser._subparsers else ():
            for choice in action._choices_actions:
                child = action.choices[choice.dest]
                child.description = child.description or choice.help
                describe(child)
    describe(p)

    args = p.parse_args(argv)
    if args.cmd == "demo" and "--data" not in (argv if argv is not None else sys.argv)             and not os.environ.get("FARRIER_DATA"):
        args.data = "./farrier-demo"
    args.fn(args)


if __name__ == "__main__":
    main()
