"""Zombie certificates: alive, but they should not be.

Kinds:
  expired_served        an expired certificate is still being served
  not_in_inventory      a scan found a TLS endpoint Farrier does not track (active scan only)
  discovered_unowned    an endpoint added by discovery that nobody has claimed (no owner, never renewed)
  unexpected_issuer     a name Farrier manages is served by a certificate from a different CA
  unexpected_issuance   same CA, but a certificate Farrier did not issue (someone renewed by hand)
  stale_duplicate       an endpoint serves a fingerprint that a verified renewal already replaced
  dead_endpoint         an inventory endpoint has not answered a TLS handshake for N days
  pack_never_installed  a manual change pack has waited longer than N days (or is past its deadline)

``from_store`` works only from stored observations and is cheap; ``from_scan`` adds what an active
discovery scan sees. Each finding: {kind, severity, endpoint_id, endpoint, target, evidence, action}.
"""
from __future__ import annotations

from collections import Counter
from datetime import datetime, timedelta

from farrier.core import policy
from farrier.core.x509util import parse_pem
from farrier.db.store import parse_dt

SEVERITY = {"expired_served": "critical", "stale_duplicate": "high", "unexpected_issuer": "high",
            "unexpected_issuance": "medium", "pack_never_installed": "medium", "dead_endpoint": "medium",
            "not_in_inventory": "medium", "discovered_unowned": "low"}


def _finding(kind: str, ep: dict | None, evidence: dict, action: str, target: str | None = None) -> dict:
    return {"kind": kind, "severity": SEVERITY[kind], "endpoint_id": ep and ep["id"], "endpoint": ep and ep["name"],
            "target": target or (ep and (f"{ep['sni']}@" if ep.get("sni") else "") + f"{ep['host']}:{ep['port']}"),
            "evidence": evidence, "action": action}


def _names(ep: dict) -> set[str]:
    return {n.lower() for n in [ep.get("common_name"), *(ep.get("sans") or [])] if n}


def _covers(cert_names: set[str], managed: set[str]) -> set[str]:
    from farrier.monitoring.health import name_matches
    return {m for m in managed for c in cert_names if name_matches(c, m) or name_matches(m, c)}


class _Farrier:
    """What Farrier itself issued and verified, from the renewals table."""

    def __init__(self, store):
        rows = store.q("""SELECT id, endpoint_id, state, prev_fingerprint, new_fingerprint, cert_pem, updated_at
                          FROM renewals WHERE new_fingerprint IS NOT NULL ORDER BY id""")
        self.issued = {r["new_fingerprint"] for r in rows}
        self.done = [r for r in rows if r["state"] == "done"]
        self.issuers_by_ep: dict[int, set[str]] = {}
        self.all_issuers: set[str] = set()
        for r in rows:
            try:
                iss = parse_pem(r["cert_pem"]).issuer if r["cert_pem"] else None
            except Exception:  # noqa: BLE001 - a corrupt row must not break the report
                iss = None
            if iss:
                self.issuers_by_ep.setdefault(r["endpoint_id"], set()).add(iss)
                self.all_issuers.add(iss)
        # fingerprint -> (renewal that replaced it, when it was verified)
        self.superseded: dict[str, dict] = {}
        for r in self.done:
            if r["prev_fingerprint"] and r["prev_fingerprint"] != r["new_fingerprint"]:
                self.superseded[r["prev_fingerprint"]] = r
        for fp in list(self.superseded):
            # a fingerprint deliberately re-deployed by a later verified renewal is current again, not stale
            if any(r["new_fingerprint"] == fp and r["id"] > self.superseded[fp]["id"] for r in self.done):
                del self.superseded[fp]


def from_store(store, now: datetime | None = None, dead_days: int = 7, pack_days: int = 3) -> list[dict]:
    now = now or policy.utcnow()
    out: list[dict] = []
    eps = store.endpoints()
    far = _Farrier(store)
    managed_eps = [e for e in eps if e["id"] in far.issuers_by_ep]
    renewed_eps = {r["endpoint_id"] for r in store.q("SELECT DISTINCT endpoint_id FROM renewals")}

    for e in eps:
        fp, na = e["fingerprint"], parse_dt(e["not_after"])
        obs_at = parse_dt(e["observed_at"])
        if fp and na and na < now and e["enabled"]:
            out.append(_finding("expired_served", e, {
                "fingerprint": fp, "not_after": e["not_after"], "issuer": e["cert_issuer"],
                "days_expired": round((now - na) / timedelta(days=1), 1), "observed_at": e["observed_at"]},
                "renew now (POST /api/endpoints/{id}/renew), or disable/remove the endpoint if it is retired"))
        if fp and fp in far.superseded and obs_at and obs_at > parse_dt(far.superseded[fp]["updated_at"]):
            r = far.superseded[fp]
            out.append(_finding("stale_duplicate", e, {
                "fingerprint": fp, "replaced_by": r["new_fingerprint"], "renewal_id": r["id"],
                "replaced_on_endpoint_id": r["endpoint_id"], "verified_at": r["updated_at"],
                "observed_at": e["observed_at"]},
                "this node still serves the old certificate: deploy the current one here (a missed cluster member, "
                "VIP or reverted config), then re-verify"))
        # names Farrier manages served by a certificate Farrier did not issue
        if fp and fp not in far.issued and e["enabled"] and (not na or na >= now):
            mine = far.issuers_by_ep.get(e["id"])
            if mine:
                last_done = max((r for r in far.done if r["endpoint_id"] == e["id"]), key=lambda r: r["id"],
                                default=None)
                if last_done and obs_at and obs_at > parse_dt(last_done["updated_at"]) and \
                        fp != last_done["prev_fingerprint"]:
                    kind = "unexpected_issuance" if e["cert_issuer"] in mine else "unexpected_issuer"
                    out.append(_finding(kind, e, {
                        "fingerprint": fp, "issuer": e["cert_issuer"], "farrier_issuers": sorted(mine),
                        "farrier_fingerprint": last_done["new_fingerprint"], "observed_at": e["observed_at"]},
                        "find out who replaced Farrier's certificate; adopt it (cancel Farrier's plan) or redeploy"))
            elif managed_eps:
                overlap = set()
                for m in managed_eps:
                    if m["id"] != e["id"]:
                        overlap |= _covers({e["subject_cn"].lower()} if e["subject_cn"] else set(), _names(m))
                if overlap and e["cert_issuer"] and e["cert_issuer"] not in far.all_issuers:
                    out.append(_finding("unexpected_issuer", e, {
                        "fingerprint": fp, "issuer": e["cert_issuer"], "names": sorted(overlap),
                        "farrier_issuers": sorted(far.all_issuers)},
                        "a different CA issued for a name Farrier manages: check CAA and who requested it"))
        # dead: nothing but errors for dead_days
        if e["enabled"] and e["scan_error"]:
            last_ok = store.q1("""SELECT observed_at FROM observations WHERE endpoint_id=? AND fingerprint IS NOT NULL
                                  ORDER BY observed_at DESC LIMIT 1""", (e["id"],))
            first_err = store.q1("""SELECT MIN(observed_at) AS at FROM observations WHERE endpoint_id=? AND error IS NOT NULL
                                    AND observed_at > ?""", (e["id"], last_ok["observed_at"] if last_ok else ""))
            since = parse_dt(first_err["at"]) if first_err and first_err["at"] else None
            if since and now - since >= timedelta(days=dead_days):
                out.append(_finding("dead_endpoint", e, {
                    "last_success": last_ok and last_ok["observed_at"], "failing_since": first_err["at"],
                    "last_error": e["scan_error"], "days": round((now - since) / timedelta(days=1), 1)},
                    f"no TLS answer for {dead_days}+ days: confirm it is decommissioned and remove it (or fix the "
                    "address), so it stops generating renewals and alerts"))
        if "discovered" in (e["tags"] or []) and not e["owner"] and e["id"] not in renewed_eps and fp:
            out.append(_finding("discovered_unowned", e, {
                "subject": e["subject_cn"], "issuer": e["cert_issuer"], "not_after": e["not_after"]},
                "assign an owner and a connector, or remove it if the service should not exist"))

    for r in store.renewals(("awaiting_manual",), limit=100000):
        since = parse_dt(r["updated_at"])
        overdue = r["deadline"] and parse_dt(r["deadline"]) < now
        if overdue or (since and now - since >= timedelta(days=pack_days)):
            ep = store.endpoint(r["endpoint_id"])
            out.append(_finding("pack_never_installed", ep, {
                "renewal_id": r["id"], "waiting_since": r["updated_at"], "deadline": r["deadline"],
                "ticket_ref": r["ticket_ref"], "overdue": bool(overdue),
                "days_waiting": round((now - since) / timedelta(days=1), 1) if since else None},
                "install the change pack (GET /api/renewals/{rid}/pack) or cancel the renewal; the pack holds a "
                "private key on disk until then"))
    return out


def from_scan(store, results, now: datetime | None = None) -> list[dict]:
    """Findings from an active discovery scan (discovery.scan results); nothing is written to the inventory."""
    now = now or policy.utcnow()
    out: list[dict] = []
    far = _Farrier(store)
    eps = store.endpoints()
    managed = {n for e in eps if e["id"] in far.issuers_by_ep for n in _names(e)}
    for r in results:
        if r.cert is None:
            continue
        target = (f"{r.sni}@" if r.sni else "") + f"{r.host}:{r.port}"
        ep = store.endpoint_by_addr(r.host, r.port, r.sni)
        c = r.cert
        if c.not_after < now:
            out.append(_finding("expired_served", ep, {
                "fingerprint": c.fingerprint, "subject": c.subject_cn, "issuer": c.issuer,
                "not_after": c.not_after.isoformat(), "days_expired": round((now - c.not_after) / timedelta(days=1), 1)},
                "replace the certificate or take the service down", target=target))
        if ep is None:
            out.append(_finding("not_in_inventory", None, {
                "fingerprint": c.fingerprint, "subject": c.subject_cn, "sans": c.sans[:20], "issuer": c.issuer,
                "not_after": c.not_after.isoformat()},
                "add it to the inventory (POST /api/discover registers it) or shut it down", target=target))
        if c.fingerprint in far.superseded:
            ren = far.superseded[c.fingerprint]
            out.append(_finding("stale_duplicate", ep, {
                "fingerprint": c.fingerprint, "replaced_by": ren["new_fingerprint"], "renewal_id": ren["id"],
                "verified_at": ren["updated_at"]},
                "deploy the current certificate on this node", target=target))
        if c.fingerprint not in far.issued and c.not_after >= now:
            overlap = _covers({n.lower() for n in [c.subject_cn, *c.sans] if n}, managed)
            if overlap:
                kind = "unexpected_issuance" if c.issuer in far.all_issuers else "unexpected_issuer"
                out.append(_finding(kind, ep, {
                    "fingerprint": c.fingerprint, "issuer": c.issuer, "names": sorted(overlap),
                    "farrier_issuers": sorted(far.all_issuers)},
                    "a certificate for a name Farrier manages was issued outside Farrier: find its owner, revoke it "
                    "if unexpected, or bring the endpoint under Farrier", target=target))
    return out


def summarize(findings: list[dict], now: datetime | None = None) -> dict:
    order = list(SEVERITY)
    seen, unique = set(), []
    for f in findings:  # a scan and the stored view can report the same thing
        key = (f["kind"], f["target"], f["evidence"].get("fingerprint"), f["evidence"].get("renewal_id"))
        if key not in seen:
            seen.add(key)
            unique.append(f)
    findings = sorted(unique, key=lambda f: (order.index(f["kind"]), f["endpoint"] or f["target"] or ""))
    return {"generated_at": (now or policy.utcnow()).isoformat(timespec="seconds"), "count": len(findings),
            "by_kind": dict(Counter(f["kind"] for f in findings)), "findings": findings}
