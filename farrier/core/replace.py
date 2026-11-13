"""Mass replacement and revocation: the drill for a key compromise, a distrusted CA or a bad issuer.

replace() renews every endpoint matching a filter now (skipping change windows, as "renew now" does), and
with revoke=True records the certificate each one served. Once nothing serves an old certificate any more
(every endpoint that had it is replaced and verified), revoke_due() asks its CA to revoke it: an ACME CA
(RFC 8555 revokeCert, signed by the issuer's account) or AWS Private CA. One certificate on many VIPs is
revoked only after the last of them moved.

Filter keys (all optional, combined with AND): endpoint_ids, project, issuer (an issuers.json name),
ca (text in the served certificate's issuer, e.g. "R10" or "Entrust"), key_type, tag.
"""
from __future__ import annotations

import json

from farrier.db.store import OPEN_STATES, now_iso

KIND = "revoke_after"   # config_items: renewal id -> {prev, reason, issuer, endpoint_id}
REASONS = {"unspecified": 0, "keyCompromise": 1, "cACompromise": 2, "affiliationChanged": 3, "superseded": 4,
           "cessationOfOperation": 5}
FILTER_KEYS = {"endpoint_ids", "project", "issuer", "ca", "key_type", "tag"}


def matches(ep: dict, f: dict) -> bool:
    if f.get("endpoint_ids") and ep["id"] not in {int(i) for i in f["endpoint_ids"]}:
        return False
    if f.get("project") and ep.get("project") != f["project"]:
        return False
    if f.get("issuer") and (ep.get("issuer") or "default") != f["issuer"]:
        return False
    if f.get("ca") and str(f["ca"]).lower() not in str(ep.get("cert_issuer") or "").lower():
        return False
    if f.get("key_type") and ep.get("key_type") != f["key_type"]:
        return False
    if f.get("tag") and f["tag"] not in (ep.get("tags") or []):
        return False
    return True


def select(engine, f: dict, visible=None) -> list[dict]:
    if not f or set(f) - FILTER_KEYS or not any(f.values()):
        raise ValueError(f"name at least one filter: {', '.join(sorted(FILTER_KEYS))}")
    return [e for e in engine.store.endpoints()
            if e["enabled"] and matches(e, f) and (visible is None or visible(e))]


def replace(engine, f: dict, reason: str, revoke: bool, actor: str, visible=None) -> dict:
    if revoke and reason not in REASONS:
        raise ValueError(f"revocation reason: one of {', '.join(REASONS)}")
    from farrier.core.engine import NotApproved
    out = {"renewals": [], "skipped": []}
    for ep in select(engine, f, visible):
        try:
            rid = engine.force_renewal(ep["id"], f"replace ({reason}) by {actor}")
        except NotApproved:
            out["skipped"].append({"endpoint_id": ep["id"], "name": ep["name"], "why": "discovered, not approved"})
            continue
        out["renewals"].append({"endpoint_id": ep["id"], "name": ep["name"], "renewal_id": rid})
        if revoke and ep.get("fingerprint"):
            body = {"prev": ep["fingerprint"], "reason": reason, "issuer": ep.get("issuer") or "default",
                    "endpoint_id": ep["id"], "requested_by": actor, "at": now_iso()}
            engine.store.x("DELETE FROM config_items WHERE kind=? AND name=?", (KIND, str(rid)))
            engine.store.x("INSERT INTO config_items(kind, name, body, updated_at) VALUES (?,?,?,?)",
                           (KIND, str(rid), json.dumps(body), now_iso()))
    engine.store.log(f"replace ({reason}) requested by {actor}: {len(out['renewals'])} renewals"
                     + (", old certificates revoked once replaced" if revoke else ""))
    return out


def revoke_due(engine) -> int:
    """Revoke old certificates nothing serves any more (leader tick)."""
    done = 0
    for row in engine.store.q("SELECT name, body FROM config_items WHERE kind=?", (KIND,)):
        b, rid = json.loads(row["body"]), int(row["name"])
        r = engine.store.renewal(rid)
        state = r["state"] if r else "gone"
        if state in OPEN_STATES:
            continue
        drop = lambda: engine.store.x("DELETE FROM config_items WHERE kind=? AND name=?", (KIND, row["name"]))  # noqa: E731
        if state != "done":
            drop()
            engine.store.log(f"old certificate {b['prev'][:16]} not revoked: its replacement ended {state}",
                             b["endpoint_id"], rid, level="warning")
            continue
        still = [e["name"] for e in engine.store.endpoints() if e["enabled"] and e["fingerprint"] == b["prev"]]
        if still:
            continue   # another endpoint still serves it: revoking now would break that one
        pems = engine.store.certificate_pems(b["prev"])
        issuer = engine.issuers.get(b["issuer"]) or engine.issuers.get("default")
        if not pems or not hasattr(issuer, "revoke"):
            drop()
            why = "its PEM was never stored" if not pems else f"issuer {b['issuer']} cannot revoke"
            engine.store.log(f"old certificate {b['prev'][:16]} not revoked: {why}; revoke it at the CA",
                             b["endpoint_id"], rid, level="warning")
            continue
        try:
            issuer.revoke(pems["cert_pem"], b["reason"])
        except Exception as e:  # noqa: BLE001 - kept, retried next tick
            engine.store.log(f"revoking {b['prev'][:16]} failed: {type(e).__name__}: {e}"[:500], b["endpoint_id"],
                             rid, level="error")
            continue
        drop()
        engine.store.log(f"old certificate {b['prev'][:16]} revoked ({b['reason']})", b["endpoint_id"], rid)
        done += 1
    return done
