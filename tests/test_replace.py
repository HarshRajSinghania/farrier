"""Mass replace and revoke: replace now, revoke an old certificate only once nothing serves it."""
import pytest

from farrier.core.discovery import fetch_cert
from farrier.core.replace import select
from farrier.core.x509util import parse_pem


class Revoking:
    """The local CA, plus a revoke() that records what the CA was asked to revoke."""

    def __init__(self, ca):
        self.ca, self.revoked = ca, []

    def issue(self, csr, names):
        return self.ca.issue(csr, names)

    def revoke(self, pem, reason):
        self.revoked.append((parse_pem(pem).fingerprint, reason))


def test_replace_then_revoke_when_nothing_serves_the_old_cert(engine, served, monkeypatch):
    from farrier.core.engine import Engine
    s, srv = served
    ca = Revoking(engine.issuers["default"])
    monkeypatch.setattr(Engine, "issuers", property(lambda self: {"default": ca}))
    old = fetch_cert("127.0.0.1", s.port, "app.internal.test")
    e1 = engine.store.upsert_endpoint({"name": "web", "host": "127.0.0.1", "port": s.port, "sni": "app.internal.test",
                                       "connector": "files", "connector_config": {
                                           "fullchain_path": str(srv / "fullchain.pem"), "cert_path": str(srv / "leaf.pem"),
                                           "key_path": str(srv / "key.pem")}})
    e2 = engine.store.upsert_endpoint({"name": "other-vip", "host": "10.0.0.9", "port": 443, "connector": "manual",
                                       "connector_config": {}})
    engine.observe(engine.store.endpoint(e1))
    engine.store.add_observation(e2, old)                      # the same certificate, on another VIP

    with pytest.raises(ValueError):
        select(engine, {})                                    # no accidental "replace everything"
    assert [e["id"] for e in select(engine, {"endpoint_ids": [e1]})] == [e1]

    from farrier.core.replace import replace
    out = replace(engine, {"endpoint_ids": [e1]}, "keyCompromise", True, "test")
    rid = out["renewals"][0]["renewal_id"]
    engine.tick(scan=False)
    assert engine.store.renewal(rid)["state"] == "done"
    assert ca.revoked == []                                   # other-vip still serves it: not yet

    engine.store.add_observation(e2, None, "no TLS")          # other-vip moved off it too
    engine.tick(scan=False)
    assert ca.revoked == [(old.fingerprint, "keyCompromise")]
    engine.tick(scan=False)
    assert len(ca.revoked) == 1                               # once


def test_replace_route_dry_run(engine, served, monkeypatch):
    from fastapi.testclient import TestClient

    from farrier.api.app import create_app
    monkeypatch.setenv("FARRIER_API_TOKEN", "t")
    s, srv = served
    engine.store.upsert_endpoint({"name": "x", "host": "127.0.0.1", "port": s.port, "sni": "app.internal.test",
                                  "connector": "manual", "connector_config": {}})
    engine.observe(engine.store.endpoints()[0])
    c = TestClient(create_app(engine))
    r = c.post("/api/replace", headers={"Authorization": "Bearer t"}, json={"filter": {"ca": "Farrier"}, "dry_run": True})
    assert r.status_code == 200 and [m["name"] for m in r.json()["matches"]] == ["x"]
    assert c.post("/api/replace", headers={"Authorization": "Bearer t"},
                  json={"filter": {"ca": "x"}, "revoke": True, "reason": "oops"}).status_code == 400
