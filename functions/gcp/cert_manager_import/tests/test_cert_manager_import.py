"""cert_manager_import against a fake HTTP layer: exercises core *and* the REST adapters."""

from __future__ import annotations

import base64
import json
from collections.abc import Mapping
from typing import Any

import pytest
from cert_manager_import.adapters import (
    CERTMANAGER,
    HttpResponse,
    RestCertificateManager,
    RestSecretManager,
    RestStorage,
)
from cert_manager_import.core import (
    Config,
    Deps,
    certificate_id_for,
    handle,
    labelled_fingerprint,
    resolve_target,
)
from farrier_events import PermanentError, RetryPolicy, TransientError, get_logger, parse_event
from farrier_testkit import NoSleep, assert_no_secrets, make_event, material

KEY_REF = "gcp-sm:projects/acme-prod/secrets/farrier-key-2041/versions/1"
CHAIN_REF = "gs://acme-certs/farrier/2041/fullchain.pem"
NAME = "projects/acme-prod/locations/global/certificates/www-cert"
LOG = get_logger("test-gcp")


class FakeGoogle:
    """Minimal Certificate Manager + Secret Manager + GCS over one HttpClient."""

    def __init__(self, chain: str, key: str) -> None:
        self.chain, self.key = chain, key
        self.certs: dict[str, dict[str, Any]] = {}
        self.requests: list[tuple[str, str, Mapping[str, str] | None, Any]] = []
        self.fail_next: list[int] = []
        self.ops_pending = 0

    def request(self, method: str, url: str, *, params=None, json=None) -> HttpResponse:  # noqa: A002
        self.requests.append((method, url, params, json))
        if self.fail_next:
            return HttpResponse(self.fail_next.pop(0), b'{"error":"x"}')
        if url.startswith("https://storage.googleapis.com/"):
            assert url.endswith("/b/acme-certs/o/farrier%2F2041%2Ffullchain.pem") and params == {"alt": "media"}
            return HttpResponse(200, self.chain.encode())
        if url.startswith("https://secretmanager.googleapis.com/"):
            assert url.endswith("/projects/acme-prod/secrets/farrier-key-2041/versions/1:access")
            payload = {"payload": {"data": base64.b64encode(self.key.encode()).decode()}}
            return self._json(payload)
        path = url.removeprefix(CERTMANAGER + "/")
        if "/operations/" in path:
            self.ops_pending -= 1
            return self._json({"name": path, "done": self.ops_pending <= 0})
        if method == "GET":
            return self._json(self.certs[path]) if path in self.certs else HttpResponse(404, b"{}")
        if method == "POST":
            name = f"{path.removesuffix('/certificates')}/certificates/{params['certificateId']}"
            if name in self.certs:
                return HttpResponse(409, b"{}")
            self.certs[name] = {"name": name, "labels": json["labels"], "selfManaged": {}, "sanDnsnames": []}
        elif method == "PATCH":
            assert params == {"updateMask": "selfManaged,labels"}
            self.certs[path]["labels"] = json["labels"]
        return self._json(
            {"name": "projects/acme-prod/locations/global/operations/op-1", "done": self.ops_pending <= 0}
        )

    @staticmethod
    def _json(obj: Any) -> HttpResponse:
        return HttpResponse(200, json.dumps(obj).encode())

    def writes(self) -> list[str]:
        return [m for m, *_ in self.requests if m in ("POST", "PATCH")]


@pytest.fixture
def m():
    return material()


@pytest.fixture
def google(m) -> FakeGoogle:
    return FakeGoogle(m.fullchain, m.key_pem)


@pytest.fixture
def sleep() -> NoSleep:
    return NoSleep()


def deps_for(google: FakeGoogle) -> Deps:
    return Deps(secrets=RestSecretManager(google), chains=RestStorage(google), cm=RestCertificateManager(google))


def cfg(sleep: NoSleep, **kw: Any) -> Config:
    return Config(project="acme-prod", retry=RetryPolicy(attempts=3, sleep=sleep), sleep=sleep, poll_interval_s=1, **kw)


def pubsub(ev: dict) -> dict:
    data = base64.b64encode(json.dumps(ev).encode()).decode()
    return {"data": data, "messageId": "123", "attributes": {"ce-type": ev["type"], "ce-id": ev["id"]}}


def gcp_event(m, **kw: Any) -> dict:
    return make_event(chain_ref=CHAIN_REF, private_key_ref=KEY_REF, fingerprint=m.fingerprint, **kw)


def test_target_resolution(sleep: NoSleep) -> None:
    c = cfg(sleep, name_pattern="www-*")
    assert resolve_target(parse_event(make_event(tags=["gcp-cm:www-cert"])), c) == NAME
    full = "projects/other/locations/europe-west1/certificates/x1"
    assert resolve_target(parse_event(make_event(tags=[f"gcp-cm:{full}"])), c) == full
    assert resolve_target(parse_event(make_event(tags=[])), c).endswith("/certificates/farrier-www-lb")
    assert resolve_target(parse_event(make_event(tags=[], endpoint_name="db")), c) is None
    with pytest.raises(PermanentError):
        resolve_target(parse_event(make_event(tags=["gcp-cm:Bad_Id"])), c)
    assert certificate_id_for("WWW.Example_LB") == "farrier-www-example-lb"


def test_first_renewal_creates_then_duplicate_skips(google: FakeGoogle, m, sleep: NoSleep) -> None:
    ev = gcp_event(m, tags=["gcp-cm:www-cert"])
    out = handle(pubsub(ev), deps_for(google), cfg(sleep), LOG)
    assert out == {"action": "created", "reason": None, "certificate": NAME}
    method, url, params, body = next(r for r in google.requests if r[0] == "POST")
    assert url == f"{CERTMANAGER}/projects/acme-prod/locations/global/certificates" and params == {
        "certificateId": "www-cert"
    }
    assert body["selfManaged"]["pemCertificate"].count("BEGIN CERTIFICATE") == 2
    assert labelled_fingerprint(body["labels"]) == m.fingerprint
    assert all(len(v) <= 63 for v in body["labels"].values())

    again = handle(pubsub(ev), deps_for(google), cfg(sleep), LOG)
    assert again["reason"] == "already-current"
    assert google.writes() == ["POST"]


def test_existing_certificate_is_patched_and_foreign_labels_kept(google: FakeGoogle, m, sleep: NoSleep) -> None:
    google.certs[NAME] = {"name": NAME, "selfManaged": {}, "labels": {"team": "web", "farrier-renewal-id": "2000"}}
    out = handle(pubsub(gcp_event(m, tags=["gcp-cm:www-cert"])), deps_for(google), cfg(sleep), LOG)
    assert out["action"] == "updated"
    assert google.certs[NAME]["labels"]["team"] == "web"
    assert google.certs[NAME]["labels"]["farrier-renewal-id"] == "2041"


def test_stale_and_google_managed_targets(google: FakeGoogle, m, sleep: NoSleep) -> None:
    google.certs[NAME] = {"name": NAME, "selfManaged": {}, "labels": {"farrier-renewal-id": "9999"}}
    assert (
        handle(pubsub(gcp_event(m, tags=["gcp-cm:www-cert"])), deps_for(google), cfg(sleep), LOG)["reason"]
        == "stale-event"
    )
    google.certs[NAME] = {"name": NAME, "managed": {"domains": ["x"]}, "labels": {}}
    with pytest.raises(PermanentError, match="Google-managed"):
        handle(pubsub(gcp_event(m, tags=["gcp-cm:www-cert"])), deps_for(google), cfg(sleep), LOG)


def test_long_running_operation_is_polled(google: FakeGoogle, m, sleep: NoSleep) -> None:
    google.ops_pending = 3
    assert (
        handle(pubsub(gcp_event(m, tags=["gcp-cm:www-cert"])), deps_for(google), cfg(sleep), LOG)["action"] == "created"
    )
    assert sum(1 for _, url, *_ in google.requests if "/operations/" in url) == 3


def test_operation_that_never_finishes_raises_transient(google: FakeGoogle, m, sleep: NoSleep) -> None:
    google.ops_pending = 100
    with pytest.raises(TransientError, match="did not finish"):
        handle(pubsub(gcp_event(m, tags=["gcp-cm:www-cert"])), deps_for(google), cfg(sleep, operation_polls=2), LOG)


def test_transient_http_errors_are_retried(google: FakeGoogle, m, sleep: NoSleep) -> None:
    google.fail_next = [503, 429]
    assert (
        handle(pubsub(gcp_event(m, tags=["gcp-cm:www-cert"])), deps_for(google), cfg(sleep), LOG)["action"] == "created"
    )
    assert len(sleep.calls) == 2


def test_permanent_http_error_raises(google: FakeGoogle, m, sleep: NoSleep) -> None:
    google.fail_next = [403]
    with pytest.raises(PermanentError, match="HTTP 403"):
        handle(pubsub(gcp_event(m, tags=["gcp-cm:www-cert"])), deps_for(google), cfg(sleep), LOG)


def test_wrong_cloud_refs_are_poison(google: FakeGoogle, m, sleep: NoSleep) -> None:
    ev = make_event(tags=["gcp-cm:www-cert"], fingerprint=m.fingerprint)  # s3:// and aws-sm: refs
    with pytest.raises(PermanentError):
        handle(pubsub(ev), deps_for(google), cfg(sleep), LOG)


def test_no_secrets_in_logs(google: FakeGoogle, m, sleep: NoSleep, capsys) -> None:
    handle(pubsub(gcp_event(m, tags=["gcp-cm:www-cert"])), deps_for(google), cfg(sleep), LOG)
    google.certs.clear()
    google.fail_next = [500] * 10
    with pytest.raises(TransientError):
        handle(pubsub(gcp_event(m, tags=["gcp-cm:www-cert"])), deps_for(google), cfg(sleep), LOG)
    assert_no_secrets(capsys.readouterr().out, m.key_pem, m.leaf_pem)
