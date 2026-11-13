"""End-to-end against Pebble, Let's Encrypt's ACME test server, with its DNS test server for DNS-01.

Runs in CI (the "letsencrypt" job) and locally when FARRIER_TEST_PEBBLE=1 and both are up:

    docker network create --subnet 10.30.50.0/24 acme
    docker run -d --network acme --ip 10.30.50.3 -p 8055:8055 ghcr.io/letsencrypt/pebble-challtestsrv \\
        -defaultIPv6 "" -defaultIPv4 10.30.50.3
    docker run -d --network acme -p 14000:14000 ghcr.io/letsencrypt/pebble \\
        -config test/config/pebble-config.json -dnsserver 10.30.50.3:8053

Pebble rejects a share of nonces on purpose and validates like Let's Encrypt's Boulder, so this
checks the client against real CA behaviour rather than our own mock.
"""
import os

import httpx
import pytest

from farrier.core.x509util import build_csr, generate_key, parse_pem
from farrier.issuers.acme import AcmeIssuer

pytestmark = pytest.mark.skipif(os.environ.get("FARRIER_TEST_PEBBLE") != "1", reason="needs Pebble (CI job)")

DIRECTORY = os.environ.get("FARRIER_PEBBLE_DIRECTORY", "https://localhost:14000/dir")
CHALLTESTSRV = os.environ.get("FARRIER_PEBBLE_DNS", "http://localhost:8055")


def dns_hook(action, name, value):
    host = name.rstrip(".") + "."
    if action == "present":
        httpx.post(f"{CHALLTESTSRV}/set-txt", json={"host": host, "value": value}).raise_for_status()
    else:
        httpx.post(f"{CHALLTESTSRV}/clear-txt", json={"host": host}).raise_for_status()


def issuer(tmp_path, **kw):
    # Pebble serves its API with a throwaway test certificate; only this test skips verification
    return AcmeIssuer(tmp_path, DIRECTORY, email="ci@example.org", dns_hook=dns_hook, propagation_seconds=0,
                      http=httpx.Client(verify=False, timeout=30), poll_interval=0.5, timeout=120, **kw)


def test_issue_and_renew_against_pebble(tmp_path):
    acme = issuer(tmp_path)
    names = ["www.farrier.test", "api.farrier.test"]
    cert, chain = acme.issue(build_csr(generate_key(), names[0], names), names)
    info = parse_pem(cert)
    assert sorted(info.sans) == sorted(names)
    assert "BEGIN CERTIFICATE" in chain

    # ARI: Pebble offers renewalInfo; a renewal names the certificate it replaces
    window = acme.renewal_window(cert)
    assert window is None or (window[0] and window[1])
    again, _ = acme.issue(build_csr(generate_key(), names[0], names), names, replaces_pem=cert)
    assert parse_pem(again).fingerprint != info.fingerprint


def test_profile_when_offered(tmp_path):
    acme = issuer(tmp_path)
    profiles = (acme.directory.get("meta") or {}).get("profiles") or {}
    if not profiles:
        pytest.skip("this Pebble build offers no profiles")
    acme.profile = next(iter(profiles))
    cert, _ = acme.issue(build_csr(generate_key(), "profile.farrier.test", ["profile.farrier.test"]), ["profile.farrier.test"])
    assert parse_pem(cert).sans == ["profile.farrier.test"]


def test_revoke_against_pebble(tmp_path):
    acme = issuer(tmp_path)
    names = ["revoke.farrier.test"]
    cert, _ = acme.issue(build_csr(generate_key(), names[0], names), names)
    acme.revoke(cert, "keyCompromise")
    acme.revoke(cert, "keyCompromise")        # already revoked counts as done
