"""Live checks against real CAs and real DNS (the nightly "live" workflow). Each test runs only when its
secrets are set, so forks and local runs skip them:

  FARRIER_LIVE_DOMAIN      a zone you control, e.g. ci.example.com (names under it are issued)
  FARRIER_LIVE_DNS_JSON    a dns.json body whose account can write TXT records in that zone, with
                           env: references to the credentials (they come from the same CI secrets)
  FARRIER_LIVE_ACM_EAB_ARN an AWS ACM managed ACME binding whose endpoint prevalidates FARRIER_LIVE_DOMAIN
                           (AWS credentials from the job's OIDC role)

Let's Encrypt staging is used, so nothing is publicly trusted and production rate limits are untouched.
"""
import os
import uuid

import pytest

from farrier.core.x509util import build_csr, generate_key, parse_pem
from farrier.issuers.acme import AcmeIssuer
from farrier.issuers.aws_acm import AcmAcmeIssuer

DOMAIN = os.environ.get("FARRIER_LIVE_DOMAIN", "")
LE_STAGING = "https://acme-staging-v02.api.letsencrypt.org/directory"


def _names():
    label = f"farrier-{uuid.uuid4().hex[:8]}"
    return [f"{label}.{DOMAIN}"]


@pytest.mark.skipif(not (DOMAIN and os.environ.get("FARRIER_LIVE_DNS_JSON")), reason="live DNS secrets not set")
def test_letsencrypt_staging_dns01(tmp_path):
    (tmp_path / "dns.json").write_text(os.environ["FARRIER_LIVE_DNS_JSON"])
    acme = AcmeIssuer(tmp_path, LE_STAGING, dns="auto", poll_interval=3, timeout=600)
    names = _names()
    cert, chain = acme.issue(build_csr(generate_key(), names[0], names), names)
    info = parse_pem(cert)
    assert info.sans == names and "(STAGING)" in info.issuer
    window = acme.renewal_window(cert)               # Let's Encrypt offers ARI
    assert window and window[0] < window[1]


@pytest.mark.skipif(not (DOMAIN and os.environ.get("FARRIER_LIVE_ACM_EAB_ARN")), reason="live ACM secrets not set")
def test_aws_acm_managed_acme(tmp_path):
    acme = AcmAcmeIssuer(tmp_path, acm_eab_arn=os.environ["FARRIER_LIVE_ACM_EAB_ARN"], poll_interval=3)
    names = _names()
    cert, _ = acme.issue(build_csr(generate_key(), names[0], names), names)
    assert parse_pem(cert).sans == names
