"""Cloud private CAs as issuers: AWS Private CA and Google Certificate Authority Service.

Both sign Farrier's CSR as is (names come from the CSR's SAN extension) and need no DNS validation: the
cloud IAM policy on the CA is the authorization. Credentials come from the platform chain (IRSA, ECS/EKS
task role, instance profile or keys on AWS; workload identity, metadata server or a key file on Google).

issuers.json:
  {"type": "aws_pca", "ca_arn": "arn:aws:acm-pca:eu-west-1:123456789012:certificate-authority/1234...",
   "template_arn": "arn:aws:acm-pca:::template/EndEntityCertificate/V1", "lifetime_days": 30}
  {"type": "gcp_cas", "ca_pool": "projects/p/locations/europe-west1/caPools/internal",
   "certificate_template": "projects/p/locations/europe-west1/certificateTemplates/tls-server"}
lifetime_days defaults to the public CA/B Forum maximum for today, so private certificates rehearse the
47-day schedule; set it to whatever your PKI policy allows.
"""
from __future__ import annotations

import base64
import re
import time
import uuid
from datetime import UTC, datetime

from farrier.core.policy import max_lifetime_days
from farrier.security.cloud_auth import google
from farrier.security.cloud_auth.aws import json_call
from farrier.security.cloud_auth.http import CloudError, json_body, request

PCA_ARN = re.compile(r"^arn:aws[a-z-]*:acm-pca:([a-z0-9-]+):\d{12}:certificate-authority/[0-9a-f-]+$")
CAS_POOL = re.compile(r"^projects/[^/]+/locations/[^/]+/caPools/[^/]+$")
# DescribeCertificateAuthority KeyAlgorithm -> the signing algorithm IssueCertificate needs
PCA_SIGNING = {"RSA_2048": "SHA256WITHRSA", "RSA_3072": "SHA256WITHRSA", "RSA_4096": "SHA256WITHRSA",
               "EC_prime256v1": "SHA256WITHECDSA", "EC_secp384r1": "SHA384WITHECDSA", "EC_secp521r1": "SHA512WITHECDSA"}


def _days(lifetime_days: int | None) -> int:
    return int(lifetime_days or max_lifetime_days(datetime.now(UTC)))


class AwsPrivateCA:
    """acm-pca IssueCertificate + GetCertificate. A CA shared from another account through RAM works too."""

    automated_dcv = True

    def __init__(self, data_dir=None, ca_arn: str = "", template_arn: str | None = None,
                 signing_algorithm: str | None = None, lifetime_days: int | None = None, creds=None, http=None,
                 poll_interval: float = 1.0, timeout: float = 120):
        m = PCA_ARN.match(ca_arn or "")
        if not m:
            raise ValueError(f'aws_pca issuer: "ca_arn" must be an AWS Private CA ARN, got {ca_arn!r}')
        self.ca_arn, self.region = ca_arn, m.group(1)
        self.template_arn, self.signing_algorithm, self.lifetime_days = template_arn, signing_algorithm, lifetime_days
        self.creds, self.http, self.poll_interval, self.timeout = creds, http, poll_interval, timeout

    def _call(self, action: str, payload: dict, allow=()) -> dict:
        return json_call("acm-pca", action, payload, region=self.region, what=f"AWS Private CA {action}",
                         creds=self.creds, http=self.http, allow=allow)

    def _algorithm(self) -> str:
        if not self.signing_algorithm:
            ca = self._call("DescribeCertificateAuthority", {"CertificateAuthorityArn": self.ca_arn})
            cfg = ca["CertificateAuthority"]["CertificateAuthorityConfiguration"]
            self.signing_algorithm = PCA_SIGNING.get(cfg["KeyAlgorithm"]) or cfg["SigningAlgorithm"]
        return self.signing_algorithm

    def check(self) -> str:
        ca = self._call("DescribeCertificateAuthority", {"CertificateAuthorityArn": self.ca_arn})["CertificateAuthority"]
        if ca.get("Status") != "ACTIVE":
            raise RuntimeError(f"the CA is {ca.get('Status')}, not ACTIVE")
        return f"AWS Private CA {self.ca_arn.rsplit('/', 1)[1]} is ACTIVE ({ca.get('UsageMode') or 'GENERAL_PURPOSE'})"

    def revoke(self, cert_pem: str, reason: str = "unspecified") -> None:
        from cryptography import x509
        h = format(x509.load_pem_x509_certificate(cert_pem.encode()).serial_number, "x")
        h = "0" * (len(h) % 2) + h                                   # whole bytes
        serial = ":".join(h[i:i + 2] for i in range(0, len(h), 2))   # Private CA wants colon-separated hex
        codes = {"keyCompromise": "KEY_COMPROMISE", "cACompromise": "CERTIFICATE_AUTHORITY_COMPROMISE",
                 "affiliationChanged": "AFFILIATION_CHANGED", "superseded": "SUPERSEDED",
                 "cessationOfOperation": "CESSATION_OF_OPERATION"}
        self._call("RevokeCertificate", {"CertificateAuthorityArn": self.ca_arn, "CertificateSerial": serial,
                                         "RevocationReason": codes.get(reason, "UNSPECIFIED")})

    def issue(self, csr_pem: str, names: list[str]) -> tuple[str, str]:
        body = {"CertificateAuthorityArn": self.ca_arn, "Csr": base64.b64encode(csr_pem.encode()).decode(),
                "SigningAlgorithm": self._algorithm(), "IdempotencyToken": uuid.uuid4().hex[:36],
                "Validity": {"Type": "DAYS", "Value": _days(self.lifetime_days)}}
        if self.template_arn:
            body["TemplateArn"] = self.template_arn
        arn = self._call("IssueCertificate", body)["CertificateArn"]
        deadline = time.monotonic() + self.timeout
        while True:   # issuance is asynchronous: RequestInProgressException until it is signed
            try:
                got = self._call("GetCertificate", {"CertificateAuthorityArn": self.ca_arn, "CertificateArn": arn})
                return got["Certificate"].strip() + "\n", (got.get("CertificateChain") or "").strip() + "\n"
            except CloudError as e:
                if e.code != "RequestInProgressException" or time.monotonic() > deadline:
                    raise
            time.sleep(self.poll_interval)


class GoogleCAS:
    """privateca caPools.certificates.create. Enterprise-tier pools keep and can revoke what they issue."""

    automated_dcv = True
    API = "https://privateca.googleapis.com/v1"

    def __init__(self, data_dir=None, ca_pool: str = "", certificate_template: str | None = None,
                 issuing_ca: str | None = None, lifetime_days: int | None = None, tokens=None, http=None):
        if not CAS_POOL.match(ca_pool or ""):
            raise ValueError('gcp_cas issuer: "ca_pool" must look like projects/P/locations/L/caPools/POOL, '
                             f"got {ca_pool!r}")
        self.ca_pool, self.certificate_template, self.issuing_ca = ca_pool, certificate_template, issuing_ca
        self.lifetime_days, self.tokens, self.http = lifetime_days, tokens, http

    def _auth(self) -> dict:
        return {"Authorization": f"Bearer {(self.tokens or google.default_provider()).token(google.CLOUD_PLATFORM)}"}

    def check(self) -> str:
        pool = json_body(request("GET", f"{self.API}/{self.ca_pool}", what="Google CAS caPools.get", http=self.http,
                                 headers=self._auth()), "CA pool")
        return f"CA pool {self.ca_pool.rsplit('/', 1)[1]} reachable ({pool.get('tier', 'tier unknown')})"

    def issue(self, csr_pem: str, names: list[str]) -> tuple[str, str]:
        body = {"pemCsr": csr_pem, "lifetime": f"{_days(self.lifetime_days) * 86400}s"}
        if self.certificate_template:
            body["certificateTemplate"] = self.certificate_template
        params = {"certificateId": f"farrier-{uuid.uuid4().hex[:24]}", "requestId": str(uuid.uuid4())}
        if self.issuing_ca:
            params["issuingCertificateAuthorityId"] = self.issuing_ca
        r = request("POST", f"{self.API}/{self.ca_pool}/certificates", what="Google CAS certificates.create",
                    http=self.http, params=params, json=body, headers=self._auth())
        cert = json_body(r, "Google CAS certificate")
        return cert["pemCertificate"], "".join(cert.get("pemCertificateChain") or [])
