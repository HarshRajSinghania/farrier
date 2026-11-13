"""AWS Certificate Manager managed ACME: the control plane (endpoints, domain prevalidation, External Account
Bindings) over the ACM JSON API, and the issuer that orders certificates from such an endpoint.

ACM endpoints authorize names by prevalidation (one CNAME per domain, created by ACM itself when the domain
sits in a Route 53 hosted zone), so orders arrive already authorized: no DNS-01 at issuance time.

Two issuer forms (issuers.json):
  {"preset": "aws-acm", "acm_eab_arn": "arn:aws:acm:eu-west-1:123456789012:acme-endpoint/E/acme-external-account-binding/B"}
      the directory URL and the EAB key are read from ACM with the AWS credential chain (IRSA, ECS/EKS task
      role, EC2 instance profile, or keys): nothing secret is stored
  {"preset": "aws-acm", "directory_url": "https://acm-acme-enroll.<region>.api.aws/<id>/directory",
   "eab_kid": "env:ACM_EAB_KID", "eab_hmac_key": "env:ACM_EAB_HMAC"}
      the portable form, for an engine running outside AWS (GKE, AKS, on premises)
"""
from __future__ import annotations

import re
import time
import uuid
from pathlib import Path

from farrier.issuers.acme import AcmeIssuer
from farrier.security.cloud_auth.aws import json_call

ARN = re.compile(r"^arn:aws[a-z-]*:acm:([a-z0-9-]+):\d{12}:acme-endpoint/[A-Za-z0-9-]+")
EAB_ARN = re.compile(ARN.pattern + r"/acme-external-account-binding/[A-Za-z0-9-]+$")
KEY_ALGORITHMS = {"ec256": "EC_prime256v1", "ec384": "EC_secp384r1", "rsa2048": "RSA_2048"}


def region_of(arn: str) -> str:
    m = ARN.match(arn or "")
    if not m:
        raise ValueError(f"not an ACM ACME ARN: {arn!r}")
    return m.group(1)


def endpoint_of(arn: str) -> str:
    """The endpoint ARN of an endpoint, domain validation or EAB ARN."""
    region_of(arn)
    return ARN.match(arn).group(0)


class Acm:
    """ACM's ACME control plane in one region. Every method is one documented API action."""

    def __init__(self, region: str, creds=None, http=None, endpoint: str | None = None):
        self.region, self.creds, self.http, self.endpoint = region, creds, http, endpoint

    def call(self, action: str, payload: dict) -> dict:
        return json_call("acm", action, payload, region=self.region, what=f"ACM {action}", endpoint=self.endpoint,
                         creds=self.creds, http=self.http)

    def pages(self, action: str, key: str, payload: dict | None = None) -> list[dict]:
        out, token = [], None
        while True:
            r = self.call(action, {**(payload or {}), "MaxResults": 100, **({"NextToken": token} if token else {})})
            out += r.get(key) or []
            token = r.get("NextToken")
            if not token:
                return out

    # ---- endpoints -------------------------------------------------------------------------------------
    def create_endpoint(self, key_types=("ec256",), contact_required: bool = False, tags: dict | None = None) -> str:
        algs = [KEY_ALGORITHMS[k] for k in key_types]  # KeyError names an unsupported type; the CLI checks first
        body = {"AuthorizationBehavior": "PRE_APPROVED", "IdempotencyToken": uuid.uuid4().hex,
                "CertificateAuthority": {"PublicCertificateAuthority": {"AllowedKeyAlgorithms": algs}},
                "Contact": "REQUIRED" if contact_required else "NOT_REQUIRED"}
        if tags:
            body["Tags"] = [{"Key": k, "Value": v} for k, v in tags.items()]
        return self.call("CreateAcmeEndpoint", body)["AcmeEndpointArn"]

    def describe_endpoint(self, arn: str) -> dict:
        return self.call("DescribeAcmeEndpoint", {"AcmeEndpointArn": arn})["AcmeEndpoint"]

    def list_endpoints(self) -> list[dict]:
        return self.pages("ListAcmeEndpoints", "AcmeEndpoints")

    def delete_endpoint(self, arn: str) -> None:
        self.call("DeleteAcmeEndpoint", {"AcmeEndpointArn": arn})

    def directory_url(self, endpoint_arn: str) -> str:
        e = self.describe_endpoint(endpoint_arn)
        if e.get("Status") != "ACTIVE" or not e.get("EndpointUrl"):
            raise RuntimeError(f"ACM ACME endpoint {endpoint_arn} is {e.get('Status')}"
                               + (f": {e['FailureReason']}" if e.get("FailureReason") else ""))
        return e["EndpointUrl"]

    # ---- domain prevalidation --------------------------------------------------------------------------
    def add_domain(self, endpoint_arn: str, domain: str, hosted_zone_id: str | None = None,
                   subdomains: bool = True, wildcards: bool = False) -> str:
        """With a Route 53 hosted zone ACM writes the CNAME itself; otherwise describe_domain shows it."""
        on = {True: "ENABLED", False: "DISABLED"}
        dns = {"DomainScope": {"ExactDomain": "ENABLED", "Subdomains": on[subdomains], "Wildcards": on[wildcards]}}
        if hosted_zone_id:
            dns["HostedZoneId"] = hosted_zone_id
        return self.call("CreateAcmeDomainValidation", {
            "AcmeEndpointArn": endpoint_arn, "DomainName": domain.lower().rstrip("."),
            "PrevalidationOptions": {"DnsPrevalidation": dns}, "IdempotencyToken": uuid.uuid4().hex,
        })["AcmeDomainValidationArn"]

    def describe_domain(self, arn: str) -> dict:
        return self.call("DescribeAcmeDomainValidation", {"AcmeDomainValidationArn": arn})["AcmeDomainValidation"]

    def list_domains(self, endpoint_arn: str) -> list[dict]:
        return self.pages("ListAcmeDomainValidations", "AcmeDomainValidations", {"AcmeEndpointArn": endpoint_arn})

    def delete_domain(self, arn: str) -> None:
        self.call("DeleteAcmeDomainValidation", {"AcmeDomainValidationArn": arn})

    # ---- External Account Bindings ---------------------------------------------------------------------
    def create_eab(self, endpoint_arn: str, role_arn: str, expires_days: int | None = None) -> dict:
        body = {"AcmeEndpointArn": endpoint_arn, "RoleArn": role_arn, "IdempotencyToken": uuid.uuid4().hex}
        if expires_days:
            body["Expiration"] = {"Type": "DAYS", "Value": int(expires_days)}
        return self.call("CreateAcmeExternalAccountBinding", body)["ExternalAccountBinding"]

    def eab_credentials(self, eab_arn: str) -> tuple[str, str]:
        r = self.call("GetAcmeExternalAccountBindingCredentials", {"AcmeExternalAccountBindingArn": eab_arn})
        return r["KeyId"], r["MacKey"]

    def list_eabs(self, endpoint_arn: str) -> list[dict]:
        return self.pages("ListAcmeExternalAccountBindings", "ExternalAccountBindings",
                          {"AcmeEndpointArn": endpoint_arn})

    def revoke_eab(self, eab_arn: str) -> None:
        self.call("RevokeAcmeExternalAccountBinding", {"AcmeExternalAccountBindingArn": eab_arn})

    def delete_eab(self, eab_arn: str) -> None:
        self.call("DeleteAcmeExternalAccountBinding", {"AcmeExternalAccountBindingArn": eab_arn})


def wait_until(fetch, done=("VALID", "ACTIVE"), failed=("INVALID", "FAILED"), timeout: float = 600,
               interval: float = 10) -> dict:
    """Poll ``fetch()`` until its Status is done (returned) or failed/timeout (RuntimeError)."""
    deadline = time.monotonic() + timeout
    while True:
        obj = fetch()
        if obj.get("Status") in done:
            return obj
        if obj.get("Status") in failed:
            why = obj.get("FailureDetails") or obj.get("FailureReason") or ""
            raise RuntimeError(f"{obj.get('Status')}: {why}")
        if time.monotonic() > deadline:
            raise RuntimeError(f"still {obj.get('Status')} after {timeout:.0f}s")
        time.sleep(interval)


class AcmAcmeIssuer(AcmeIssuer):
    """An ACME issuer for an ACM managed endpoint. Names must be prevalidated on the endpoint."""

    prevalidated = True

    def __init__(self, data_dir: Path, acm_eab_arn: str | None = None, directory_url: str | None = None,
                 acm: Acm | None = None, **kw):
        if acm_eab_arn:
            if not EAB_ARN.match(acm_eab_arn):
                raise ValueError(f"acm_eab_arn {acm_eab_arn!r} is not an ACM external account binding ARN")
            self.acm_eab_arn = acm_eab_arn
            self.acm = acm or Acm(region_of(acm_eab_arn))
            # the endpoint ARN stands in until the first directory fetch; it also names the account key
            directory_url = directory_url or endpoint_of(acm_eab_arn)
        elif not (directory_url and kw.get("eab_kid") and kw.get("eab_hmac_key")):
            raise ValueError('aws-acm issuer: set "acm_eab_arn", or "directory_url" with "eab_kid" and "eab_hmac_key"')
        else:
            self.acm_eab_arn, self.acm = None, None
        kw.setdefault("timeout", 600)  # ACM may take up to two minutes to issue
        super().__init__(data_dir, directory_url=directory_url, **kw)

    @property
    def directory(self) -> dict:
        if self.directory_url.startswith("arn:"):
            self.directory_url = self.acm.directory_url(self.directory_url)
        return super().directory

    def ensure_account(self):
        if not self.kid and self.acm_eab_arn and not self.eab_kid:
            self.eab_kid, self.eab_hmac_key = self.acm.eab_credentials(self.acm_eab_arn)
        super().ensure_account()
