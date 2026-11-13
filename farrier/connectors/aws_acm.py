"""AWS Certificate Manager: the renewed certificate imported into ACM, optionally switched on an ELBv2 listener.

Three modes, by config:
  certificate_arn  re-import into that ARN (ImportCertificate with CertificateArn). Every ALB, NLB, CloudFront
                   distribution and API Gateway domain using it switches at once. NOT reversible: ACM never
                   gives back the previous private key (ExportCertificate covers only private-CA and exportable
                   public certificates, not imported ones), so rollback raises and says so.
  listener_arn     import under a NEW ARN, then point the listener at it: as its default certificate
                   (ModifyListener), or with "listener_mode": "additional" in its SNI list
                   (AddListenerCertificates, and the previous renewal of this endpoint is taken off it).
                   Rollback switches the listener back and deletes the new certificate. The previous
                   certificate is never modified, so rollback is exact.
  neither          import under a new ARN and leave wiring to something else (e.g. the AWS Load Balancer
                   Controller discovering certificates by host name). Rollback deletes it.
Imported certificates carry the tag farrier:endpoint=<endpoint name> plus any configured tags.

config:
  region                      e.g. "eu-west-1" (CloudFront certificates live in us-east-1)
  certificate_arn             optional, see above
  listener_arn                optional, see above (not with certificate_arn)
  listener_mode               "default" (default) | "additional"
  role_arn, external_id       optional: sts:AssumeRole into the account holding the certificate
  tags                        optional {"key": "value"}, on new imports (ACM refuses tags on a re-import)

IAM: acm:ImportCertificate, acm:AddTagsToCertificate, acm:DeleteCertificate, acm:ListTagsForCertificate;
with listener_arn: elasticloadbalancing:DescribeListenerCertificates, ModifyListener,
AddListenerCertificates, RemoveListenerCertificates.
"""
from __future__ import annotations

import base64
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from urllib.parse import urlencode

from farrier.connectors.base import Bundle, Connector, DeployError
from farrier.security.cloud_auth import http as cloud_http
from farrier.security.cloud_auth.aws import (
    REGION,
    ROLE_ARN,
    assume_role,
    json_call,
    signed_request,
)
from farrier.security.cloud_auth.http import CloudError

ARN_REGION = re.compile(r"^arn:aws[a-z-]*:(acm|elasticloadbalancing):([a-z0-9-]+):\d{12}:")
TAG_VALUE = re.compile(r"[^\w .:/=+\-@]")


def _b64(s: str) -> str:
    return base64.b64encode(s.encode()).decode()


def _members(arns: list[str]) -> dict:
    return {f"Certificates.member.{i}.CertificateArn": a for i, a in enumerate(arns, 1)}


class AwsAcmConnector(Connector):
    kind = "aws_acm"
    required = ("region",)

    def __init__(self, config: dict, data_dir: Path):
        super().__init__(config, data_dir)
        c = self.cfg
        if c.get("certificate_arn") and c.get("listener_arn"):
            raise ValueError("aws_acm connector: set certificate_arn (re-import in place) or listener_arn (import "
                             "and switch the listener), not both")
        if c.get("listener_mode", "default") not in ("default", "additional"):
            raise ValueError('aws_acm connector listener_mode: "default" or "additional"')
        if c.get("runner"):
            return   # values may be env:/file: references only the runner resolves
        if not REGION.match(str(c["region"])):
            raise ValueError(f"aws_acm connector region {c['region']!r} is not an AWS region name")
        for k, service in (("certificate_arn", "acm"), ("listener_arn", "elasticloadbalancing")):
            m = ARN_REGION.match(str(c.get(k) or ""))
            if c.get(k) and not (m and m.group(1) == service and m.group(2) == c["region"]):
                raise ValueError(f"aws_acm connector {k} must be an {service} ARN in region {c['region']}")
        if c.get("role_arn") and not ROLE_ARN.match(str(c["role_arn"])):
            raise ValueError("aws_acm connector role_arn must be an IAM role ARN (arn:aws:iam::<account>:role/<name>)")
        if not isinstance(c.get("tags") or {}, dict):
            raise ValueError('aws_acm connector tags: an object, e.g. {"team": "web"}')

    # ---- AWS calls --------------------------------------------------------------------------------------
    def _creds(self):
        return assume_role(self.cfg["role_arn"], self.cfg.get("external_id")) if self.cfg.get("role_arn") else None

    def _acm(self, action: str, payload: dict) -> dict:
        return json_call("acm", action, payload, region=self.cfg["region"], what=f"ACM {action}", creds=self._creds())

    def _elb(self, action: str, params: dict) -> ET.Element:
        """An ELBv2 Query API call (form in, XML out). Errors keep the AWS error code."""
        what = f"ELBv2 {action}"
        r = signed_request("POST", f"https://elasticloadbalancing.{self.cfg['region']}.amazonaws.com/",
                           service="elasticloadbalancing", region=self.cfg["region"], what=what, creds=self._creds(),
                           body=urlencode({"Action": action, "Version": "2015-12-01", **params}).encode(),
                           headers={"Content-Type": "application/x-www-form-urlencoded; charset=utf-8"}, allow=(400,))
        root = ET.fromstring(r.content)
        if r.status_code == 400:
            code, msg = root.findtext(".//{*}Error/{*}Code"), root.findtext(".//{*}Error/{*}Message") or ""
            raise CloudError(f"{what}: HTTP 400 {code}: {' '.join(msg.split())[:200]}", 400, code)
        return root

    @staticmethod
    def _retry(fn, code: str, tries: int = 6, wait: float = 5):
        """ACM and ELB are eventually consistent: a just-imported certificate can be CertificateNotFound to ELB,
        and a just-detached one ResourceInUse to ACM, for a few seconds."""
        for i in range(tries):
            try:
                return fn()
            except CloudError as e:
                if e.code != code or i == tries - 1:
                    raise
                cloud_http.sleep(wait)

    def _listener_certs(self, listener: str) -> list[tuple[str, bool]]:
        out, marker = [], None
        while True:
            root = self._elb("DescribeListenerCertificates", {"ListenerArn": listener, **({"Marker": marker} if marker
                                                                                          else {})})
            out += [(m.findtext("{*}CertificateArn"), m.findtext("{*}IsDefault") == "true")
                    for m in root.iterfind(".//{*}Certificates/{*}member")]
            marker = root.findtext(".//{*}NextMarker")
            if not marker:
                return out

    def _endpoint_tag(self, arn: str) -> str | None:
        tags = self._acm("ListTagsForCertificate", {"CertificateArn": arn}).get("Tags") or []
        return next((t.get("Value") for t in tags if t.get("Key") == "farrier:endpoint"), None)

    def _delete(self, arn: str) -> None:
        try:
            self._retry(lambda: self._acm("DeleteCertificate", {"CertificateArn": arn}), "ResourceInUseException")
        except CloudError as e:
            if e.code != "ResourceInUseException":
                raise
            # still attached somewhere after the retries: an unused certificate is left, not an outage

    # ---- deploy / rollback ------------------------------------------------------------------------------
    def deploy(self, b: Bundle) -> dict:
        blobs = {"Certificate": _b64(b.cert_pem), "PrivateKey": _b64(b.key_pem)}
        if b.chain_pem.strip():
            blobs["CertificateChain"] = _b64(b.chain_pem)
        if self.cfg.get("certificate_arn"):
            self._acm("ImportCertificate", {**blobs, "CertificateArn": self.cfg["certificate_arn"]})
            return {"reimported": self.cfg["certificate_arn"]}
        name = TAG_VALUE.sub("_", b.name)[:256]
        tags = {"farrier:endpoint": name, **{str(k): str(v) for k, v in (self.cfg.get("tags") or {}).items()}}
        listener = self.cfg.get("listener_arn")
        additional = self.cfg.get("listener_mode") == "additional"
        if listener:   # read the listener first: a refusal here leaves nothing behind
            certs = self._listener_certs(listener)
            defaults = {a for a, d in certs if d}
            old = sorted({a for a, d in certs if not d and a not in defaults and ":acm:" in a
                          and self._endpoint_tag(a) == name}) if additional else []
        new = self._acm("ImportCertificate", {**blobs, "Tags": [{"Key": k, "Value": v} for k, v in tags.items()]}
                        )["CertificateArn"]
        token = {"certificate_arn": new}
        if not listener:
            return token
        action = "AddListenerCertificates" if additional else "ModifyListener"
        try:
            self._retry(lambda: self._elb(action, {"ListenerArn": listener, **_members([new])}), "CertificateNotFound")
        except Exception:
            self._delete(new)   # nothing points at it yet
            raise
        token["listener_arn"] = listener
        if additional:
            if old:   # earlier renewals of this endpoint: SNI could keep choosing them
                self._elb("RemoveListenerCertificates", {"ListenerArn": listener, **_members(old)})
            token["removed"] = old
        else:
            token["previous_default"] = next(iter(defaults), None)
        return token

    def rollback(self, token: dict) -> None:
        if token.get("reimported"):
            raise DeployError(
                f"aws_acm: {token['reimported']} was re-imported in place and cannot be rolled back: ACM never "
                "returns the private key of an imported certificate, so Farrier cannot re-import the previous one. "
                "Re-import it from your own copy (aws acm import-certificate --certificate-arn ...), or configure "
                "listener_arn instead so each renewal gets a new ARN and rollback can switch back.")
        new, listener = token["certificate_arn"], token.get("listener_arn")
        if listener and "removed" in token:
            if token["removed"]:
                self._elb("AddListenerCertificates", {"ListenerArn": listener, **_members(token["removed"])})
            self._elb("RemoveListenerCertificates", {"ListenerArn": listener, **_members([new])})
        elif listener:
            if not token.get("previous_default"):
                raise DeployError(f"aws_acm: listener {listener} had no default certificate before; nothing to "
                                  "switch back to")
            self._elb("ModifyListener", {"ListenerArn": listener, **_members([token["previous_default"]])})
        self._delete(new)
