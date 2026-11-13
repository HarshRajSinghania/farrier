"""Google Cloud load balancers: a self-managed Certificate Manager certificate, and/or classic Compute Engine SSL
certificates on global target HTTPS proxies, through the REST APIs.

Certificate Manager: the certificate is created on the first renewal and patched in place (selfManaged) after
that, so certificate maps and proxies that reference it serve the new material without a change.

Classic (target_https_proxies): a new global sslCertificates object per renewal, then setSslCertificates on each
proxy. Older objects are left in place, which keeps rollback possible.

config:
  project              Google Cloud project id
  certificate          Certificate Manager certificate id, e.g. "app-example-com"
  location             Certificate Manager location; default "global"
  target_https_proxies list of global target HTTPS proxy names (classic load balancers)
At least one of certificate and target_https_proxies.

Identity: Farrier's Google identity (see farrier/security/cloud_auth/google.py). Roles: Certificate Manager
Editor (roles/certificatemanager.editor); for proxies, Compute Load Balancer Admin (roles/compute.loadBalancerAdmin).

Rollback: proxies are switched back to the certificates they had. A patched Certificate Manager certificate
cannot be rolled back: the API never returns a private key, so the previous key and certificate are gone; rollback
refuses and says so. A certificate Farrier created (none existed before) is deleted.
"""
from __future__ import annotations

import re
from pathlib import Path

from farrier.connectors.base import Bundle, Connector, DeployError
from farrier.security.cloud_auth import google
from farrier.security.cloud_auth import http as cloud_http
from farrier.security.cloud_auth.http import CloudError, json_body, request

CM = "https://certificatemanager.googleapis.com/v1"
COMPUTE = "https://compute.googleapis.com/compute/v1"
RESOURCE = re.compile(r"^[a-z]([-a-z0-9]{0,61}[a-z0-9])?$")


class GcpCertificateManagerConnector(Connector):
    kind = "gcp_certificate_manager"
    required = ("project",)
    tokens = None   # tests inject a token provider; default: farrier.security.cloud_auth.google

    def __init__(self, config: dict, data_dir: Path):
        super().__init__(config, data_dir)
        self.proxies = list(self.cfg.get("target_https_proxies") or [])
        if not self.cfg.get("certificate") and not self.proxies:
            raise ValueError("gcp_certificate_manager connector needs certificate, target_https_proxies or both")
        for v in [self.cfg["project"], self.cfg.get("location", "global"), *self.proxies,
                  *([self.cfg["certificate"]] if self.cfg.get("certificate") else [])]:
            if not re.fullmatch(r"[a-z0-9][-a-z0-9]{0,62}", str(v)):
                raise ValueError(f"gcp_certificate_manager: {v!r} is not a valid Google Cloud resource name")
        self.cert = (f"projects/{self.cfg['project']}/locations/{self.cfg.get('location', 'global')}/certificates/"
                     f"{self.cfg['certificate']}") if self.cfg.get("certificate") else None
        self.compute = f"{COMPUTE}/projects/{self.cfg['project']}/global"

    def _call(self, method: str, url: str, what: str, **kw) -> dict:
        tokens = self.tokens or google.default_provider()
        try:
            r = request(method, url, what=what, headers={"Authorization": f"Bearer {tokens.token()}"}, **kw)
        except CloudError as e:
            raise DeployError(str(e)) from None
        return {"_status": r.status_code} if r.status_code == 404 else json_body(r, what)

    def _cm_wait(self, op: dict, what: str) -> None:
        for _ in range(60):
            if op.get("done"):
                if op.get("error"):
                    raise DeployError(f"{what}: {op['error'].get('message') or op['error']}")
                return
            cloud_http.sleep(2)
            op = self._call("GET", f"{CM}/{op['name']}", what)
        raise DeployError(f"{what}: still running after 2 minutes")

    def _compute_wait(self, op: dict, what: str) -> None:
        for _ in range(5):   # each wait call blocks up to 2 minutes on Google's side
            if op.get("status") == "DONE":
                if op.get("error"):
                    raise DeployError(f"{what}: {op['error'].get('errors') or op['error']}")
                return
            op = self._call("POST", f"{self.compute}/operations/{op['name']}/wait", what)
        raise DeployError(f"{what}: still running after 10 minutes")

    def _set_proxy(self, proxy: str, certs: list[str]) -> None:
        self._compute_wait(self._call("POST", f"{self.compute}/targetHttpsProxies/{proxy}/setSslCertificates",
                                      f"set certificates on {proxy}", json={"sslCertificates": certs}),
                           f"set certificates on {proxy}")

    def deploy(self, b: Bundle) -> dict:
        token: dict = {}
        if self.cert:
            existing = self._call("GET", f"{CM}/{self.cert}", "get certificate", allow=(404,))
            created = existing.get("_status") == 404
            if not created and "selfManaged" not in existing:
                raise DeployError(f"{self.cert} is a Google-managed certificate; it cannot take uploaded material")
            material = {"selfManaged": {"pemCertificate": b.fullchain_pem, "pemPrivateKey": b.key_pem}}
            if created:
                parent, _, cid = self.cert.rpartition("/certificates/")
                op = self._call("POST", f"{CM}/{parent}/certificates", "create certificate",
                                params={"certificateId": cid}, json={**material, "labels": {"managed-by": "farrier"}})
            else:
                op = self._call("PATCH", f"{CM}/{self.cert}", "update certificate",
                                params={"updateMask": "selfManaged"}, json=material)
            self._cm_wait(op, f"Certificate Manager {self.cert}")
            token["created"] = created
        if self.proxies:
            name = b.short_name(63).lower().replace("_", "-").replace(".", "-")
            if not RESOURCE.match(name):
                raise DeployError(f"cannot make a Compute resource name from {b.object_name!r}")
            op = self._call("POST", f"{self.compute}/sslCertificates", "create SSL certificate",
                            allow=(409,), json={"name": name, "certificate": b.fullchain_pem,
                                                "privateKey": b.key_pem, "description": "Managed by Farrier"})
            if "name" in op:   # 409: a retried deploy already created it
                self._compute_wait(op, f"create SSL certificate {name}")
            token["proxies"] = {}
            for proxy in self.proxies:
                token["proxies"][proxy] = self._call("GET", f"{self.compute}/targetHttpsProxies/{proxy}",
                                                     f"get proxy {proxy}").get("sslCertificates") or []
                self._set_proxy(proxy, [f"{self.compute}/sslCertificates/{name}"])
        return token

    def rollback(self, token: dict) -> None:
        for proxy, certs in (token.get("proxies") or {}).items():
            if certs:
                self._set_proxy(proxy, certs)
        if "created" not in token:
            return
        if not token["created"]:
            raise DeployError(f"{self.cert} was updated in place and Certificate Manager never returns a private key, "
                              "so the previous certificate cannot be restored; deploy a known-good certificate instead")
        self._cm_wait(self._call("DELETE", f"{CM}/{self.cert}", "delete certificate"),
                      f"delete Certificate Manager {self.cert}")
