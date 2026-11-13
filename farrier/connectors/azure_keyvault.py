"""An Azure Key Vault certificate, for Application Gateway, Front Door, App Service and anything else that
reads it by versionless id, through the Key Vault and Resource Manager REST APIs.

Flow: note the current version -> import the renewed certificate, key and chain as a new version (a PFX with an
exportable key: Application Gateway and Front Door read it through the certificate's secret) -> optionally make
lazy consumers pick it up now instead of hours later.

config:
  vault        https://<vault>.vault.azure.net
  certificate  certificate name in the vault ([0-9A-Za-z-])
  refresh      optional {"application_gateway": <ARM id or list>, "front_door": <ARM id or list>}
                 application_gateway  /subscriptions/../providers/Microsoft.Network/applicationGateways/<name>:
                                      a farrier-refresh tag is written, and any change to a gateway makes it
                                      re-read Key Vault at once (otherwise every 4 hours)
                 front_door           /subscriptions/../providers/Microsoft.Cdn/profiles/<p>/customDomains/<d>:
                                      a Front Door secret pinned to the new version is created and the domain
                                      switched to it (a "Latest" secret takes up to 72 hours). RSA keys only.

Identity: Farrier's Azure identity (see farrier/security/cloud_auth/azure.py). Roles: Key Vault Certificates
Officer on the vault (Key Vault Secrets User too, for rollback); for refresh, Network Contributor on the gateway
and CDN Profile Contributor on the Front Door profile.

Rollback: Key Vault cannot make an older version current again, and disabling the new version does not fall
back: versionless readers then fail (Application Gateway turns the listener off). So rollback reads the previous
version through its secret, which holds the key when the key is exportable, and imports it again as the newest
version. A previous version with a non-exportable key cannot come back; rollback refuses and says so. Front Door
domains are switched back to the secret they used before. If the certificate did not exist before, rollback
disables the version Farrier imported.
"""
from __future__ import annotations

import base64
import re
import secrets
from datetime import UTC, datetime
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12

from farrier.connectors.base import Bundle, Connector, DeployError
from farrier.connectors.keystore import build_pkcs12
from farrier.core.x509util import load_key
from farrier.security.cloud_auth import azure
from farrier.security.cloud_auth import http as cloud_http
from farrier.security.cloud_auth.http import CloudError, json_body, request
from farrier.security.secret_backends.azure import NAME, vault_origin

API = "7.4"
ARM = "https://management.azure.com"    # shortcut: public cloud only, add a config key for sovereign clouds
GATEWAY_API = "2024-05-01"
CDN_API = "2025-04-15"
PKCS12 = "application/x-pkcs12"
IDS = {"application_gateway": r"Microsoft\.Network/applicationGateways/[^/]+",
       "front_door": r"Microsoft\.Cdn/profiles/[^/]+/customDomains/[^/]+"}


def _ids(v) -> list[str]:
    return [v] if isinstance(v, str) else list(v or [])


def _version(cert_id: str) -> str:
    return cert_id.rstrip("/").rsplit("/", 1)[-1]


def _has_key(value: str, content_type: str) -> bool:
    if content_type != PKCS12:
        return "PRIVATE KEY" in value
    try:
        return pkcs12.load_key_and_certificates(base64.b64decode(value), None)[0] is not None
    except ValueError:
        return False


class AzureKeyVaultConnector(Connector):
    kind = "azure_keyvault"
    required = ("vault", "certificate")
    tokens = None   # tests inject a token provider; default: farrier.security.cloud_auth.azure

    def __init__(self, config: dict, data_dir: Path):
        super().__init__(config, data_dir)
        self.vault = vault_origin(str(self.cfg["vault"]), "azure_keyvault vault")
        self.name = str(self.cfg["certificate"])
        if not NAME.match(self.name):
            raise ValueError("azure_keyvault certificate: use 1-127 characters from A-Z a-z 0-9 -")
        self.refresh = self.cfg.get("refresh") or {}
        for k, v in self.refresh.items():
            if k not in IDS:
                raise ValueError(f"azure_keyvault refresh {k!r}: use application_gateway or front_door")
            for i in _ids(v):
                if not re.fullmatch(rf"/subscriptions/[^/]+/resourceGroups/[^/]+/providers/{IDS[k]}", i, re.IGNORECASE):
                    raise ValueError(f"azure_keyvault refresh {k} {i!r} is not that kind of Azure resource id")

    # ---- REST ------------------------------------------------------------------------------------
    def _call(self, method: str, url: str, scope: str, what: str, api: str, **kw):
        tokens = self.tokens or azure.default_provider()
        try:
            return request(method, url, what=what, params={"api-version": api},
                           headers={"Authorization": f"Bearer {tokens.token(scope)}"}, **kw)
        except CloudError as e:
            raise DeployError(str(e)) from None

    def _kv(self, method: str, path: str, what: str, **kw):
        return self._call(method, f"{self.vault}/{path}", azure.VAULT_SCOPE, f"Key Vault {what}", API, **kw)

    def _arm(self, method: str, rid: str, api: str, what: str, **kw) -> dict:
        r = self._call(method, ARM + rid, azure.ARM_SCOPE, what, api, **kw)
        return json_body(r, what) if r.content else {}

    def _current(self) -> str | None:
        r = self._kv("GET", f"certificates/{self.name}", "get certificate", allow=(404,))
        return None if r.status_code == 404 else _version(json_body(r, "Key Vault certificate")["id"])

    def _import(self, value: str, content_type: str, pwd: str | None = None) -> str:
        body = {"value": value, "tags": {"managed-by": "farrier"},
                "policy": {"key_props": {"exportable": True, "reuse_key": False},
                           "secret_props": {"contentType": content_type}, "issuer": {"name": "Unknown"}}}
        if pwd:
            body["pwd"] = pwd
        return _version(json_body(self._kv("POST", f"certificates/{self.name}/import", "import certificate",
                                           json=body), "Key Vault import")["id"])

    # ---- refresh ---------------------------------------------------------------------------------
    def _refresh_gateways(self) -> None:
        stamp = datetime.now(UTC).isoformat(timespec="seconds")
        for gw in _ids(self.refresh.get("application_gateway")):
            tags = self._arm("GET", gw, GATEWAY_API, "get application gateway").get("tags") or {}
            self._arm("PATCH", gw, GATEWAY_API, "tag application gateway", json={"tags": {**tags,
                                                                                           "farrier-refresh": stamp}})

    def _switch_domain(self, domain: str, secret_id: str) -> None:
        tls = self._arm("GET", domain, CDN_API, "get Front Door domain")["properties"].get("tlsSettings") or {}
        self._arm("PATCH", domain, CDN_API, "switch Front Door domain certificate",
                  json={"properties": {"tlsSettings": {**tls, "secret": {"id": secret_id}}}})

    def _pin_front_door(self, version: str) -> dict:
        """{custom domain id: the Front Door secret it used before}, after switching each to the new version."""
        before = {}
        for domain in _ids(self.refresh.get("front_door")):
            tls = self._arm("GET", domain, CDN_API, "get Front Door domain")["properties"].get("tlsSettings") or {}
            old = (tls.get("secret") or {}).get("id")
            if tls.get("certificateType") != "CustomerCertificate" or not old:
                raise DeployError(f"Front Door domain {domain} does not use a customer certificate; attach this "
                                  "Key Vault certificate to it once in Front Door first")
            params = self._arm("GET", old, CDN_API, "get Front Door secret")["properties"]["parameters"]
            source = params["secretSource"]["id"]
            if not source.rstrip("/").lower().endswith(f"/secrets/{self.name.lower()}"):
                raise DeployError(f"Front Door domain {domain} uses Key Vault certificate {source}, not {self.name}")
            # shortcut: one pinned secret per renewal is left in the profile; delete old ones by hand if they pile up
            new = f"{domain.rsplit('/customDomains/', 1)[0]}/secrets/farrier-{self.name[:40]}-{version[:12]}"
            self._arm("PUT", new, CDN_API, "create Front Door secret", json={"properties": {"parameters": {
                "type": "CustomerCertificate", "secretSource": {"id": source}, "secretVersion": version,
                "useLatestVersion": False}}})
            for _ in range(20):
                state = self._arm("GET", new, CDN_API, "get Front Door secret")["properties"].get("provisioningState")
                if state in ("Succeeded", "Failed"):
                    break
                cloud_http.sleep(3)
            if state != "Succeeded":
                raise DeployError(f"Front Door secret {new} is {state}, not Succeeded")
            self._switch_domain(domain, new)
            before[domain] = old
        return before

    # ---- contract --------------------------------------------------------------------------------
    def deploy(self, b: Bundle) -> dict:
        if self.refresh.get("front_door") and not isinstance(load_key(b.key_pem), rsa.RSAPrivateKey):
            raise DeployError("Azure Front Door does not accept elliptic-curve certificates: give this endpoint an "
                              "RSA key, or remove refresh.front_door")
        previous = self._current()
        pwd = secrets.token_urlsafe(24)
        # 3DES PFX: the format every Key Vault and gateway parser reads; the password travels in the same request
        pfx = build_pkcs12(b, b.object_name, pwd, legacy=True)
        version = self._import(base64.b64encode(pfx).decode(), PKCS12, pwd)
        self._refresh_gateways()
        return {"version": version, "previous": previous, "front_door": self._pin_front_door(version)}

    def rollback(self, token: dict) -> None:
        for domain, secret_id in (token.get("front_door") or {}).items():
            self._switch_domain(domain, secret_id)
        current = self._current()
        if current != token["version"]:
            raise DeployError(f"Key Vault certificate {self.name} is now at version {current}, not Farrier's "
                              f"{token['version']}; not rolling back over it")
        prev = token.get("previous")
        if not prev:   # the certificate did not exist before Farrier imported it
            self._kv("PATCH", f"certificates/{self.name}/{current}", "disable version",
                     json={"attributes": {"enabled": False}})
        else:
            s = json_body(self._kv("GET", f"secrets/{self.name}/{prev}", "read previous version"), "Key Vault secret")
            value, content_type = s.get("value") or "", s.get("contentType") or PKCS12
            if not _has_key(value, content_type):
                raise DeployError(f"previous version {prev} of {self.name} has a non-exportable key, so Key Vault "
                                  "cannot return it and it cannot be imported again; roll back by hand")
            self._import(value, content_type)
        self._refresh_gateways()
