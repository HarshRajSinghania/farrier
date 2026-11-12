"""Azure DNS (public zones) via ARM REST with a client-credentials (service principal) OAuth token.

credentials: tenant_id, client_id, client_secret
options:     subscription_id (required), resource_group (optional: discovered across the whole subscription
             when omitted), authority (default https://login.microsoftonline.com),
             management (default https://management.azure.com; set both for sovereign clouds)
One account per subscription; several subscriptions = several accounts.
"""
from __future__ import annotations

import time

from ...cloud_auth.azure import AUTHORITY, client_credentials_form, token_expiry, token_url
from ..base import DnsConfigError, DnsError, RRsetProvider, Zone, norm, relative

API_VERSION = "2018-05-01"


class Azure(RRsetProvider):
    name = "azure"
    required = ("tenant_id", "client_id", "client_secret")
    options_known = ("subscription_id", "resource_group", "authority", "management")
    _token: tuple[str, float] | None = None

    @property
    def mgmt(self) -> str:
        return self.opts.get("management", "https://management.azure.com").rstrip("/")

    def _bearer(self) -> str:
        if self._token and self._token[1] > time.time() + 120:
            return self._token[0]
        authority = self.opts.get("authority", AUTHORITY)
        r = self.request("POST", token_url(authority, self.secret("tenant_id")), data=client_credentials_form(
            self.secret("client_id"), self.secret("client_secret"), f"{self.mgmt}/.default"))
        j = r.json()
        self._redact.add(j["access_token"])
        self._token = (j["access_token"], token_expiry(j))
        return self._token[0]

    def _sub(self) -> str:
        sub = self.opts.get("subscription_id")
        if not sub:
            raise DnsConfigError(f"dns account {self.account!r}: options.subscription_id is required for azure")
        return sub

    def _call(self, method, url, **kw):
        kw.setdefault("params", {})["api-version"] = API_VERSION
        return self.request(method, url, headers={"Authorization": f"Bearer {self._bearer()}"}, **kw)

    def list_zones(self) -> list[Zone]:
        rg = self.opts.get("resource_group")
        url = (f"{self.mgmt}/subscriptions/{self._sub()}/resourceGroups/{rg}/providers/Microsoft.Network/dnszones"
               if rg else f"{self.mgmt}/subscriptions/{self._sub()}/providers/Microsoft.Network/dnszones")
        j = self._call("GET", url).json()
        zones = [Zone(norm(z["name"]), z["id"]) for z in j.get("value", [])]
        url = j.get("nextLink")
        while url:  # nextLink already carries api-version and the skip token
            j = self.request("GET", url, headers={"Authorization": f"Bearer {self._bearer()}"}).json()
            zones += [Zone(norm(z["name"]), z["id"]) for z in j.get("value", [])]
            url = j.get("nextLink")
        return zones

    def zone_id(self, name: str) -> str:
        rg = self.opts.get("resource_group")
        if rg:
            return f"/subscriptions/{self._sub()}/resourceGroups/{rg}/providers/Microsoft.Network/dnszones/{norm(name)}"
        return self._zone_id_from_list(name)

    def _url(self, zone: Zone, fqdn: str) -> str:
        if not zone.id or "/dnszones/" not in zone.id.lower():
            raise DnsError(f"{self.label}: no Azure resource id for zone {zone.name}")
        return f"{self.mgmt}{zone.id}/TXT/{relative(fqdn, zone.name) or '@'}"

    def _get(self, zone, fqdn):
        r = self._call("GET", self._url(zone, fqdn), allow=(404,))
        if r.status_code == 404:
            return []
        self._etags[fqdn] = r.headers.get("ETag")
        return ["".join(rec.get("value", [])) for rec in r.json().get("properties", {}).get("TXTRecords", [])]

    def _cond(self, fqdn) -> dict:
        etag = self._etags.pop(fqdn, None)
        return {"If-Match": etag} if etag else {"If-None-Match": "*"}

    def _put(self, zone, fqdn, values, current):
        body = {"properties": {"TTL": self.ttl, "TXTRecords": [{"value": [v]} for v in values]}}
        headers = {"Authorization": f"Bearer {self._bearer()}", **self._cond(fqdn)}
        self.request("PUT", self._url(zone, fqdn), params={"api-version": API_VERSION}, json=body, headers=headers)

    def _remove(self, zone, fqdn, current):
        etag = self._etags.pop(fqdn, None)
        headers = {"Authorization": f"Bearer {self._bearer()}", **({"If-Match": etag} if etag else {})}
        self.request("DELETE", self._url(zone, fqdn), params={"api-version": API_VERSION}, headers=headers,
                     allow=(404,))
