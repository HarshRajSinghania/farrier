"""DNS Made Easy (REST API V2.0). Each request carries x-dnsme-hmac = HMAC-SHA1(secret, x-dnsme-requestDate).
credentials: api_key, secret_key        options: sandbox (default false)"""
from __future__ import annotations

import hashlib
import hmac
from email.utils import formatdate

from farrier.dns.base import RecordProvider, norm, quote_txt, relative, unquote_txt


class DnsMadeEasy(RecordProvider):
    name = "dnsmadeeasy"
    required = ("api_key", "secret_key")
    options_known = ("sandbox",)

    @property
    def base(self):
        host = "api.sandbox.dnsmadeeasy.com" if self.opts.get("sandbox") else "api.dnsmadeeasy.com"
        return f"https://{host}/V2.0"

    def _h(self):
        date = formatdate(usegmt=True)
        mac = hmac.new(self.secret("secret_key").encode(), date.encode(), hashlib.sha1).hexdigest()
        return {"x-dnsme-apiKey": self.secret("api_key"), "x-dnsme-requestDate": date, "x-dnsme-hmac": mac}

    def zone_id(self, name):
        j = self.request("GET", f"{self.base}/dns/managed/name", headers=self._h(), params={"domainname": norm(name)}).json()
        return str(j["id"])

    def _records(self, zone, fqdn):
        rel = relative(fqdn, zone.name)
        j = self.request("GET", f"{self.base}/dns/managed/{zone.id}/records", headers=self._h(),
                         params={"type": "TXT", "recordName": rel}).json()
        return [(str(r["id"]), unquote_txt(r["value"])) for r in j.get("data", []) if r.get("name") == rel]

    def _create(self, zone, fqdn, value):
        self.request("POST", f"{self.base}/dns/managed/{zone.id}/records", headers=self._h(), json={
            "type": "TXT", "name": relative(fqdn, zone.name), "value": quote_txt(value), "ttl": self.ttl, "gtdLocation": "DEFAULT"})

    def _delete(self, zone, fqdn, record_id):
        self.request("DELETE", f"{self.base}/dns/managed/{zone.id}/records/{record_id}", headers=self._h(), allow=(404,))
