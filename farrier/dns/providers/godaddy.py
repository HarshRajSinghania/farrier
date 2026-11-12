"""GoDaddy Domains API v1. credentials: api_key, api_secret.  options: ote (default false, test environment).
GoDaddy restricts DNS API access to accounts meeting its eligibility rules (e.g. 10+ domains); a 403
ACCESS_DENIED from GoDaddy means the account is not eligible, not that Farrier is misconfigured."""
from __future__ import annotations

from farrier.dns.base import RRsetProvider, Zone, norm, relative


class GoDaddy(RRsetProvider):
    name = "godaddy"
    required = ("api_key", "api_secret")
    options_known = ("ote",)
    default_ttl = 600  # GoDaddy minimum

    @property
    def base(self):
        return "https://api.ote-godaddy.com/v1" if self.opts.get("ote") else "https://api.godaddy.com/v1"

    def _h(self):
        return {"Authorization": f"sso-key {self.secret('api_key')}:{self.secret('api_secret')}"}

    def list_zones(self) -> list[Zone]:
        j = self.request("GET", f"{self.base}/domains", headers=self._h(), params={"statuses": "ACTIVE", "limit": 1000}).json()
        return [Zone(norm(d["domain"]), norm(d["domain"])) for d in j]

    def _url(self, zone, fqdn):
        return f"{self.base}/domains/{zone.name}/records/TXT/{relative(fqdn, zone.name) or '@'}"

    def _get(self, zone, fqdn):
        r = self.request("GET", self._url(zone, fqdn), headers=self._h(), allow=(404,))
        return [] if r.status_code == 404 else [rec["data"] for rec in r.json()]

    def _put(self, zone, fqdn, values, current):
        self.request("PUT", self._url(zone, fqdn), headers=self._h(),
                     json=[{"data": v, "ttl": max(self.ttl, 600)} for v in values])

    def _remove(self, zone, fqdn, current):
        self.request("DELETE", self._url(zone, fqdn), headers=self._h(), allow=(404,))
