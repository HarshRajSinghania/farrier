"""DuckDNS. One TXT value per duckdns subdomain (shared by every name under it), so a certificate for
x.duckdns.org AND *.x.duckdns.org cannot be validated in one order. That case fails with a clear error
instead of silently overwriting the first value (which would make the CA reject one authorization).
credentials: token."""
from __future__ import annotations

from farrier.dns.base import DnsError, Provider, norm

API = "https://www.duckdns.org/update"


class DuckDNS(Provider):
    name = "duckdns"
    required = ("token",)

    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self._live: dict[str, str] = {}

    def _sub(self, fqdn: str) -> str:
        name = norm(fqdn)
        if not name.endswith(".duckdns.org"):
            raise DnsError(f"{self.label}: {fqdn} is not a duckdns.org name")
        return name[: -len(".duckdns.org")].split(".")[-1]

    def _update(self, sub: str, txt: str, clear: bool):
        params = {"domains": sub, "token": self.secret("token"), "txt": txt, "verbose": "true"}
        if clear:
            params["clear"] = "true"
        r = self.request("GET", API, params=params)
        if not r.text.startswith("OK"):
            raise DnsError(f"{self.label}: update refused (KO)")

    def present(self, fqdn, value):
        sub = self._sub(fqdn)
        with self.lock(sub):
            if self._live.get(sub) not in (None, value):
                raise DnsError(f"{self.label}: DuckDNS holds one TXT value per subdomain; {sub}.duckdns.org already "
                               "carries another challenge (wildcard + apex cannot be validated in one order)")
            self._update(sub, value, False)
            self._live[sub] = value

    def cleanup(self, fqdn, value):
        sub = self._sub(fqdn)
        with self.lock(sub):
            if self._live.get(sub) == value:
                self._update(sub, "", True)
                self._live.pop(sub, None)
