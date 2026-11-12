"""ACME-DNS (github.com/joohoi/acme-dns): `_acme-challenge.example.com` is a CNAME to
`<subdomain>.auth.example.org`, and the TXT value is pushed to the acme-dns server's /update endpoint.

credentials, either one registration:   username, password, subdomain
            or many (one per domain):  registrations = file:/etc/farrier/acmedns.json
                                       {"example.com": {"username": .., "password": .., "subdomain": .., "fulldomain": ..}}
options:    api_url (e.g. https://auth.acme-dns.io)

acme-dns keeps the two most recent TXT values per subdomain, which is exactly what example.com +
*.example.com need. It has no delete API: cleanup is a no-op (the values age out on the next update).
The account's `zones` are the *client* domains it serves; the router hands it the original challenge name.
"""
from __future__ import annotations

import json

from ..base import DnsConfigError, DnsError, Provider, longest_zone, norm


class AcmeDns(Provider):
    name = "acme-dns"
    optional = ("username", "password", "subdomain", "registrations")
    options_known = ("api_url",)
    delegating = True
    supports_delete = False

    def _registration(self, fqdn: str) -> dict:
        domain = norm(fqdn).removeprefix("_acme-challenge.")
        if self.has_secret("registrations"):
            try:
                regs = {norm(k): v for k, v in json.loads(self.secret("registrations")).items()}
            except (ValueError, AttributeError):
                raise DnsConfigError(f"dns account {self.account!r}: registrations is not a JSON object") from None
            for v in regs.values():
                if isinstance(v, dict) and v.get("password"):
                    self._redact.add(v["password"])
            key = domain if domain in regs else longest_zone(domain, regs)
            if key is None:
                raise DnsError(f"{self.label}: no acme-dns registration for {domain}")
            return regs[key]
        return {"username": self.secret("username"), "password": self.secret("password"),
                "subdomain": self.secret("subdomain")}

    def present(self, fqdn, value):
        api = self.opts.get("api_url")
        if not api:
            raise DnsConfigError(f"dns account {self.account!r}: options.api_url is required for acme-dns")
        reg = self._registration(fqdn)
        try:
            headers = {"X-Api-User": reg["username"], "X-Api-Key": reg["password"]}
            body = {"subdomain": reg["subdomain"], "txt": value}
        except KeyError as e:
            raise DnsConfigError(f"dns account {self.account!r}: acme-dns registration lacks {e.args[0]!r}") from None
        self.request("POST", api.rstrip("/") + "/update", headers=headers, json=body)

    def cleanup(self, fqdn, value):
        return None
