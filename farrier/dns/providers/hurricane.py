"""Hurricane Electric (dns.he.net) dynamic TXT. The TXT record must already exist in the HE panel with
"Enable entry for dynamic dns" ticked; its DDNS key is the credential. One value per record, so (like
DuckDNS) wildcard + apex in one order is refused with a clear error. HE cannot delete through this API:
cleanup resets the value to a harmless placeholder.

credentials: either `key` (one record) or `keys` = file:/... JSON {"_acme-challenge.example.com": "<ddns key>"}
"""
from __future__ import annotations

import json

from farrier.dns.base import DnsConfigError, DnsError, Provider, norm

API = "https://dyn.dns.he.net/nic/update"
PLACEHOLDER = "farrier-cleared"


class Hurricane(Provider):
    name = "hurricane"
    optional = ("key", "keys")
    supports_delete = False

    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self._live: dict[str, str] = {}

    def _key(self, fqdn):
        if self.has_secret("keys"):
            try:
                keys = {norm(k): v for k, v in json.loads(self.secret("keys")).items()}
            except (ValueError, AttributeError):
                raise DnsConfigError(f"dns account {self.account!r}: keys is not a JSON object") from None
            self._redact.update(v for v in keys.values() if isinstance(v, str) and len(v) >= 4)
            if norm(fqdn) not in keys:
                raise DnsError(f"{self.label}: no dynamic DNS key for {fqdn}")
            return keys[norm(fqdn)]
        return self.secret("key")

    def _update(self, fqdn, txt):
        r = self.request("POST", API, data={"hostname": norm(fqdn), "password": self._key(fqdn), "txt": txt})
        if not r.text.strip().startswith(("good", "nochg")):
            raise DnsError(f"{self.label}: update refused ({self.redact(r.text.strip())[:40]})")

    def present(self, fqdn, value):
        with self.lock(fqdn):
            if self._live.get(norm(fqdn)) not in (None, value):
                raise DnsError(f"{self.label}: Hurricane Electric dynamic TXT holds one value; {fqdn} is busy "
                               "(wildcard + apex cannot be validated in one order)")
            self._update(fqdn, value)
            self._live[norm(fqdn)] = value

    def cleanup(self, fqdn, value):
        with self.lock(fqdn):
            if self._live.get(norm(fqdn)) == value:
                self._update(fqdn, PLACEHOLDER)
                self._live.pop(norm(fqdn), None)
