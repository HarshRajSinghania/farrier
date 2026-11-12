"""EfficientIP SOLIDserver DDI (REST API, /rest/dns_rr_*).
credentials: username, password
options:     host (required), dns_server (dns_name of the managed server, optional), view (optional),
             verify_tls (default true; set a CA path for an internal CA rather than false)"""
from __future__ import annotations

import base64

from ..base import DnsConfigError, Provider, norm, unquote_txt


class SolidServer(Provider):
    name = "solidserver"
    required = ("username", "password")
    options_known = ("host", "dns_server", "view", "verify_tls")
    default_ttl = 60

    @property
    def base(self):
        host = self.opts.get("host")
        if not host:
            raise DnsConfigError(f"dns account {self.account!r}: options.host is required for solidserver")
        return f"https://{host.removeprefix('https://').rstrip('/')}/rest"

    def _h(self):
        return {"X-IPM-Username": base64.b64encode(self.secret("username").encode()).decode(),
                "X-IPM-Password": base64.b64encode(self.secret("password").encode()).decode()}

    def _list(self, fqdn):
        where = f"rr_full_name='{norm(fqdn)}' and rr_type='TXT'"
        if self.opts.get("dns_server"):
            where += f" and dns_name='{self.opts['dns_server']}'"
        r = self.request("GET", f"{self.base}/dns_rr_list", headers=self._h(), params={"WHERE": where}, allow=(204,))
        if r.status_code == 204 or not r.content:
            return []
        return [(str(x["rr_id"]), unquote_txt(x.get("value1", ""))) for x in r.json()]

    def present(self, fqdn, value):
        if "'" in fqdn:
            raise DnsConfigError("invalid name")
        with self.lock(fqdn):
            if any(v == value for _, v in self._list(fqdn)):
                return
            params = {"rr_name": norm(fqdn), "rr_type": "TXT", "value1": value, "rr_ttl": self.ttl}
            if self.opts.get("dns_server"):
                params["dns_name"] = self.opts["dns_server"]
            if self.opts.get("view"):
                params["dnsview_name"] = self.opts["view"]
            self.request("POST", f"{self.base}/dns_rr_add", headers=self._h(), params=params)

    def cleanup(self, fqdn, value):
        with self.lock(fqdn):
            for rid, v in self._list(fqdn):
                if v == value:
                    self.request("DELETE", f"{self.base}/dns_rr_delete", headers=self._h(), params={"rr_id": rid},
                                 allow=(404,))
