"""Namecheap XML API. Namecheap has no per-record API: setHosts REPLACES the whole host list of a domain.
So we read every host (getHosts), add/remove only our TXT value, and write the full list back, keeping
MX preferences, TTLs and the EmailType. A per-domain lock serialises read-modify-write in this process.
Do not run another tool against the same domain's hosts at the same moment.

credentials: api_user, api_key
options:     username (defaults to api_user), client_ip (required by Namecheap, must be whitelisted),
             sandbox (default false)
Zones must be configured ("zones": ["example.co.uk"]) or are taken from the SOA; SLD/TLD split follows them.
"""
from __future__ import annotations

import xml.etree.ElementTree as ET

from farrier.dns.base import DnsConfigError, DnsError, Provider, Zone, relative

NS = {"n": "http://api.namecheap.com/xml.response"}


class Namecheap(Provider):
    name = "namecheap"
    required = ("api_user", "api_key")
    options_known = ("username", "client_ip", "sandbox")
    default_ttl = 300

    @property
    def url(self):
        return ("https://api.sandbox.namecheap.com/xml.response" if self.opts.get("sandbox")
                else "https://api.namecheap.com/xml.response")

    def _call(self, command: str, zone: Zone, extra: dict | None = None):
        ip = self.opts.get("client_ip")
        if not ip:
            raise DnsConfigError(f"dns account {self.account!r}: options.client_ip is required for namecheap")
        sld, _, tld = zone.name.partition(".")
        user = self.secret("api_user")
        data = {"ApiUser": user, "ApiKey": self.secret("api_key"), "UserName": self.opts.get("username", user),
                "ClientIp": ip, "Command": command, "SLD": sld, "TLD": tld, **(extra or {})}
        root = ET.fromstring(self.request("POST", self.url, data=data).content)
        if root.get("Status") != "OK":
            errs = "; ".join(f"{e.get('Number')}: {e.text}" for e in root.findall(".//n:Errors/n:Error", NS))
            raise DnsError(f"{self.label}: {command} failed: {self.redact(errs)}")
        return root

    def _hosts(self, zone):
        res = self._call("namecheap.domains.dns.getHosts", zone).find(".//n:DomainDNSGetHostsResult", NS)
        if res is None:
            raise DnsError(f"{self.label}: getHosts returned no host list")
        return res.get("EmailType"), [dict(h.attrib) for h in res.findall("n:host", NS)]

    def _set(self, zone, email_type, hosts):
        extra = {}
        for i, h in enumerate(hosts, 1):
            extra.update({f"HostName{i}": h["Name"], f"RecordType{i}": h["Type"], f"Address{i}": h["Address"],
                          f"TTL{i}": h.get("TTL", "1800")})
            if h["Type"] == "MX":
                extra[f"MXPref{i}"] = h.get("MXPref", "10")
        if email_type:
            extra["EmailType"] = email_type
        self._call("namecheap.domains.dns.setHosts", zone, extra)

    def present(self, fqdn, value):
        zone = self.find_zone(fqdn)
        rel = relative(fqdn, zone.name) or "@"
        with self.lock(zone.name):
            email, hosts = self._hosts(zone)
            if any(h["Type"] == "TXT" and h["Name"] == rel and h["Address"] == value for h in hosts):
                return
            self._set(zone, email, hosts + [{"Name": rel, "Type": "TXT", "Address": value, "TTL": str(self.ttl)}])

    def cleanup(self, fqdn, value):
        zone = self.find_zone(fqdn)
        rel = relative(fqdn, zone.name) or "@"
        with self.lock(zone.name):
            email, hosts = self._hosts(zone)
            keep = [h for h in hosts if not (h["Type"] == "TXT" and h["Name"] == rel and h["Address"] == value)]
            if len(keep) != len(hosts):
                self._set(zone, email, keep)
