"""AWS Route 53 via the REST/XML API, signed with SigV4 implemented here (no boto3).

credentials: access_key_id, secret_access_key, [session_token], [external_id]
options:     hosted_zone_id (skip discovery), role_arn (STS AssumeRole into another AWS account),
             private_zones (default false), wait_insync (default true), partition_endpoint
"""
from __future__ import annotations

import xml.etree.ElementTree as ET
from urllib.parse import urlencode
from xml.sax.saxutils import escape

from farrier.dns.base import DnsError, RRsetProvider, Zone, norm, quote_txt, unquote_txt
from farrier.security.cloud_auth.aws import (
    AssumeRoleProvider,
    AwsCredentialProvider,
    signing_key,
    sigv4_headers,
)
from farrier.security.cloud_auth.http import CloudError

ENDPOINT = "https://route53.amazonaws.com"
NS = {"r": "https://route53.amazonaws.com/doc/2013-04-01/"}
__all__ = ["Route53", "signing_key", "sigv4_headers"]   # the signer lives in farrier.cloud_auth.aws


class Route53(RRsetProvider):
    name = "route53"
    required = ("access_key_id", "secret_access_key")
    optional = ("session_token", "external_id")
    options_known = ("hosted_zone_id", "role_arn", "private_zones", "wait_insync", "endpoint")
    _role: AssumeRoleProvider | None = None

    def _creds(self) -> tuple[str, str, str | None]:
        keys = (self.secret("access_key_id"), self.secret("secret_access_key"),
                self.secret("session_token") if self.has_secret("session_token") else None)
        role = self.opts.get("role_arn")
        if not role:
            return keys
        try:
            if self._role is None:
                base = AwsCredentialProvider(env={"AWS_ACCESS_KEY_ID": keys[0], "AWS_SECRET_ACCESS_KEY": keys[1],
                                                  "AWS_SESSION_TOKEN": keys[2] or ""})
                self._role = AssumeRoleProvider(role, self.secret("external_id") if self.has_secret("external_id")
                                                else None, "farrier-dns01", base=base, http=self.http, duration=900)
            c = self._role.get()
        except CloudError as e:
            raise DnsError(f"{self.label}: {e}") from None
        self._redact.update({c.secret_key, c.token})
        return c.access_key, c.secret_key, c.token

    def _call(self, method: str, path: str, params: dict | None = None, body: bytes = b""):
        url = self.opts.get("endpoint", ENDPOINT) + path + ("?" + urlencode(params) if params else "")
        ak, sk, tok = self._creds()
        hdrs = {"Content-Type": "application/xml"} if body else {}
        hdrs = sigv4_headers(method, url, hdrs, body, ak, sk, "us-east-1", "route53", session_token=tok)
        return ET.fromstring(self.request(method, url, headers=hdrs, content=body).content)

    def list_zones(self) -> list[Zone]:
        zones, marker = [], None
        while True:
            root = self._call("GET", "/2013-04-01/hostedzone", {"maxitems": "100", **({"marker": marker} if marker else {})})
            for hz in root.findall(".//r:HostedZone", NS):
                if hz.findtext("r:Config/r:PrivateZone", "false", NS) == "true" and not self.opts.get("private_zones"):
                    continue
                zones.append(Zone(norm(hz.findtext("r:Name", "", NS)), hz.findtext("r:Id", "", NS).split("/")[-1]))
            if root.findtext("r:IsTruncated", "false", NS) != "true":
                return zones
            marker = root.findtext("r:NextMarker", None, NS)

    def zone_id(self, name: str) -> str:
        if self.opts.get("hosted_zone_id"):
            return self.opts["hosted_zone_id"]
        return self._zone_id_from_list(name)

    def _get(self, zone, fqdn):
        root = self._call("GET", f"/2013-04-01/hostedzone/{zone.id}/rrset",
                          {"name": fqdn + ".", "type": "TXT", "maxitems": "1"})
        for rs in root.findall(".//r:ResourceRecordSet", NS):
            if norm(rs.findtext("r:Name", "", NS)) == fqdn and rs.findtext("r:Type", "", NS) == "TXT":
                self._ttls[fqdn] = int(rs.findtext("r:TTL", str(self.ttl), NS))
                return [unquote_txt(v.text or "") for v in rs.findall(".//r:ResourceRecord/r:Value", NS)]
        return []

    def _change(self, zone, action: str, fqdn: str, values: list[str]):
        ttl = self._ttls.get(fqdn, self.ttl) if action == "DELETE" else self.ttl
        recs = "".join(f"<ResourceRecord><Value>{escape(quote_txt(v))}</Value></ResourceRecord>" for v in values)
        body = ('<?xml version="1.0" encoding="UTF-8"?>'
                f'<ChangeResourceRecordSetsRequest xmlns="{NS["r"]}"><ChangeBatch><Comment>farrier dns-01</Comment>'
                f"<Changes><Change><Action>{action}</Action><ResourceRecordSet><Name>{escape(fqdn)}.</Name>"
                f"<Type>TXT</Type><TTL>{ttl}</TTL><ResourceRecords>{recs}</ResourceRecords>"
                "</ResourceRecordSet></Change></Changes></ChangeBatch></ChangeResourceRecordSetsRequest>").encode()
        root = self._call("POST", f"/2013-04-01/hostedzone/{zone.id}/rrset/", body=body)
        change = root.findtext(".//r:ChangeInfo/r:Id", "", NS).split("/")[-1]
        if change and self.opts.get("wait_insync", True) and action != "DELETE":
            for _ in range(60):
                if self._call("GET", f"/2013-04-01/change/{change}").findtext(".//r:Status", "", NS) == "INSYNC":
                    return
                self.sleep(2)

    def _put(self, zone, fqdn, values, current):
        self._change(zone, "UPSERT", fqdn, values)

    def _remove(self, zone, fqdn, current):
        self._change(zone, "DELETE", fqdn, current)  # DELETE must name the exact current values
