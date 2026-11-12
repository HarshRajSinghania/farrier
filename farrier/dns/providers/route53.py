"""AWS Route 53 via the REST/XML API, signed with SigV4 implemented here (no boto3).

credentials: access_key_id, secret_access_key, [session_token], [external_id]
options:     hosted_zone_id (skip discovery), role_arn (STS AssumeRole into another AWS account),
             private_zones (default false), wait_insync (default true), partition_endpoint
"""
from __future__ import annotations

import hashlib
import hmac
import time
import xml.etree.ElementTree as ET
from datetime import UTC, datetime
from urllib.parse import parse_qsl, quote, urlencode, urlsplit
from xml.sax.saxutils import escape

from ..base import DnsError, RRsetProvider, Zone, norm, quote_txt, unquote_txt

ENDPOINT = "https://route53.amazonaws.com"
NS = {"r": "https://route53.amazonaws.com/doc/2013-04-01/"}
STS_NS = {"s": "https://sts.amazonaws.com/doc/2011-06-15/"}


def _hmac(key: bytes, msg: str) -> bytes:
    return hmac.new(key, msg.encode(), hashlib.sha256).digest()


def signing_key(secret_key: str, date: str, region: str, service: str) -> bytes:
    k = _hmac(("AWS4" + secret_key).encode(), date)
    k = _hmac(k, region)
    k = _hmac(k, service)
    return _hmac(k, "aws4_request")


def sigv4_headers(method: str, url: str, headers: dict, body: bytes, access_key: str, secret_key: str,
                  region: str, service: str, amz_date: str | None = None, session_token: str | None = None) -> dict:
    """Return `headers` plus X-Amz-Date, [X-Amz-Security-Token] and Authorization (AWS SigV4)."""
    amz_date = amz_date or datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    parts = urlsplit(url)
    out = dict(headers)
    out["X-Amz-Date"] = amz_date
    if session_token:
        out["X-Amz-Security-Token"] = session_token
    canon_h = {k.lower().strip(): " ".join(str(v).split()) for k, v in out.items()}
    canon_h["host"] = parts.netloc
    signed = ";".join(sorted(canon_h))
    q = sorted(parse_qsl(parts.query, keep_blank_values=True))
    canon_q = "&".join(f"{quote(k, safe='-_.~')}={quote(v, safe='-_.~')}" for k, v in q)
    creq = "\n".join([method, quote(parts.path or "/", safe="/-_.~%"), canon_q,
                      "".join(f"{k}:{canon_h[k]}\n" for k in sorted(canon_h)), signed,
                      hashlib.sha256(body).hexdigest()])
    scope = f"{amz_date[:8]}/{region}/{service}/aws4_request"
    sts = "\n".join(["AWS4-HMAC-SHA256", amz_date, scope, hashlib.sha256(creq.encode()).hexdigest()])
    sig = hmac.new(signing_key(secret_key, amz_date[:8], region, service), sts.encode(), hashlib.sha256).hexdigest()
    out["Authorization"] = f"AWS4-HMAC-SHA256 Credential={access_key}/{scope}, SignedHeaders={signed}, Signature={sig}"
    return out


class Route53(RRsetProvider):
    name = "route53"
    required = ("access_key_id", "secret_access_key")
    optional = ("session_token", "external_id")
    options_known = ("hosted_zone_id", "role_arn", "private_zones", "wait_insync", "endpoint")
    _assumed: tuple[str, str, str, float] | None = None

    def _creds(self) -> tuple[str, str, str | None]:
        role = self.opts.get("role_arn")
        if not role:
            return (self.secret("access_key_id"), self.secret("secret_access_key"),
                    self.secret("session_token") if self.has_secret("session_token") else None)
        if self._assumed and self._assumed[3] > time.time() + 300:
            return self._assumed[:3]
        params = {"Action": "AssumeRole", "Version": "2011-06-15", "RoleArn": role,
                  "RoleSessionName": "farrier-dns01", "DurationSeconds": "900"}
        if self.has_secret("external_id"):
            params["ExternalId"] = self.secret("external_id")
        url = "https://sts.amazonaws.com/?" + urlencode(params)
        hdrs = sigv4_headers("GET", url, {}, b"", self.secret("access_key_id"), self.secret("secret_access_key"),
                             "us-east-1", "sts", session_token=self.secret("session_token")
                             if self.has_secret("session_token") else None)
        root = ET.fromstring(self.request("GET", url, headers=hdrs).content)
        c = root.find(".//s:Credentials", STS_NS)
        if c is None:
            raise DnsError(f"{self.label}: AssumeRole returned no credentials")
        ak, sk, tok = (c.findtext(f"s:{k}", namespaces=STS_NS) for k in ("AccessKeyId", "SecretAccessKey", "SessionToken"))
        self._redact.update({sk, tok})
        self._assumed = (ak, sk, tok, time.time() + 900)
        return ak, sk, tok

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
