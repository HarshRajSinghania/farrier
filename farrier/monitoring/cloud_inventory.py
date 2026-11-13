"""Certificates held in the clouds: AWS Certificate Manager, Azure Key Vault and Google Certificate Manager.

These are not TLS endpoints Farrier scans; they are the certificates load balancers, CDNs and gateways
use. Listing them next to the inventory shows what expires where, and which are in use.

settings.json:
  "cloud_inventory": {"aws_regions": ["eu-west-1", "us-east-1"],
                      "aws_accounts": [{"role_arn": "arn:aws:iam::210987654321:role/farrier-inventory",
                                        "external_id": "env:AWS_INV_EXTERNAL_ID", "regions": ["eu-west-1"]}],
                      "azure_vaults": ["prod-kv", "edge-kv"],
                      "gcp_projects": ["my-project"]}
Credentials come from the platform chain of each cloud (farrier.security.cloud_auth); each aws_accounts
entry assumes its role on top of the AWS chain, and its rows show "<account id>/<region>" as location. Each source is
listed on its own: one that fails is reported in ``errors`` and the rest still show.
Rows: source, location, name, id, domains, not_after, in_use, managed (the cloud renews it itself).
"""
from __future__ import annotations

from datetime import UTC, datetime

from farrier.security.cloud_auth import azure, google
from farrier.security.cloud_auth.aws import ROLE_ARN, assume_role, json_call
from farrier.security.cloud_auth.http import json_body, request
from farrier.security.vault import resolve_secret

KEYS = {"aws_regions", "aws_accounts", "azure_vaults", "gcp_projects"}


def _iso(v) -> str | None:
    if v in (None, ""):
        return None
    if isinstance(v, (int, float)):     # AWS JSON timestamps and Key Vault "exp" are epoch seconds
        return datetime.fromtimestamp(v, UTC).isoformat(timespec="seconds")
    return str(v)


def aws(region: str, http=None, creds=None, location: str | None = None) -> list[dict]:
    rows, token = [], None
    while True:
        body = {"MaxItems": 1000, "Includes": {"keyTypes": ["RSA_1024", "RSA_2048", "RSA_3072", "RSA_4096",
                                                            "EC_prime256v1", "EC_secp384r1", "EC_secp521r1"]}}
        if token:
            body["NextToken"] = token
        r = json_call("acm", "ListCertificates", body, region=region, what="ACM ListCertificates", http=http,
                      creds=creds)
        for c in r.get("CertificateSummaryList") or []:
            rows.append({"source": "aws-acm", "location": location or region, "name": c.get("DomainName"),
                         "id": c["CertificateArn"], "domains": c.get("SubjectAlternativeNameSummaries") or
                         [c.get("DomainName")], "not_after": _iso(c.get("NotAfter")), "in_use": c.get("InUse"),
                         "managed": c.get("Type") in ("AMAZON_ISSUED", "PRIVATE") and c.get("RenewalEligibility")
                         == "ELIGIBLE", "status": c.get("Status")})
        token = r.get("NextToken")
        if not token:
            return rows


def azure_vault(vault: str, http=None, tokens=None) -> list[dict]:
    rows = []
    url = f"https://{vault}.vault.azure.net/certificates?api-version=7.4&maxresults=25"
    tok = (tokens or azure.default_provider()).token(azure.VAULT_SCOPE)
    while url:
        j = json_body(request("GET", url, what=f"Key Vault {vault} certificates", http=http,
                              headers={"Authorization": f"Bearer {tok}"}), "certificate list")
        for c in j.get("value") or []:
            a = c.get("attributes") or {}
            rows.append({"source": "azure-keyvault", "location": vault, "name": c["id"].rstrip("/").rsplit("/", 1)[-1],
                         "id": c["id"], "domains": (c.get("subject") and [c["subject"]]) or [], "not_after": _iso(a.get("exp")),
                         "in_use": None, "managed": None, "status": "enabled" if a.get("enabled", True) else "disabled"})
        url = j.get("nextLink")
    return rows


def gcp(project: str, http=None, tokens=None) -> list[dict]:
    rows, page = [], None
    tok = (tokens or google.default_provider()).token(google.CLOUD_PLATFORM)
    while True:
        params = {"pageSize": 500, **({"pageToken": page} if page else {})}
        j = json_body(request("GET", f"https://certificatemanager.googleapis.com/v1/projects/{project}/locations/-/"
                              "certificates", what=f"Certificate Manager {project}", http=http, params=params,
                              headers={"Authorization": f"Bearer {tok}"}), "certificate list")
        for c in j.get("certificates") or []:
            rows.append({"source": "gcp-certificate-manager", "location": c["name"].split("/")[3],
                         "name": c["name"].rsplit("/", 1)[-1], "id": c["name"], "domains": c.get("sanDnsnames") or [],
                         "not_after": c.get("expireTime"), "in_use": None, "managed": "managed" in c,
                         "status": (c.get("managed") or {}).get("state") or "SELF_MANAGED"})
        page = j.get("nextPageToken")
        if not page:
            return rows


def _account(a: dict, region: str):
    """ACM in another account: its role assumed on top of the default AWS chain."""
    def fn(location, http=None):
        ext = a.get("external_id")
        return aws(region, http=http, location=location,
                   creds=assume_role(a["role_arn"], resolve_secret(ext) if ext else None, "farrier-inventory"))
    return fn


def inventory(cfg: dict | None, http=None) -> dict:
    """{"certificates": [...] soonest expiry first, "errors": [{"source", "location", "error"}]}."""
    cfg = cfg or {}
    rows, errors = [], []
    sources = ([("aws-acm", r, aws) for r in cfg.get("aws_regions") or []]
               + [("aws-acm", f"{a['role_arn'].split(':')[4]}/{r}", _account(a, r))
                  for a in cfg.get("aws_accounts") or [] for r in a["regions"]]
               + [("azure-keyvault", v, azure_vault) for v in cfg.get("azure_vaults") or []]
               + [("gcp-certificate-manager", p, gcp) for p in cfg.get("gcp_projects") or []])
    for source, where, fn in sources:
        try:
            rows += fn(where, http=http)
        except Exception as e:  # noqa: BLE001 - one cloud failing must not hide the others
            errors.append({"source": source, "location": where, "error": f"{type(e).__name__}: {e}"[:300]})
    now = datetime.now(UTC)
    for r in rows:
        try:
            r["days_left"] = round((datetime.fromisoformat(r["not_after"].replace("Z", "+00:00")) - now).total_seconds()
                                   / 86400, 1) if r["not_after"] else None
        except ValueError:
            r["days_left"] = None
    rows.sort(key=lambda r: r["not_after"] or "9999")
    return {"certificates": rows, "errors": errors}


def validate(cfg) -> None:
    if cfg is None:
        return
    names = lambda v: isinstance(v, list) and all(isinstance(x, str) and x for x in v)  # noqa: E731
    if not isinstance(cfg, dict) or set(cfg) - KEYS or not all(names(v) for k, v in cfg.items() if k != "aws_accounts"):
        raise ValueError(f'settings.json "cloud_inventory": an object with lists of names under {", ".join(sorted(KEYS))}')
    accounts = cfg.get("aws_accounts") or []
    if not isinstance(accounts, list) or not all(
            isinstance(a, dict) and not set(a) - {"role_arn", "external_id", "regions"}
            and ROLE_ARN.match(str(a.get("role_arn"))) and names(a.get("regions")) and a["regions"]
            and isinstance(a.get("external_id", ""), str) for a in accounts):
        raise ValueError('settings.json "cloud_inventory" "aws_accounts": a list of {"role_arn": "arn:aws:iam::'
                         '<account>:role/<name>", "regions": ["eu-west-1"], "external_id": optional}')
