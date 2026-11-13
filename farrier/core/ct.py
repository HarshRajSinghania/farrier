"""Certificate Transparency discovery: every publicly trusted certificate is logged, so the logs list the names
your organisation has certificates for, including ones nobody told IT about. Uses crt.sh's public search.

ct_names("example.com") -> one row per name (newest certificate): name, not_after, issuer, wildcard. Wildcard
names are kept (flagged) because they show where a shared key is deployed; they are not scan targets.
Only the domain is sent to crt.sh; results are public data.
"""
from __future__ import annotations

import re

import httpx

DOMAIN = re.compile(r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
URL = "https://crt.sh/"


def ct_names(domain: str, http: httpx.Client | None = None, timeout: float = 60) -> list[dict]:
    domain = domain.strip().lower().rstrip(".").removeprefix("*.")
    if not DOMAIN.match(domain):
        raise ValueError(f"not a domain name: {domain!r}")
    params = {"q": f"%.{domain}", "output": "json", "exclude": "expired"}   # %.domain: every name below it
    try:
        if http is not None:
            r = http.get(URL, params=params)
        else:
            with httpx.Client(timeout=timeout, headers={"User-Agent": "farrier-ct"}) as c:
                r = c.get(URL, params=params)
    except httpx.HTTPError as e:
        raise RuntimeError(f"crt.sh did not answer ({type(e).__name__}); try again in a minute") from None
    if r.status_code != 200:
        raise RuntimeError(f"crt.sh answered HTTP {r.status_code}; try again in a minute")
    try:
        entries = r.json()
    except ValueError:   # crt.sh answers an HTML error page with 200 when it is overloaded
        raise RuntimeError("crt.sh sent an error page instead of results; try again in a minute") from None
    rows: dict[str, dict] = {}
    for e in entries if isinstance(entries, list) else []:
        for name in str(e.get("name_value", "")).lower().split("\n"):
            name = name.strip().rstrip(".")
            if not name or not (name == domain or name.endswith("." + domain)):
                continue
            row = {"name": name, "not_after": e.get("not_after"), "issuer": e.get("issuer_name"),
                   "wildcard": name.startswith("*.")}
            if name not in rows or (row["not_after"] or "") > (rows[name]["not_after"] or ""):
                rows[name] = row
    return sorted(rows.values(), key=lambda x: (x["wildcard"], x["name"]))
