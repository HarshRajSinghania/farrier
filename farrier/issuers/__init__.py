"""Issuer registry. Issuers are configured in <data_dir>/issuers.json:

{
  "default": {"type": "local_ca"},
  "le":      {"preset": "letsencrypt", "email": "pki@example.com", "dns": "auto"},
  "zerossl": {"preset": "zerossl", "eab_kid": "env:FARRIER_SECRET_ZEROSSL_KID",
              "eab_hmac_key": "env:FARRIER_SECRET_ZEROSSL_HMAC", "dns": "cf-prod"},
  "digicert":{"preset": "digicert", "directory_url": "https://acme.digicert.com/v2/acme/directory/",
              "eab_kid": "env:DIGICERT_EAB_KID", "eab_hmac_key": "env:DIGICERT_EAB_HMAC",
              "dns_hook": "/opt/farrier/hooks/infoblox.sh"},
  "legacy":  {"type": "acme", "directory_url": "https://acme-v02.api.letsencrypt.org/directory",
              "email": "pki@example.com", "dns_hook": "/opt/farrier/hooks/route53.sh", "propagation_seconds": 60}
}

"dns": "auto" picks the DNS account per name from <data_dir>/dns.json (longest matching zone);
"dns": "<account>" pins one account. "dns_hook" (shell command) keeps working unchanged.
A preset fills in "type" and "directory_url"; anything set explicitly wins.
"""
from __future__ import annotations

import json
from pathlib import Path

from ..vault import resolve_secret
from .acme import AcmeIssuer
from .local_ca import LocalCA

# name -> (directory URL or None when it is account-specific, EAB required?)
PRESETS: dict[str, dict] = {
    "letsencrypt": {"directory_url": "https://acme-v02.api.letsencrypt.org/directory", "eab": False},
    "letsencrypt-staging": {"directory_url": "https://acme-staging-v02.api.letsencrypt.org/directory", "eab": False},
    "zerossl": {"directory_url": "https://acme.zerossl.com/v2/DV90", "eab": True},
    "google": {"directory_url": "https://dv.acme-v02.api.pki.goog/directory", "eab": True},
    "google-staging": {"directory_url": "https://dv.acme-v02.test-api.pki.goog/directory", "eab": True},
    "buypass": {"directory_url": "https://api.buypass.com/acme/directory", "eab": False},
    "buypass-staging": {"directory_url": "https://api.test4.buypass.no/acme/directory", "eab": False},
    # SSL.com: one directory per key family; the account key is ECDSA, the certificate key may be either
    "sslcom": {"directory_url": "https://acme.ssl.com/sslcom-dv-ecc", "eab": True},
    "sslcom-rsa": {"directory_url": "https://acme.ssl.com/sslcom-dv-rsa", "eab": True},
    # Commercial CAs hand out a per-account / per-product directory URL together with the EAB key
    "digicert": {"directory_url": None, "eab": True},
    "sectigo": {"directory_url": None, "eab": True},
}


def apply_preset(name: str, c: dict) -> dict:
    """Expand {"preset": ...} into a plain acme config. Raises ValueError with a precise message."""
    preset = c.pop("preset")
    p = PRESETS.get(str(preset).lower())
    if p is None:
        raise ValueError(f"issuer {name}: unknown preset {preset!r}; known: {', '.join(sorted(PRESETS))}")
    if c.setdefault("type", "acme") != "acme":
        raise ValueError(f"issuer {name}: preset {preset!r} is an ACME preset but type is {c['type']!r}")
    if not c.get("directory_url"):
        if p["directory_url"] is None:
            raise ValueError(f"issuer {name}: preset {preset!r} needs \"directory_url\" (the ACME directory "
                             "your CA account was given)")
        c["directory_url"] = p["directory_url"]
    if p["eab"] and not (c.get("eab_kid") and c.get("eab_hmac_key")):
        raise ValueError(f"issuer {name}: preset {preset!r} requires External Account Binding: set \"eab_kid\" "
                         "and \"eab_hmac_key\" (as env:/file: references)")
    return c


def load_issuers(data_dir: Path) -> dict:
    path = Path(data_dir) / "issuers.json"
    cfg = json.loads(path.read_text()) if path.exists() else {"default": {"type": "local_ca"}}
    out = {}
    for name, c in cfg.items():
        c = dict(c)
        if "preset" in c:
            c = apply_preset(name, c)
        c = {k: resolve_secret(v) for k, v in c.items()}
        kind = c.pop("type", None)
        if kind == "local_ca":
            out[name] = LocalCA(data_dir, **c)
        elif kind == "acme":
            out[name] = AcmeIssuer(data_dir, **c)
        else:
            raise ValueError(f"issuer {name}: unknown type {kind}")
    return out
