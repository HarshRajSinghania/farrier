"""Built-in DNS providers, imported lazily (a provider module is loaded only when an account uses it)."""
from __future__ import annotations

import importlib

from ..base import DnsConfigError, Provider

PROVIDERS = {
    "cloudflare": "cloudflare:Cloudflare",
    "route53": "route53:Route53",
    "azure": "azure:Azure",
    "google": "google:Google",
    "digitalocean": "digitalocean:DigitalOcean",
    "powerdns": "powerdns:PowerDNS",
    "linode": "linode:Linode",
    "gandi": "gandi:Gandi",
    "ovh": "ovh:OVH",
    "namecheap": "namecheap:Namecheap",
    "arvancloud": "arvancloud:ArvanCloud",
    "infomaniak": "infomaniak:Infomaniak",
    "acme-dns": "acmedns:AcmeDns",
    "duckdns": "duckdns:DuckDNS",
    "vultr": "vultr:Vultr",
    "dnsmadeeasy": "dnsmadeeasy:DnsMadeEasy",
    "ns1": "ns1:NS1",
    "hetzner": "hetzner:Hetzner",
    "hetzner-cloud": "hetzner_cloud:HetznerCloud",
    "porkbun": "porkbun:Porkbun",
    "godaddy": "godaddy:GoDaddy",
    "hurricane": "hurricane:Hurricane",
    "dynu": "dynu:Dynu",
    "akamai": "akamai:Akamai",
    "desec": "desec:Desec",
    "scaleway": "scaleway:Scaleway",
    "rfc2136": "rfc2136:RFC2136",
    "solidserver": "solidserver:SolidServer",
    "script": "script:Script",
}

ALIASES = {
    "aws": "route53", "route-53": "route53", "azure-dns": "azure", "azuredns": "azure", "gcloud": "google",
    "google-cloud-dns": "google", "gcp": "google", "do": "digitalocean", "pdns": "powerdns", "acmedns": "acme-dns",
    "he": "hurricane", "hurricane-electric": "hurricane", "edgedns": "akamai", "akamai-edgedns": "akamai",
    "efficientip": "solidserver", "dns-made-easy": "dnsmadeeasy", "hetzner-dns": "hetzner",
    "hetznercloud": "hetzner-cloud", "nsone": "ns1", "nsupdate": "rfc2136", "bind": "rfc2136", "exec": "script",
}

# Credentials where any one of several sets is enough (everything else: all `required` keys).
ALTERNATIVES = {
    "cloudflare": (("api_token",), ("api_key", "email")),
    "gandi": (("api_token",), ("api_key",)),
    "acme-dns": (("registrations",), ("username", "password", "subdomain")),
    "hurricane": (("key",), ("keys",)),
}


def canonical(name: str) -> str:
    n = str(name).strip().lower()
    n = ALIASES.get(n, n)
    if n not in PROVIDERS:
        raise DnsConfigError(f"unknown DNS provider {name!r}; known: {', '.join(sorted(PROVIDERS))}")
    return n


def provider_class(name: str) -> type[Provider]:
    module, cls = PROVIDERS[canonical(name)].split(":")
    return getattr(importlib.import_module(f"{__name__}.{module}"), cls)
