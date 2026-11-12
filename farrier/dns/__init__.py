"""Built-in DNS-01 providers, multi-account routing and authoritative propagation checks.

    from farrier.dns import DnsAccounts
    accounts = DnsAccounts.load(data_dir)        # <data_dir>/dns.json
    solver = accounts.solver("auto")             # or a named account
    try:
        solver.present("_acme-challenge.example.com", value)
        solver.wait()                            # every authoritative NS serves the value
        ...                                      # let the CA validate
    finally:
        solver.cleanup()                         # never raises
"""
from farrier.dns.accounts import DnsAccounts, DnsSolver, validate_account
from farrier.dns.base import (
    DnsConfigError,
    DnsError,
    DnsPropagationError,
    Provider,
    RecordProvider,
    RRsetProvider,
    Zone,
)
from farrier.dns.providers import PROVIDERS, canonical, provider_class

__all__ = [
           "PROVIDERS",
           "DnsAccounts",
           "DnsConfigError",
           "DnsError",
           "DnsPropagationError",
           "DnsSolver",
           "Provider",
           "RRsetProvider",
           "RecordProvider",
           "Zone",
           "canonical",
           "provider_class",
           "validate_account",
]
