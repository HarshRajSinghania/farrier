"""The original Farrier hook contract, for any DNS host without a built-in provider.

options: dns_hook  (shell command; receives FARRIER_DNS_ACTION=present|cleanup, FARRIER_DNS_NAME,
                    FARRIER_DNS_VALUE). Same contract as the ACME issuer's `dns_hook`; see
                    examples/dns-hook-nsupdate.sh. The key is named dns_hook so the API's command-key
                    guard (api.COMMAND_KEYS) applies to it too.
credentials: any; each is exported to the hook as FARRIER_DNS_CRED_<NAME> (resolved at call time),
             so the script never needs secrets on its command line.
Unlike CertMate's custom script, cleanup is not optional: a hook that fails "cleanup" is reported.
"""
from __future__ import annotations

import os
import subprocess

from farrier.dns.base import DnsConfigError, DnsError, Provider, norm


class Script(Provider):
    name = "script"
    options_known = ("dns_hook", "timeout")

    def _run(self, action, fqdn, value):
        cmd = self.opts.get("dns_hook")
        if not cmd:
            raise DnsConfigError(f"dns account {self.account!r}: options.dns_hook is required for the script provider")
        env = {**os.environ, "FARRIER_DNS_ACTION": action, "FARRIER_DNS_NAME": norm(fqdn), "FARRIER_DNS_VALUE": value}
        for k in self._refs:
            env[f"FARRIER_DNS_CRED_{k.upper()}"] = self.secret(k)
        try:
            subprocess.run(cmd, shell=True, check=True, env=env, timeout=int(self.opts.get("timeout", 300)),
                           stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        except subprocess.CalledProcessError as e:
            err = (e.stderr or b"").decode(errors="replace").strip().splitlines()[-1:] or [""]
            raise DnsError(f"{self.label}: hook {action} exited {e.returncode}: {self.redact(err[0])[:200]}") from None
        except subprocess.TimeoutExpired:
            raise DnsError(f"{self.label}: hook {action} timed out") from None

    def present(self, fqdn, value):
        self._run("present", fqdn, value)

    def cleanup(self, fqdn, value):
        self._run("cleanup", fqdn, value)
