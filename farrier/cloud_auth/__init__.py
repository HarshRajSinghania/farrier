"""Cloud identity shared by DNS providers, secret backends, the master-key KMS, object storage and event
publishing. No cloud SDKs: httpx plus the signing each platform needs.

    aws        SigV4 + credentials: env keys, IRSA web identity, ECS/EKS Pod Identity, EC2 IMDSv2
    google     service-account JWT, workload identity federation, metadata server
    azure      workload identity, managed identity (App Service and IMDS), service principal
    hashicorp  VAULT_TOKEN, a token file, or Kubernetes auth with renewal
    http       the one place cloud HTTP happens: timeouts, bounded retries, secret-free errors

Platform identity comes first everywhere; long-lived keys are used only when explicitly configured.
"""
from __future__ import annotations

from .http import CloudConfigError, CloudError, set_client


def reset() -> None:
    """Drop cached identities (tests; or after rotating credentials in the environment)."""
    from . import aws, azure, google
    aws._default = None
    google._default = None
    azure._default = None


__all__ = ["CloudConfigError", "CloudError", "reset", "set_client"]
