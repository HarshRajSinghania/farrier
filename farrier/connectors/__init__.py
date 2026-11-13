from __future__ import annotations

from pathlib import Path

from farrier.connectors.azure_keyvault import AzureKeyVaultConnector
from farrier.connectors.aws_acm import AwsAcmConnector
from farrier.connectors.base import Bundle, Connector, DeployError
from farrier.connectors.citrix import CitrixConnector
from farrier.connectors.f5 import F5Connector
from farrier.connectors.files import FilesConnector
from farrier.connectors.fortigate import FortiGateConnector
from farrier.connectors.gcp_certificate_manager import GcpCertificateManagerConnector
from farrier.connectors.iis import IISConnector
from farrier.connectors.keystore import KeystoreConnector
from farrier.connectors.kubernetes import KubernetesConnector
from farrier.connectors.manual import ManualConnector
from farrier.connectors.panos import PanOSConnector

REGISTRY: dict[str, type[Connector]] = {c.kind: c for c in (
    FilesConnector, KeystoreConnector, F5Connector, FortiGateConnector, PanOSConnector, CitrixConnector,
    KubernetesConnector, IISConnector, AzureKeyVaultConnector, GcpCertificateManagerConnector, AwsAcmConnector,
    ManualConnector)}


def make_connector(kind: str, config: dict, data_dir: Path) -> Connector:
    if kind not in REGISTRY:
        raise ValueError(f"unknown connector {kind!r}; choose from {', '.join(REGISTRY)}")
    return REGISTRY[kind](config, data_dir)


def is_automated(kind: str) -> bool:
    return REGISTRY.get(kind, ManualConnector).automated


__all__ = ["REGISTRY", "Bundle", "Connector", "DeployError", "is_automated", "make_connector"]
