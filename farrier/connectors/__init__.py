from __future__ import annotations

from pathlib import Path

from .base import Bundle, Connector, DeployError
from .f5 import F5Connector
from .files import FilesConnector
from .fortigate import FortiGateConnector
from .keystore import KeystoreConnector
from .manual import ManualConnector
from .panos import PanOSConnector

REGISTRY: dict[str, type[Connector]] = {c.kind: c for c in (
    FilesConnector, KeystoreConnector, F5Connector, FortiGateConnector, PanOSConnector, ManualConnector)}


def make_connector(kind: str, config: dict, data_dir: Path) -> Connector:
    if kind not in REGISTRY:
        raise ValueError(f"unknown connector {kind!r}; choose from {', '.join(REGISTRY)}")
    return REGISTRY[kind](config, data_dir)


def is_automated(kind: str) -> bool:
    return REGISTRY.get(kind, ManualConnector).automated


__all__ = ["REGISTRY", "Bundle", "Connector", "DeployError", "is_automated", "make_connector"]
