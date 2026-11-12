"""The artifacts build offline and contain exactly what each runtime needs."""

from __future__ import annotations

import hashlib
import importlib.util
import sys
import zipfile
from pathlib import Path

import pytest

PACKAGE_PY = Path(__file__).resolve().parents[2] / "tools" / "package.py"
_spec = importlib.util.spec_from_file_location("farrier_package_tool", PACKAGE_PY)
assert _spec and _spec.loader
package = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = package  # dataclasses look the module up while decorating
_spec.loader.exec_module(package)

EXPECTED = {
    "aws/acm_import": {
        "acm_import/handler.py",
        "acm_import/core.py",
        "farrier_events/event.py",
        "farrier_aws/__init__.py",
    },
    "aws/notify_router": {"notify_router/handler.py", "notify_router/sinks.py", "farrier_aws/errors.py"},
    "gcp/cert_manager_import": {"main.py", "requirements.txt", "cert_manager_import/core.py", "farrier_events/refs.py"},
    "azure/keyvault_import": {"function_app.py", "host.json", "requirements.txt", "keyvault_import/core.py"},
}


@pytest.mark.parametrize("name", sorted(EXPECTED))
def test_artifact_contents(name: str, tmp_path: Path) -> None:
    path = package.build(name, tmp_path)
    names = set(zipfile.ZipFile(path).namelist())
    assert EXPECTED[name] <= names
    assert not any("/tests/" in n or n.endswith(".pyc") or "__pycache__" in n for n in names)
    assert not any(n.startswith("farrier_testkit") for n in names)


def test_artifacts_are_reproducible(tmp_path: Path) -> None:
    a = package.build("aws/acm_import", tmp_path / "a")
    b = package.build("aws/acm_import", tmp_path / "b")
    assert hashlib.sha256(a.read_bytes()).digest() == hashlib.sha256(b.read_bytes()).digest()
