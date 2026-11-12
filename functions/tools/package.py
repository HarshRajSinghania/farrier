#!/usr/bin/env python3
"""Build a deployable artifact for one function, offline.

    python functions/tools/package.py aws/acm_import            # -> functions/dist/acm_import.zip
    python functions/tools/package.py all --out /tmp/artifacts

The shared packages (``farrier_events``, plus ``farrier_aws`` for Lambdas) are
copied from ``functions/common`` into the artifact -- nothing is downloaded.
Third-party dependencies are not bundled:

* Lambda: boto3 ships with the Python 3.12 runtime.
* Cloud Functions / Azure Functions: ``requirements.txt`` is installed by the
  platform's build (Cloud Build, Oryx remote build) at deploy time.

Archives are reproducible (sorted entries, fixed timestamps and modes), so the
Terraform ``source_code_hash`` only changes when the code does.
"""

from __future__ import annotations

import argparse
import sys
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

FUNCTIONS_DIR = Path(__file__).resolve().parent.parent
COMMON_DIR = FUNCTIONS_DIR / "common"
FIXED_TIME = (1980, 1, 1, 0, 0, 0)
EXCLUDED_DIRS = {"tests", "__pycache__", ".pytest_cache"}
EXCLUDED_SUFFIXES = {".pyc", ".pyo"}


@dataclass(frozen=True)
class Spec:
    package: str  # the function's own package, kept as a package in the artifact
    shared: tuple[str, ...]  # packages copied from functions/common
    root_files: tuple[str, ...] = field(default=())  # files lifted from the package to the artifact root


SPECS: dict[str, Spec] = {
    "aws/acm_import": Spec("acm_import", ("farrier_events", "farrier_aws")),
    "aws/notify_router": Spec("notify_router", ("farrier_events", "farrier_aws")),
    "gcp/cert_manager_import": Spec("cert_manager_import", ("farrier_events",), ("main.py", "requirements.txt")),
    "azure/keyvault_import": Spec(
        "keyvault_import", ("farrier_events",), ("function_app.py", "host.json", "requirements.txt")
    ),
}


def _files(root: Path) -> list[Path]:
    out = []
    for path in sorted(root.rglob("*")):
        rel = path.relative_to(root)
        if path.is_dir() or any(part in EXCLUDED_DIRS for part in rel.parts) or path.suffix in EXCLUDED_SUFFIXES:
            continue
        out.append(path)
    return out


def entries(name: str) -> list[tuple[str, Path]]:
    """``(archive path, source path)`` pairs for a function, sorted."""
    spec = SPECS[name]
    src = FUNCTIONS_DIR / name
    pairs: list[tuple[str, Path]] = []
    for path in _files(src):
        rel = path.relative_to(src).as_posix()
        if rel in spec.root_files:
            pairs.append((rel, path))
        elif path.suffix == ".py":
            pairs.append((f"{spec.package}/{rel}", path))
    for shared in spec.shared:
        base = COMMON_DIR / shared
        if not base.is_dir():
            raise SystemExit(f"missing shared package {base}")
        pairs.extend((f"{shared}/{p.relative_to(base).as_posix()}", p) for p in _files(base) if p.suffix == ".py")
    missing = [f for f in spec.root_files if f not in {a for a, _ in pairs}]
    if missing:
        raise SystemExit(f"{name}: missing root files {missing}")
    return sorted(pairs)


def build(name: str, out_dir: Path) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    target = out_dir / f"{SPECS[name].package}.zip"
    tmp = target.with_suffix(".zip.tmp")
    with zipfile.ZipFile(tmp, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for arcname, path in entries(name):
            info = zipfile.ZipInfo(arcname, date_time=FIXED_TIME)
            info.external_attr = 0o644 << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            zf.writestr(info, path.read_bytes().replace(b"\r\n", b"\n"))
    tmp.replace(target)
    return target


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("function", choices=[*SPECS, "all"])
    parser.add_argument("--out", type=Path, default=FUNCTIONS_DIR / "dist")
    args = parser.parse_args(argv)
    for name in SPECS if args.function == "all" else [args.function]:
        print(build(name, args.out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
