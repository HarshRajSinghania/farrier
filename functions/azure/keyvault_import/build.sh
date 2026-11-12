#!/usr/bin/env sh
# Build the deployable artifact for azure/keyvault_import into functions/dist/ (no network access).
# Extra arguments are passed through, e.g. ./build.sh --out /tmp/artifacts
set -eu
here=$(cd "$(dirname "$0")" && pwd)
exec "${PYTHON:-python3}" "$here/../../tools/package.py" azure/keyvault_import "$@"
