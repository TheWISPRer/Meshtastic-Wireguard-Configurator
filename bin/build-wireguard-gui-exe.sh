#!/usr/bin/env bash
# Linux/macOS equivalent of build-wireguard-gui-exe.cmd.
# PyInstaller is not a cross-compiler: this builds a binary for the OS it runs on
# (a Linux executable on Linux, a macOS app bundle on macOS).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

PYTHON="$(command -v python3 || command -v python || true)"
if [ -z "$PYTHON" ]; then
    echo "Python 3 was not found. Install Python 3, then retry."
    exit 1
fi

cd "$REPO_ROOT"
"$PYTHON" "$SCRIPT_DIR/build-wireguard-gui-exe.py" "$@"

echo
echo "Build complete. The binary is in dist/."
