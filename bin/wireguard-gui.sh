#!/usr/bin/env bash
# Linux/macOS equivalent of wireguard-gui.cmd.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
LOCAL_PY="$REPO_ROOT/.wireguard-gui-venv/bin/python"

if [ -x "$LOCAL_PY" ]; then
    PYTHON="$LOCAL_PY"
else
    PYTHON="$(command -v python3 || command -v python || true)"
fi

if [ -z "${PYTHON:-}" ]; then
    echo "Python was not found. Install Python, then run bin/setup-wireguard-gui.sh."
    exit 1
fi

exec "$PYTHON" "$SCRIPT_DIR/wireguard-gui.py"
