#!/usr/bin/env bash
# Linux/macOS equivalent of setup-wireguard-gui.cmd.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

PYTHON="$(command -v python3 || command -v python || true)"
if [ -z "$PYTHON" ]; then
    echo "Python 3 was not found. Install Python 3, then retry."
    echo "On Debian/Ubuntu you also need tkinter: sudo apt install python3-tk"
    exit 1
fi

cd "$REPO_ROOT"
"$PYTHON" "$SCRIPT_DIR/setup-wireguard-gui.py" "$@"

echo
echo "Setup complete. You can now run bin/wireguard-gui.sh."
