#!/usr/bin/env python3
"""Build a standalone executable for the WireGuard GUI.

PyInstaller is not a cross-compiler, so this produces a binary for the OS it runs
on: a `.exe` on Windows, a `.app` bundle on macOS, and a plain executable on Linux.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
VENV_DIR = REPO_ROOT / ".wireguard-gui-venv"
SETUP_SCRIPT = REPO_ROOT / "bin" / "setup-wireguard-gui.py"
GUI_SCRIPT = REPO_ROOT / "bin" / "wireguard-gui.py"
CONFIG_SCRIPT = REPO_ROOT / "bin" / "wireguard-config.py"
APP_NAME = "MeshtasticWireGuardConfigurator"


def _venv_python() -> Path:
    if sys.platform == "win32":
        return VENV_DIR / "Scripts" / "python.exe"
    return VENV_DIR / "bin" / "python"


def _run(command: list[str]) -> None:
    print("+ " + " ".join(command), flush=True)
    subprocess.run(command, cwd=REPO_ROOT, check=True)


def main() -> int:
    python = _venv_python()
    if not python.exists():
        _run([sys.executable, str(SETUP_SCRIPT)])

    _run([str(python), "-m", "pip", "install", "pyinstaller"])
    # PyInstaller's --add-data uses ';' on Windows and ':' elsewhere.
    separator = os.pathsep
    _run(
        [
            str(python),
            "-m",
            "PyInstaller",
            "--noconfirm",
            "--clean",
            "--onefile",
            "--windowed",
            "--name",
            APP_NAME,
            "--add-data",
            f"{CONFIG_SCRIPT}{separator}.",
            "--collect-submodules",
            "meshtastic.protobuf",
            "--hidden-import",
            "meshtastic.serial_interface",
            "--hidden-import",
            "meshtastic.tcp_interface",
            "--hidden-import",
            "serial.tools.list_ports",
            str(GUI_SCRIPT),
        ]
    )

    if sys.platform == "win32":
        artifact = REPO_ROOT / "dist" / f"{APP_NAME}.exe"
    elif sys.platform == "darwin":
        artifact = REPO_ROOT / "dist" / f"{APP_NAME}.app"
    else:
        artifact = REPO_ROOT / "dist" / APP_NAME
    print()
    print(f"Built: {artifact}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
