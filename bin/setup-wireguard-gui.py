#!/usr/bin/env python3
"""Create a local Python environment for the WireGuard GUI."""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
import venv
from pathlib import Path
from urllib.request import urlopen


REPO_ROOT = Path(__file__).resolve().parents[1]
VENV_DIR = REPO_ROOT / ".wireguard-gui-venv"
DEFAULT_PROTO_BASE_URL = "https://raw.githubusercontent.com/TheWISPRer/Meshtastic/Wireguard/protobufs/meshtastic"
PROTO_PROFILES = {
    "wireguard": DEFAULT_PROTO_BASE_URL,
    "2.8-wireguard-trial": "https://raw.githubusercontent.com/meshtastic/protobufs/develop/meshtastic",
}
WIREGUARD_CONFIG_PROTO = r'''
  /*
   * Configuration for the experimental WireGuard VPN client
   */
  message WireGuardConfig {
    /*
     * Client address. Must not include subnet mask.
     */
    string address = 1;

    /*
     * WireGuard server host
     */
    string server_addr = 2;

    /*
     * WireGuard server port
     */
    uint32 server_port = 3;

    /*
     * Client private key
     */
    string private_key = 4;

    /*
     * Server public key
     */
    string public_key = 5;

    /*
     * Optional preshared key
     */
    string preshared_key = 6;

    /*
     * Whether the WireGuard tunnel should be started when networking and NTP are ready.
     */
    bool enabled = 7;

    /*
     * Runtime tunnel status. This is reported by firmware and is not intended to be saved by clients.
     */
    enum Status {
      STATUS_UNSPECIFIED = 0;
      DISABLED = 1;
      NOT_CONFIGURED = 2;
      WAITING_FOR_NETWORK = 3;
      WAITING_FOR_NTP = 4;
      RESOLVING_SERVER = 5;
      RUNNING = 6;
      FAILED = 7;
    }

    /*
     * Current runtime status for the tunnel.
     */
    Status status = 8;

    /*
     * Short human-readable reason for the current status, if any.
     */
    string last_error = 9;
  }
'''
WIREGUARD_ONEOF_PROTO = '''
    /*
     * WireGuard VPN configuration
     */
    WireGuardConfig wireguard = 17;
'''
WIREGUARD_LOCAL_PROTO = '''
  /*
   * WireGuard VPN Config
   */
  ModuleConfig.WireGuardConfig wireguard = 18;
'''
WORK_PROTO_ROOT = VENV_DIR / "generated-proto-src"
GENERATED_ROOT = VENV_DIR / "generated-protobufs"
PROTO_FILES = [
    "admin.proto",
    "apponly.proto",
    "atak.proto",
    "cannedmessages.proto",
    "channel.proto",
    "clientonly.proto",
    "config.proto",
    "connection_status.proto",
    "device_ui.proto",
    "deviceonly.proto",
    "interdevice.proto",
    "localonly.proto",
    "mesh.proto",
    "module_config.proto",
    "mqtt.proto",
    "paxcount.proto",
    "portnums.proto",
    "powermon.proto",
    "remote_hardware.proto",
    "rtttl.proto",
    "serial_hal.proto",
    "storeforward.proto",
    "telemetry.proto",
    "xmodem.proto",
]


def _venv_python() -> Path:
    if sys.platform == "win32":
        return VENV_DIR / "Scripts" / "python.exe"
    return VENV_DIR / "bin" / "python"


def _run(command: list[str], *, cwd: Path | None = None) -> None:
    print("+ " + " ".join(command))
    subprocess.run(command, cwd=cwd or REPO_ROOT, check=True)


def _create_venv(clear: bool) -> Path:
    if clear and VENV_DIR.exists():
        shutil.rmtree(VENV_DIR)
    if not VENV_DIR.exists():
        venv.EnvBuilder(with_pip=True).create(VENV_DIR)
    return _venv_python()


def _install_dependencies(python: Path) -> None:
    _run([str(python), "-m", "pip", "install", "--upgrade", "pip"])
    _run([str(python), "-m", "pip", "install", "meshtastic", "grpcio-tools"])


def _read_proto(proto_name: str, proto_dir: Path | None, proto_base_url: str) -> str:
    if proto_dir:
        return (proto_dir / proto_name).read_text(encoding="utf-8")

    url = f"{proto_base_url.rstrip('/')}/{proto_name}"
    with urlopen(url, timeout=30) as response:
        return response.read().decode("utf-8")


def _copy_nanopb_proto(proto_dir: Path | None, proto_base_url: str) -> None:
    target = WORK_PROTO_ROOT / "nanopb.proto"
    if proto_dir:
        nanopb = proto_dir.parent / "nanopb.proto"
        if nanopb.exists():
            target.write_text(nanopb.read_text(encoding="utf-8"), encoding="utf-8")
        return

    url = f"{proto_base_url.rstrip('/').rsplit('/', 1)[0]}/nanopb.proto"
    try:
        with urlopen(url, timeout=30) as response:
            target.write_text(response.read().decode("utf-8"), encoding="utf-8")
    except OSError:
        pass


def _patch_wireguard_proto(text: str, proto_name: str, profile: str) -> str:
    if profile != "2.8-wireguard-trial" or proto_name != "module_config.proto":
        return text
    if "message WireGuardConfig" not in text:
        marker = "  /*\n   * TODO: REPLACE\n   */\n  oneof payload_variant {"
        if marker not in text:
            raise RuntimeError("Unable to patch WireGuardConfig into 2.8 module_config.proto.")
        text = text.replace(marker, WIREGUARD_CONFIG_PROTO + "\n" + marker, 1)
    if "WireGuardConfig wireguard" not in text:
        marker = "    TAKConfig tak = 16;\n"
        if marker not in text:
            raise RuntimeError("Unable to patch WireGuard oneof into 2.8 module_config.proto.")
        text = text.replace(marker, marker + "\n" + WIREGUARD_ONEOF_PROTO, 1)
    return text


def _patch_wireguard_admin(text: str, proto_name: str, profile: str) -> str:
    if profile != "2.8-wireguard-trial" or proto_name != "admin.proto":
        return text
    if "WIREGUARD_CONFIG" in text:
        return text
    marker = "    TAK_CONFIG = 15;\n"
    if marker not in text:
        raise RuntimeError("Unable to patch WIREGUARD_CONFIG into 2.8 admin.proto.")
    return text.replace(
        marker,
        marker
        + "\n"
        + "    /*\n"
        + "     * WireGuard VPN client configuration\n"
        + "     */\n"
        + "    WIREGUARD_CONFIG = 16;\n",
        1,
    )


def _patch_wireguard_local(text: str, proto_name: str, profile: str) -> str:
    if profile != "2.8-wireguard-trial" or proto_name != "localonly.proto":
        return text
    if "ModuleConfig.WireGuardConfig wireguard" in text:
        return text
    marker = "  ModuleConfig.TAKConfig tak = 17;\n"
    if marker not in text:
        raise RuntimeError("Unable to patch WireGuard local module config into 2.8 localonly.proto.")
    return text.replace(marker, marker + "\n" + WIREGUARD_LOCAL_PROTO, 1)


def _copy_transformed_protos(proto_dir: Path | None, proto_base_url: str, profile: str) -> list[Path]:
    if WORK_PROTO_ROOT.exists():
        shutil.rmtree(WORK_PROTO_ROOT)
    target_dir = WORK_PROTO_ROOT / "meshtastic" / "protobuf"
    target_dir.mkdir(parents=True)

    transformed: list[Path] = []
    for proto_name in PROTO_FILES:
        text = _read_proto(proto_name, proto_dir, proto_base_url)
        text = _patch_wireguard_proto(text, proto_name, profile)
        text = _patch_wireguard_admin(text, proto_name, profile)
        text = _patch_wireguard_local(text, proto_name, profile)
        text = text.replace("package meshtastic;", "package meshtastic.protobuf;")
        text = text.replace('"meshtastic/', '"meshtastic/protobuf/')
        target = target_dir / proto_name
        target.write_text(text, encoding="utf-8")
        transformed.append(target.relative_to(WORK_PROTO_ROOT))

    _copy_nanopb_proto(proto_dir, proto_base_url)
    return transformed


def _generate_branch_protobufs(python: Path, protos: list[Path], proto_dir: Path | None) -> None:
    if GENERATED_ROOT.exists():
        shutil.rmtree(GENERATED_ROOT)
    GENERATED_ROOT.mkdir(parents=True)

    include_args = ["-I", str(WORK_PROTO_ROOT)]
    repo_proto_root = REPO_ROOT / "protobufs"
    if repo_proto_root.exists():
        include_args.extend(["-I", str(repo_proto_root)])
    if proto_dir:
        include_args.extend(["-I", str(proto_dir.parent)])

    command = [
        str(python),
        "-m",
        "grpc_tools.protoc",
        *include_args,
        "--python_out",
        str(GENERATED_ROOT),
        *[str(proto).replace("\\", "/") for proto in protos],
    ]
    _run(command, cwd=WORK_PROTO_ROOT)


def _install_branch_protobufs(python: Path) -> None:
    code = "import meshtastic.protobuf, pathlib; print(pathlib.Path(meshtastic.protobuf.__file__).parent)"
    package_dir = subprocess.check_output([str(python), "-c", code], text=True).strip()
    target = Path(package_dir)
    source = GENERATED_ROOT / "meshtastic" / "protobuf"

    for generated in source.glob("*_pb2.py"):
        shutil.copy2(generated, target / generated.name)

    check = (
        "from meshtastic.protobuf import localonly_pb2, module_config_pb2; "
        "m = module_config_pb2.ModuleConfig(); "
        "lm = localonly_pb2.LocalModuleConfig(); "
        "raise SystemExit(0 if hasattr(m, 'wireguard') and hasattr(lm, 'wireguard') else 1)"
    )
    _run([str(python), "-c", check])


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--recreate", action="store_true", help="Delete and recreate the local GUI environment.")
    parser.add_argument(
        "--proto-profile",
        choices=sorted(PROTO_PROFILES),
        default="wireguard",
        help="Protobuf source profile to install. Use 2.8-wireguard-trial for current 2.8 development firmware trials.",
    )
    parser.add_argument("--proto-dir", type=Path, help="Use a local meshtastic protobuf directory instead of downloading.")
    parser.add_argument("--proto-base-url", help="Base URL for Meshtastic .proto downloads. Overrides --proto-profile.")
    args = parser.parse_args()

    proto_base_url = args.proto_base_url or PROTO_PROFILES[args.proto_profile]
    python = _create_venv(args.recreate)
    _install_dependencies(python)
    protos = _copy_transformed_protos(args.proto_dir, proto_base_url, args.proto_profile)
    _generate_branch_protobufs(python, protos, args.proto_dir)
    _install_branch_protobufs(python)

    print()
    print(f"WireGuard GUI environment is ready: {VENV_DIR}")
    print("Launch with: bin\\wireguard-gui.cmd")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
