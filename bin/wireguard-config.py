#!/usr/bin/env python3
"""Configure the experimental WireGuard module over the Meshtastic admin API."""

from __future__ import annotations

import argparse
import configparser
import errno
import json
import re
import select
import socket
import sys
import time
from pathlib import Path
from threading import Event
from typing import Any, Callable

SECRET = "sekrit"


def list_serial_ports() -> list[dict[str, str]]:
    try:
        from serial.tools import list_ports
    except ModuleNotFoundError as exc:
        raise RuntimeError(
            "pyserial is required to list serial ports. Install meshtastic-python in your active Python environment first."
        ) from exc

    return [
        {
            "device": port.device,
            "description": port.description,
            "hwid": port.hwid,
        }
        for port in list_ports.comports()
    ]


def _import_meshtastic():
    try:
        from meshtastic.mesh_interface import MeshInterface
        from meshtastic.protobuf import admin_pb2, config_pb2, mesh_pb2, module_config_pb2
        from meshtastic.serial_interface import SerialInterface
        from meshtastic.tcp_interface import TCPInterface
    except ModuleNotFoundError as exc:
        raise RuntimeError(
            "meshtastic-python is required. Install it in your active Python environment first."
        ) from exc
    _patch_wireguard_module_config_copy(MeshInterface, mesh_pb2)
    return SerialInterface, TCPInterface, admin_pb2, config_pb2, module_config_pb2


def _patch_wireguard_module_config_copy(mesh_interface: Any, mesh_pb2: Any) -> None:
    if getattr(mesh_interface, "_wireguard_patch_applied", False):
        return

    original = mesh_interface._handleFromRadio

    def patched(self: Any, from_radio_bytes: Any) -> None:
        original(self, from_radio_bytes)
        fromRadio = mesh_pb2.FromRadio()
        fromRadio.ParseFromString(from_radio_bytes)
        if not fromRadio.HasField("moduleConfig") or not fromRadio.moduleConfig.HasField("wireguard"):
            return
        self.localNode.moduleConfig.wireguard.CopyFrom(fromRadio.moduleConfig.wireguard)

    mesh_interface._handleFromRadio = patched
    mesh_interface._wireguard_patch_applied = True


def _parse_tcp_target(host: str, tcp_port: int) -> tuple[str, int]:
    host = host.strip()
    if not host:
        raise SystemExit("TCP host is empty.")

    if host.startswith("["):
        end = host.find("]")
        if end == -1:
            raise SystemExit("IPv6 TCP hosts must use [host] or [host]:port syntax.")
        hostname = host[1:end]
        if len(host) > end + 1:
            if host[end + 1] != ":":
                raise SystemExit("IPv6 TCP hosts must use [host] or [host]:port syntax.")
            try:
                tcp_port = int(host[end + 2 :])
            except ValueError as exc:
                raise SystemExit(f"TCP port is not an integer: {host[end + 2 :]!r}") from exc
        host = hostname

    elif host.count(":") == 1:
        hostname, port_text = host.rsplit(":", 1)
        try:
            tcp_port = int(port_text)
        except ValueError as exc:
            raise SystemExit(f"TCP port is not an integer: {port_text!r}") from exc
        host = hostname

    if not host:
        raise SystemExit("TCP host is empty.")
    if tcp_port <= 0 or tcp_port > 65535:
        raise SystemExit(f"TCP port is out of range: {tcp_port}")
    return host, tcp_port


ProgressCallback = Callable[[str], None]
CancelEvent = Any
InterfaceCallback = Callable[[Any], None]
UNKNOWN_PROTO_PROFILE = "unknown"
DEFAULT_PROTO_PROFILE = "wireguard"
V28_PROTO_PROFILE = "2.8-wireguard-trial"


def _check_cancel(cancel_event: CancelEvent | None) -> None:
    if cancel_event is not None and cancel_event.is_set():
        raise RuntimeError("Operation cancelled.")


def _progress(progress: ProgressCallback | None, message: str) -> None:
    if progress:
        progress(message)


def _parse_version(value: str) -> tuple[int, int, int] | None:
    match = re.search(r"(\d+)\.(\d+)\.(\d+)", value)
    if not match:
        return None
    return tuple(int(part) for part in match.groups())


def _proto_profile_for_firmware(firmware_version: str) -> str:
    parsed = _parse_version(firmware_version)
    if parsed is None:
        return UNKNOWN_PROTO_PROFILE
    if parsed >= (2, 8, 0):
        return V28_PROTO_PROFILE
    return DEFAULT_PROTO_PROFILE


def _module_config_type_name(profile: str) -> str:
    return "WIREGUARD_CONFIG"


def _connect_tcp_socket(
    hostname: str,
    port_number: int,
    timeout: int,
    *,
    progress: ProgressCallback | None = None,
    cancel_event: CancelEvent | None = None,
) -> socket.socket:
    _progress(progress, f"Checking TCP API at {hostname}:{port_number}.")
    deadline = time.monotonic() + timeout
    errors: list[str] = []
    in_progress = {
        errno.EINPROGRESS,
        errno.EWOULDBLOCK,
        getattr(errno, "WSAEWOULDBLOCK", 10035),
        getattr(errno, "WSAEINPROGRESS", 10036),
        getattr(errno, "WSAEALREADY", 10037),
    }

    try:
        candidates = socket.getaddrinfo(hostname, port_number, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise RuntimeError(f"Unable to resolve Meshtastic TCP API host {hostname}: {exc}") from exc

    for family, socktype, proto, _, address in candidates:
        sock: socket.socket | None = None
        try:
            _check_cancel(cancel_event)
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            sock = socket.socket(family, socktype, proto)
            sock.setblocking(False)
            result = sock.connect_ex(address)
            if result == 0:
                sock.setblocking(True)
                sock.settimeout(timeout)
                return sock
            if result not in in_progress:
                raise OSError(result, errno.errorcode.get(result, "connect failed"))

            while True:
                _check_cancel(cancel_event)
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("timed out")
                _, writable, exceptional = select.select([], [sock], [sock], min(0.1, remaining))
                if exceptional:
                    raise OSError("socket exception during connect")
                if writable:
                    socket_error = sock.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
                    if socket_error:
                        raise OSError(socket_error, errno.errorcode.get(socket_error, "connect failed"))
                    sock.setblocking(True)
                    sock.settimeout(timeout)
                    return sock
        except OSError as exc:
            errors.append(str(exc))
            if sock is not None:
                sock.close()
        except Exception:
            if sock is not None:
                sock.close()
            raise

    detail = errors[-1] if errors else "timed out"
    raise RuntimeError(f"Unable to reach Meshtastic TCP API at {hostname}:{port_number}: {detail}")


def _patch_wait_connected(iface: Any, timeout: int, cancel_event: CancelEvent | None) -> None:
    def wait_connected(timeout_arg: float = 30.0) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            _check_cancel(cancel_event)
            if iface.isConnected.wait(0.1):
                break
        else:
            raise RuntimeError("Timed out waiting for connection completion.")
        if iface.failure:
            raise iface.failure

    iface._waitConnected = wait_connected


def _open_interface(
    port: str | None = None,
    *,
    host: str | None = None,
    tcp_port: int = 4403,
    timeout: int = 10,
    progress: ProgressCallback | None = None,
    cancel_event: CancelEvent | None = None,
    interface_callback: InterfaceCallback | None = None,
):
    if port and host:
        raise SystemExit("Use either --port for serial or --host for TCP, not both.")
    if host:
        hostname, port_number = _parse_tcp_target(host, tcp_port)
        _check_cancel(cancel_event)
        sock = _connect_tcp_socket(
            hostname,
            port_number,
            timeout,
            progress=progress,
            cancel_event=cancel_event,
        )
        _progress(progress, f"TCP port reachable: {hostname}:{port_number}")
        _progress(progress, "Loading Meshtastic API.")
        try:
            _, tcp_interface, _, _, _ = _import_meshtastic()
        except BaseException:
            sock.close()
            raise

        iface = tcp_interface(
            hostname=hostname,
            portNumber=port_number,
            timeout=timeout,
            noNodes=True,
            connectNow=False,
        )
        if interface_callback:
            interface_callback(iface)
        _check_cancel(cancel_event)
        _patch_wait_connected(iface, timeout, cancel_event)
        _progress(progress, "Starting Meshtastic API handshake.")
        iface.socket = sock
        iface.connect()
        _check_cancel(cancel_event)
        return iface
    if port:
        _progress(progress, "Loading Meshtastic API.")
        serial_interface, _, _, _, _ = _import_meshtastic()
        iface = serial_interface(devPath=port)
        if interface_callback:
            interface_callback(iface)
        return iface
    _progress(progress, "Loading Meshtastic API.")
    serial_interface, _, _, _, _ = _import_meshtastic()
    iface = serial_interface()
    if interface_callback:
        interface_callback(iface)
    return iface


def _admin_message():
    _, _, admin_pb2, _, _ = _import_meshtastic()
    return admin_pb2.AdminMessage()


def _new_wireguard_config():
    _, _, _, _, module_config_pb2 = _import_meshtastic()
    return module_config_pb2.ModuleConfig.WireGuardConfig()


def _new_network_config():
    _, _, _, config_pb2, _ = _import_meshtastic()
    return config_pb2.Config.NetworkConfig()


def _new_bluetooth_config():
    _, _, _, config_pb2, _ = _import_meshtastic()
    return config_pb2.Config.BluetoothConfig()


def _refresh_wireguard_config(
    node: Any,
    delay: float = 5.0,
    *,
    profile: str = DEFAULT_PROTO_PROFILE,
    progress: ProgressCallback | None = None,
    cancel_event: CancelEvent | None = None,
) -> None:
    _check_cancel(cancel_event)
    config = _wireguard_config(node)
    admin = _admin_message()
    admin.get_module_config_request = admin.ModuleConfigType.Value(_module_config_type_name(profile))
    received = Event()

    def on_response(packet: dict[str, Any]) -> None:
        try:
            raw_admin = packet["decoded"]["admin"]["raw"]
            config.CopyFrom(raw_admin.get_module_config_response.wireguard)
        finally:
            received.set()

    _progress(progress, "Sent WireGuard config read request.")
    node._sendAdmin(admin, wantResponse=True, onResponse=on_response)
    _progress(progress, "Waiting for device response.")
    if not received.wait(delay):
        _check_cancel(cancel_event)
        raise TimeoutError("Timed out waiting for WireGuard config response.")
    _check_cancel(cancel_event)
    _progress(progress, "Confirmed device response.")


def _read_device_metadata(
    node: Any,
    delay: float = 5.0,
    *,
    progress: ProgressCallback | None = None,
    cancel_event: CancelEvent | None = None,
) -> dict[str, str]:
    _check_cancel(cancel_event)
    admin = _admin_message()
    admin.get_device_metadata_request = True
    metadata: dict[str, str] = {}
    received = Event()

    def on_response(packet: dict[str, Any]) -> None:
        try:
            raw_admin = packet["decoded"]["admin"]["raw"]
            response = raw_admin.get_device_metadata_response
            metadata["firmware_version"] = getattr(response, "firmware_version", "")
        finally:
            received.set()

    _progress(progress, "Sent device metadata request.")
    node._sendAdmin(admin, wantResponse=True, onResponse=on_response)
    _progress(progress, "Waiting for device metadata.")
    if not received.wait(delay):
        _check_cancel(cancel_event)
        _progress(progress, "Device metadata request timed out; using legacy protobuf profile.")
        return {"firmware_version": "", "protobuf_profile": DEFAULT_PROTO_PROFILE}
    _check_cancel(cancel_event)
    firmware_version = metadata.get("firmware_version", "")
    profile = _proto_profile_for_firmware(firmware_version)
    if profile == V28_PROTO_PROFILE:
        _progress(progress, f"Detected Meshtastic {firmware_version}; using 2.8 WireGuard protobuf profile.")
    elif profile == DEFAULT_PROTO_PROFILE:
        _progress(progress, f"Detected Meshtastic {firmware_version}; using legacy WireGuard protobuf profile.")
    else:
        _progress(progress, "Unable to parse Meshtastic firmware version; using installed protobuf profile.")
    return {
        "firmware_version": firmware_version,
        "protobuf_profile": profile if profile != UNKNOWN_PROTO_PROFILE else DEFAULT_PROTO_PROFILE,
    }


def _wireguard_config(node: Any):
    try:
        return node.moduleConfig.wireguard
    except AttributeError as exc:
        raise RuntimeError(
            "This meshtastic-python protobuf package does not include ModuleConfig.wireguard. "
            "Regenerate/install the Python protobufs from this firmware branch."
        ) from exc


def _enum_name(value: int) -> str:
    try:
        from meshtastic.protobuf import module_config_pb2

        enum = module_config_pb2.ModuleConfig.WireGuardConfig.Status
        return enum.Name(value)
    except Exception:
        return str(value)


def _redact(value: str, show_secrets: bool) -> str:
    if show_secrets or not value:
        return value
    return SECRET


def _to_dict(config: Any, show_secrets: bool = False, metadata: dict[str, str] | None = None) -> dict[str, Any]:
    data = {
        "enabled": bool(config.enabled),
        "address": config.address,
        "server_addr": config.server_addr,
        "server_port": int(config.server_port),
        "private_key": _redact(config.private_key, show_secrets),
        "public_key": config.public_key,
        "preshared_key": _redact(config.preshared_key, show_secrets),
        "status": _enum_name(int(getattr(config, "status", 0))),
        "last_error": getattr(config, "last_error", ""),
    }
    if metadata:
        data.update(metadata)
    return data


def _network_to_dict(config: Any, metadata: dict[str, str] | None = None) -> dict[str, Any]:
    data = {
        "wifi_enabled": bool(getattr(config, "wifi_enabled", False)),
        "wifi_ssid": getattr(config, "wifi_ssid", ""),
        "wifi_psk": SECRET if getattr(config, "wifi_psk", "") else "",
        "ntp_server": getattr(config, "ntp_server", ""),
        "eth_enabled": bool(getattr(config, "eth_enabled", False)),
        "rsyslog_server": getattr(config, "rsyslog_server", ""),
        "ipv6_enabled": bool(getattr(config, "ipv6_enabled", False)),
        "address_mode": int(getattr(config, "address_mode", 0)),
    }
    if metadata:
        data.update(metadata)
    return data


def _bluetooth_to_dict(config: Any) -> dict[str, Any]:
    return {
        "bluetooth_enabled": bool(getattr(config, "enabled", False)),
        "bluetooth_mode": int(getattr(config, "mode", 0)),
        "bluetooth_fixed_pin": int(getattr(config, "fixed_pin", 0)),
    }


def _set_if_present(config: Any, field: str, value: Any) -> None:
    if value is not None:
        setattr(config, field, value)


def _refresh_network_config(
    node: Any,
    delay: float = 5.0,
    *,
    progress: ProgressCallback | None = None,
    cancel_event: CancelEvent | None = None,
) -> Any:
    _check_cancel(cancel_event)
    admin = _admin_message()
    admin.get_config_request = admin.ConfigType.Value("NETWORK_CONFIG")
    current = _new_network_config()
    received = Event()

    def on_response(packet: dict[str, Any]) -> None:
        try:
            raw_admin = packet["decoded"]["admin"]["raw"]
            current.CopyFrom(raw_admin.get_config_response.network)
        finally:
            received.set()

    _progress(progress, "Sent network config read request.")
    node._sendAdmin(admin, wantResponse=True, onResponse=on_response)
    _progress(progress, "Waiting for network config.")
    if not received.wait(delay):
        _check_cancel(cancel_event)
        raise TimeoutError("Timed out waiting for network config response.")
    _check_cancel(cancel_event)
    _progress(progress, "Confirmed network config response.")
    return current


def _refresh_bluetooth_config(
    node: Any,
    delay: float = 5.0,
    *,
    progress: ProgressCallback | None = None,
    cancel_event: CancelEvent | None = None,
) -> Any:
    _check_cancel(cancel_event)
    admin = _admin_message()
    admin.get_config_request = admin.ConfigType.Value("BLUETOOTH_CONFIG")
    current = _new_bluetooth_config()
    received = Event()

    def on_response(packet: dict[str, Any]) -> None:
        try:
            raw_admin = packet["decoded"]["admin"]["raw"]
            current.CopyFrom(raw_admin.get_config_response.bluetooth)
        finally:
            received.set()

    _progress(progress, "Sent Bluetooth config read request.")
    node._sendAdmin(admin, wantResponse=True, onResponse=on_response)
    _progress(progress, "Waiting for Bluetooth config.")
    if not received.wait(delay):
        _check_cancel(cancel_event)
        raise TimeoutError("Timed out waiting for Bluetooth config response.")
    _check_cancel(cancel_event)
    _progress(progress, "Confirmed Bluetooth config response.")
    return current


def _write_network_config(
    node: Any,
    current: Any,
    values: dict[str, Any],
    *,
    progress: ProgressCallback | None = None,
    cancel_event: CancelEvent | None = None,
) -> Any:
    _check_cancel(cancel_event)
    outgoing = _new_network_config()
    outgoing.CopyFrom(current)

    for field in ("wifi_enabled", "wifi_ssid", "ntp_server", "eth_enabled", "rsyslog_server", "ipv6_enabled"):
        if field in values:
            setattr(outgoing, field, values[field])
    if values.get("wifi_psk"):
        outgoing.wifi_psk = values["wifi_psk"]

    admin = _admin_message()
    admin.set_config.network.CopyFrom(outgoing)
    on_response = None if node == node.iface.localNode else node.onAckNak
    _progress(progress, "Sent network config write request.")
    node._sendAdmin(admin, onResponse=on_response)
    _progress(progress, "Waiting for network write to settle.")
    for _ in range(20):
        time.sleep(0.1)
        _check_cancel(cancel_event)
    return outgoing


def _write_bluetooth_config(
    node: Any,
    current: Any,
    *,
    bluetooth_enabled: bool | None,
    bluetooth_mode: int | None = None,
    bluetooth_fixed_pin: int | None = None,
    progress: ProgressCallback | None = None,
    cancel_event: CancelEvent | None = None,
) -> Any:
    _check_cancel(cancel_event)
    outgoing = _new_bluetooth_config()
    outgoing.CopyFrom(current)
    if bluetooth_enabled is not None:
        outgoing.enabled = bluetooth_enabled
    if bluetooth_mode is not None:
        outgoing.mode = bluetooth_mode
    if bluetooth_fixed_pin is not None:
        outgoing.fixed_pin = bluetooth_fixed_pin

    admin = _admin_message()
    admin.set_config.bluetooth.CopyFrom(outgoing)
    on_response = None if node == node.iface.localNode else node.onAckNak
    _progress(progress, "Sent Bluetooth config write request.")
    node._sendAdmin(admin, onResponse=on_response)
    _progress(progress, "Waiting for Bluetooth write to settle.")
    for _ in range(20):
        time.sleep(0.1)
        _check_cancel(cancel_event)
    return outgoing


def _strip_cidr(address: str) -> str:
    first_address = address.split(",", 1)[0].strip()
    if "/" in first_address:
        first_address = first_address.split("/", 1)[0].strip()
    if not first_address:
        raise SystemExit("WireGuard config Interface.Address is empty.")
    if ":" in first_address:
        raise SystemExit("This firmware currently supports IPv4 WireGuard client addresses only.")
    return first_address


def _parse_endpoint(endpoint: str) -> tuple[str, int]:
    endpoint = endpoint.strip()
    if not endpoint:
        raise SystemExit("WireGuard config Peer.Endpoint is empty.")

    if endpoint.startswith("["):
        end = endpoint.find("]")
        if end == -1 or len(endpoint) <= end + 2 or endpoint[end + 1] != ":":
            raise SystemExit("IPv6 endpoints must use [host]:port syntax.")
        host = endpoint[1:end]
        port_text = endpoint[end + 2 :]
    else:
        if endpoint.count(":") != 1:
            raise SystemExit("Endpoint must be host:port. Use [IPv6-address]:port for IPv6 endpoints.")
        host, port_text = endpoint.rsplit(":", 1)

    host = host.strip()
    if not host:
        raise SystemExit("WireGuard config Peer.Endpoint host is empty.")
    try:
        port = int(port_text)
    except ValueError as exc:
        raise SystemExit(f"WireGuard config Peer.Endpoint port is not an integer: {port_text!r}") from exc
    if port <= 0 or port > 65535:
        raise SystemExit(f"WireGuard config Peer.Endpoint port is out of range: {port}")
    return host, port


def _read_wireguard_config(path: str) -> dict[str, Any]:
    parser = configparser.ConfigParser(interpolation=None)
    parser.optionxform = str.lower
    try:
        with Path(path).open("r", encoding="utf-8") as config_file:
            parser.read_file(config_file)
    except configparser.DuplicateSectionError as exc:
        raise SystemExit("WireGuard configs with multiple [Peer] sections are not supported.") from exc
    except configparser.Error as exc:
        raise SystemExit(f"Unable to parse WireGuard config: {exc}") from exc
    except OSError as exc:
        raise SystemExit(f"Unable to read WireGuard config {path!r}: {exc}") from exc

    if "Interface" not in parser:
        raise SystemExit("WireGuard config is missing an [Interface] section.")
    if "Peer" not in parser:
        raise SystemExit("WireGuard config is missing a [Peer] section.")

    interface = parser["Interface"]
    peer = parser["Peer"]
    values: dict[str, Any] = {}

    if interface.get("address"):
        values["address"] = _strip_cidr(interface["address"])
    if interface.get("privatekey"):
        values["private_key"] = interface["privatekey"].strip()
    if peer.get("publickey"):
        values["public_key"] = peer["publickey"].strip()
    if peer.get("presharedkey"):
        values["preshared_key"] = peer["presharedkey"].strip()
    if peer.get("endpoint"):
        values["server_addr"], values["server_port"] = _parse_endpoint(peer["endpoint"])

    return values


def _apply_config_file_defaults(args: argparse.Namespace) -> None:
    if not getattr(args, "config", None):
        return

    for field, value in _read_wireguard_config(args.config).items():
        if getattr(args, field) is None:
            setattr(args, field, value)


def _write_config(
    node: Any,
    config: Any,
    args: argparse.Namespace,
    *,
    progress: ProgressCallback | None = None,
    cancel_event: CancelEvent | None = None,
) -> Any:
    _check_cancel(cancel_event)
    _apply_config_file_defaults(args)

    outgoing = _new_wireguard_config()
    outgoing.CopyFrom(config)

    if args.enable:
        outgoing.enabled = True
    if args.disable:
        outgoing.enabled = False

    _set_if_present(outgoing, "address", args.address)
    _set_if_present(outgoing, "server_addr", args.server_addr)
    _set_if_present(outgoing, "server_port", args.server_port)
    _set_if_present(outgoing, "private_key", args.private_key)
    _set_if_present(outgoing, "public_key", args.public_key)
    _set_if_present(outgoing, "preshared_key", args.preshared_key)
    outgoing.status = 0
    outgoing.last_error = ""

    admin = _admin_message()
    admin.set_module_config.wireguard.CopyFrom(outgoing)
    on_response = None if node == node.iface.localNode else node.onAckNak
    _progress(progress, "Sent WireGuard config write request.")
    node._sendAdmin(admin, onResponse=on_response)
    _progress(progress, "Waiting for write to settle.")
    for _ in range(20):
        time.sleep(0.1)
        _check_cancel(cancel_event)
    return outgoing


def read_wireguard_config(
    port: str | None = None,
    show_secrets: bool = False,
    *,
    host: str | None = None,
    tcp_port: int = 4403,
    timeout: int = 10,
    progress: ProgressCallback | None = None,
    cancel_event: CancelEvent | None = None,
    interface_callback: InterfaceCallback | None = None,
) -> dict[str, Any]:
    _progress(progress, "Opening device connection.")
    iface = _open_interface(
        port,
        host=host,
        tcp_port=tcp_port,
        timeout=timeout,
        progress=progress,
        cancel_event=cancel_event,
        interface_callback=interface_callback,
    )
    try:
        _progress(progress, "Connected to device.")
        metadata = _read_device_metadata(iface.localNode, progress=progress, cancel_event=cancel_event)
        _refresh_wireguard_config(
            iface.localNode,
            profile=metadata.get("protobuf_profile", DEFAULT_PROTO_PROFILE),
            progress=progress,
            cancel_event=cancel_event,
        )
        return _to_dict(_wireguard_config(iface.localNode), show_secrets, metadata)
    finally:
        iface.close()


def set_wireguard_config(
    port: str | None = None,
    config_path: str | None = None,
    *,
    host: str | None = None,
    tcp_port: int = 4403,
    timeout: int = 10,
    progress: ProgressCallback | None = None,
    cancel_event: CancelEvent | None = None,
    interface_callback: InterfaceCallback | None = None,
    enable: bool = False,
    disable: bool = False,
    show_secrets: bool = False,
    address: str | None = None,
    server_addr: str | None = None,
    server_port: int | None = None,
    private_key: str | None = None,
    public_key: str | None = None,
    preshared_key: str | None = None,
) -> dict[str, dict[str, Any]]:
    args = argparse.Namespace(
        config=config_path,
        enable=enable,
        disable=disable,
        show_secrets=show_secrets,
        address=address,
        server_addr=server_addr,
        server_port=server_port,
        private_key=private_key,
        public_key=public_key,
        preshared_key=preshared_key,
    )

    _progress(progress, "Opening device connection.")
    iface = _open_interface(
        port,
        host=host,
        tcp_port=tcp_port,
        timeout=timeout,
        progress=progress,
        cancel_event=cancel_event,
        interface_callback=interface_callback,
    )
    try:
        _progress(progress, "Connected to device.")
        node = iface.localNode
        metadata = _read_device_metadata(node, progress=progress, cancel_event=cancel_event)
        written = _write_config(node, _wireguard_config(node), args, progress=progress, cancel_event=cancel_event)
    finally:
        iface.close()

    _progress(progress, "Reading back saved config.")
    return {
        "written": _to_dict(written, show_secrets, metadata),
        "confirmed": read_wireguard_config(
            port,
            show_secrets,
            host=host,
            tcp_port=tcp_port,
            timeout=timeout,
            progress=progress,
            cancel_event=cancel_event,
            interface_callback=interface_callback,
        ),
    }


def read_network_config(
    port: str | None = None,
    *,
    host: str | None = None,
    tcp_port: int = 4403,
    timeout: int = 10,
    progress: ProgressCallback | None = None,
    cancel_event: CancelEvent | None = None,
    interface_callback: InterfaceCallback | None = None,
) -> dict[str, Any]:
    _progress(progress, "Opening device connection.")
    iface = _open_interface(
        port,
        host=host,
        tcp_port=tcp_port,
        timeout=timeout,
        progress=progress,
        cancel_event=cancel_event,
        interface_callback=interface_callback,
    )
    try:
        _progress(progress, "Connected to device.")
        metadata = _read_device_metadata(iface.localNode, progress=progress, cancel_event=cancel_event)
        network = _refresh_network_config(iface.localNode, progress=progress, cancel_event=cancel_event)
        bluetooth = _refresh_bluetooth_config(iface.localNode, progress=progress, cancel_event=cancel_event)
        data = _network_to_dict(network, metadata)
        data.update(_bluetooth_to_dict(bluetooth))
        return data
    finally:
        iface.close()


def set_network_config(
    port: str | None = None,
    *,
    host: str | None = None,
    tcp_port: int = 4403,
    timeout: int = 10,
    progress: ProgressCallback | None = None,
    cancel_event: CancelEvent | None = None,
    interface_callback: InterfaceCallback | None = None,
    wifi_enabled: bool | None = None,
    wifi_ssid: str | None = None,
    wifi_psk: str | None = None,
    ntp_server: str | None = None,
    eth_enabled: bool | None = None,
    rsyslog_server: str | None = None,
    ipv6_enabled: bool | None = None,
    bluetooth_enabled: bool | None = None,
    bluetooth_mode: int | None = None,
    bluetooth_fixed_pin: int | None = None,
    disable_bluetooth_first: bool = False,
    disable_wifi_first: bool = False,
) -> dict[str, dict[str, Any]]:
    values: dict[str, Any] = {}
    for field, value in {
        "wifi_enabled": wifi_enabled,
        "wifi_ssid": wifi_ssid,
        "wifi_psk": wifi_psk,
        "ntp_server": ntp_server,
        "eth_enabled": eth_enabled,
        "rsyslog_server": rsyslog_server,
        "ipv6_enabled": ipv6_enabled,
    }.items():
        if value is not None:
            values[field] = value

    _progress(progress, "Opening device connection.")
    iface = _open_interface(
        port,
        host=host,
        tcp_port=tcp_port,
        timeout=timeout,
        progress=progress,
        cancel_event=cancel_event,
        interface_callback=interface_callback,
    )
    try:
        _progress(progress, "Connected to device.")
        node = iface.localNode
        metadata = _read_device_metadata(node, progress=progress, cancel_event=cancel_event)
        current_network = _refresh_network_config(node, progress=progress, cancel_event=cancel_event)
        current_bluetooth = _refresh_bluetooth_config(node, progress=progress, cancel_event=cancel_event)
        written_network = current_network
        written_bluetooth = current_bluetooth
        if disable_bluetooth_first and bluetooth_enabled is False:
            written_bluetooth = _write_bluetooth_config(
                node,
                current_bluetooth,
                bluetooth_enabled=False,
                bluetooth_mode=bluetooth_mode,
                bluetooth_fixed_pin=bluetooth_fixed_pin,
                progress=progress,
                cancel_event=cancel_event,
            )
            current_bluetooth = written_bluetooth
        if disable_wifi_first and values.get("wifi_enabled") is False:
            written_network = _write_network_config(node, current_network, values, progress=progress, cancel_event=cancel_event)
            current_network = written_network
            values = {key: value for key, value in values.items() if key != "wifi_enabled"}
        if values:
            written_network = _write_network_config(node, current_network, values, progress=progress, cancel_event=cancel_event)
        if not (disable_bluetooth_first and bluetooth_enabled is False):
            written_bluetooth = _write_bluetooth_config(
                node,
                current_bluetooth,
                bluetooth_enabled=bluetooth_enabled,
                bluetooth_mode=bluetooth_mode,
                bluetooth_fixed_pin=bluetooth_fixed_pin,
                progress=progress,
                cancel_event=cancel_event,
            )
    finally:
        iface.close()

    _progress(progress, "Reading back saved network config.")
    written = _network_to_dict(written_network, metadata)
    written.update(_bluetooth_to_dict(written_bluetooth))
    return {
        "written": written,
        "confirmed": read_network_config(
            port,
            host=host,
            tcp_port=tcp_port,
            timeout=timeout,
            progress=progress,
            cancel_event=cancel_event,
            interface_callback=interface_callback,
        ),
    }


def do_get(args: argparse.Namespace) -> int:
    print(
        json.dumps(
            read_wireguard_config(
                args.port,
                args.show_secrets,
                host=args.host,
                tcp_port=args.tcp_port,
                timeout=args.timeout,
            ),
            indent=2,
        )
    )
    return 0


def do_set(args: argparse.Namespace) -> int:
    result = set_wireguard_config(
        args.port,
        args.config,
        host=args.host,
        tcp_port=args.tcp_port,
        timeout=args.timeout,
        enable=args.enable,
        disable=args.disable,
        show_secrets=args.show_secrets,
        address=args.address,
        server_addr=args.server_addr,
        server_port=args.server_port,
        private_key=args.private_key,
        public_key=args.public_key,
        preshared_key=args.preshared_key,
    )
    print(json.dumps(result["written"], indent=2))
    return 0


def do_disable(args: argparse.Namespace) -> int:
    args.enable = False
    args.disable = True
    args.address = None
    args.server_addr = None
    args.server_port = None
    args.private_key = None
    args.public_key = None
    args.preshared_key = None
    return do_set(args)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    transport = parser.add_mutually_exclusive_group()
    transport.add_argument("--port", help="Serial device path. Omit transport options for serial auto-detection.")
    transport.add_argument("--host", help="Meshtastic TCP API host or host:port.")
    parser.add_argument("--tcp-port", type=int, default=4403, help="Meshtastic TCP API port when --host has no port.")
    parser.add_argument("--timeout", type=int, default=10, help="TCP connection and readback timeout in seconds.")
    parser.add_argument("--show-secrets", action="store_true", help="Print private and preshared keys in command output.")

    subparsers = parser.add_subparsers(dest="command", required=True)

    get_parser = subparsers.add_parser("get", help="Read WireGuard configuration and runtime status.")
    get_parser.set_defaults(func=do_get)

    set_parser = subparsers.add_parser("set", help="Set one or more WireGuard configuration fields.")
    enabled = set_parser.add_mutually_exclusive_group()
    enabled.add_argument("--enable", action="store_true", help="Enable automatic tunnel startup.")
    enabled.add_argument("--disable", action="store_true", help="Disable automatic tunnel startup.")
    set_parser.add_argument("--config", help="Read settings from a standard WireGuard .conf file.")
    set_parser.add_argument("--address", help="Client tunnel IPv4 address, without subnet mask.")
    set_parser.add_argument("--server-addr", help="WireGuard server hostname or IP address.")
    set_parser.add_argument("--server-port", type=int, help="WireGuard server UDP port.")
    set_parser.add_argument("--private-key", help=f"Client private key. Use {SECRET!r} to preserve the current value.")
    set_parser.add_argument("--public-key", help="Server public key.")
    set_parser.add_argument("--preshared-key", help=f"Optional preshared key. Use {SECRET!r} to preserve the current value.")
    set_parser.set_defaults(func=do_set)

    disable_parser = subparsers.add_parser("disable", help="Disable automatic WireGuard startup.")
    disable_parser.set_defaults(func=do_disable)

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    try:
        return args.func(args)
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
