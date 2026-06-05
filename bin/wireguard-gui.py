#!/usr/bin/env python3
"""Simple desktop client for Meshtastic WireGuard configuration."""

from __future__ import annotations

import importlib.util
import ipaddress
import json
import queue
import subprocess
import sys
import threading
import time
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from typing import Any, Callable


SCRIPT_DIR = Path(__file__).resolve().parent
BUNDLE_DIR = Path(getattr(sys, "_MEIPASS", SCRIPT_DIR))
CONFIG_SCRIPT = BUNDLE_DIR / "wireguard-config.py"
APP_BUILD = "proto28trial2"


def _load_config_api():
    spec = importlib.util.spec_from_file_location("wireguard_config", CONFIG_SCRIPT)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load {CONFIG_SCRIPT}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


wg_api = _load_config_api()


class WireGuardClient(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("Meshtastic WireGuard")
        self.minsize(760, 560)

        self._events: queue.Queue[tuple[str, Any]] = queue.Queue()
        self._monitoring = False
        self._monitor_interval = 10.0
        self._monitor_job: str | None = None
        self._busy = False
        self._operation_id = 0
        self._cancel_event: threading.Event | None = None
        self._active_iface: Any | None = None
        self._last_success_at: float | None = None
        self._health = {
            "connected": False,
            "polls": 0,
            "failures": 0,
            "rx_bytes": 0,
            "tx_bytes": 0,
        }

        self._build_vars()
        self._build_ui()
        self._log(f"App build {APP_BUILD}.")
        self._refresh_ports()
        self.after(100, self._drain_events)

    def _build_vars(self) -> None:
        self.transport_var = tk.StringVar(value="serial")
        self.port_var = tk.StringVar()
        self.host_var = tk.StringVar()
        self.tcp_port_var = tk.StringVar(value="4403")
        self.config_path_var = tk.StringVar()
        self.status_var = tk.StringVar(value="Idle")
        self.connection_var = tk.StringVar(value="Disconnected")
        self.wg_status_var = tk.StringVar(value="-")
        self.firmware_var = tk.StringVar(value="-")
        self.proto_profile_var = tk.StringVar(value="-")
        self.endpoint_var = tk.StringVar(value="-")
        self.address_var = tk.StringVar(value="-")
        self.last_error_var = tk.StringVar(value="-")
        self.last_read_var = tk.StringVar(value="-")
        self.rx_var = tk.StringVar(value="0")
        self.tx_var = tk.StringVar(value="0")
        self.polls_var = tk.StringVar(value="0")
        self.failures_var = tk.StringVar(value="0")

    def _build_ui(self) -> None:
        root = ttk.Frame(self, padding=16)
        root.grid(row=0, column=0, sticky="nsew")
        self.columnconfigure(0, weight=1)
        self.rowconfigure(0, weight=1)
        root.columnconfigure(1, weight=1)
        root.rowconfigure(6, weight=1)

        ttk.Label(root, text="Connection").grid(row=0, column=0, sticky="w")
        mode_row = ttk.Frame(root)
        mode_row.grid(row=0, column=1, sticky="ew", padx=(8, 0))
        ttk.Radiobutton(mode_row, text="Serial", value="serial", variable=self.transport_var).grid(row=0, column=0)
        ttk.Radiobutton(mode_row, text="Network", value="tcp", variable=self.transport_var).grid(row=0, column=1, padx=(10, 0))

        ttk.Label(root, text="Port").grid(row=1, column=0, sticky="w", pady=(10, 0))
        port_row = ttk.Frame(root)
        port_row.grid(row=1, column=1, sticky="ew", padx=(8, 0), pady=(10, 0))
        port_row.columnconfigure(0, weight=1)
        self.port_combo = ttk.Combobox(port_row, textvariable=self.port_var, state="readonly")
        self.port_combo.grid(row=0, column=0, sticky="ew")
        ttk.Button(port_row, text="Refresh", command=self._refresh_ports).grid(row=0, column=1, padx=(8, 0))

        ttk.Label(root, text="Network").grid(row=2, column=0, sticky="w", pady=(10, 0))
        network_row = ttk.Frame(root)
        network_row.grid(row=2, column=1, sticky="ew", padx=(8, 0), pady=(10, 0))
        network_row.columnconfigure(0, weight=1)
        ttk.Entry(network_row, textvariable=self.host_var).grid(row=0, column=0, sticky="ew")
        ttk.Label(network_row, text="TCP").grid(row=0, column=1, padx=(8, 4))
        ttk.Entry(network_row, width=8, textvariable=self.tcp_port_var).grid(row=0, column=2)

        ttk.Label(root, text="Config").grid(row=3, column=0, sticky="w", pady=(10, 0))
        config_row = ttk.Frame(root)
        config_row.grid(row=3, column=1, sticky="ew", padx=(8, 0), pady=(10, 0))
        config_row.columnconfigure(0, weight=1)
        ttk.Entry(config_row, textvariable=self.config_path_var).grid(row=0, column=0, sticky="ew")
        ttk.Button(config_row, text="Browse", command=self._browse_config).grid(row=0, column=1, padx=(8, 0))

        actions = ttk.Frame(root)
        actions.grid(row=4, column=1, sticky="ew", padx=(8, 0), pady=(12, 0))
        ttk.Button(actions, text="Push Config", command=self._push_config).grid(row=0, column=0)
        ttk.Button(actions, text="Read Device", command=self._read_device).grid(row=0, column=1, padx=(8, 0))
        self.monitor_button = ttk.Button(actions, text="Start Monitor", command=self._toggle_monitor)
        self.monitor_button.grid(row=0, column=2, padx=(8, 0))
        self.cancel_button = ttk.Button(actions, text="Cancel", command=self._cancel_operation, state="disabled")
        self.cancel_button.grid(row=0, column=3, padx=(8, 0))
        ttk.Button(actions, text="Clear", command=self._clear_profile).grid(row=0, column=4, padx=(8, 0))
        ttk.Label(actions, textvariable=self.status_var).grid(row=0, column=5, padx=(14, 0), sticky="w")

        health = ttk.LabelFrame(root, text="Health", padding=12)
        health.grid(row=5, column=0, columnspan=2, sticky="ew", pady=(16, 0))
        for col in range(4):
            health.columnconfigure(col, weight=1)

        self._metric(health, 0, 0, "Connection", self.connection_var)
        self._metric(health, 0, 1, "WireGuard", self.wg_status_var)
        self._metric(health, 0, 2, "Last Read", self.last_read_var)
        self._metric(health, 0, 3, "Failures", self.failures_var)
        self._metric(health, 1, 0, "Address", self.address_var)
        self._metric(health, 1, 1, "Endpoint", self.endpoint_var)
        self._metric(health, 1, 2, "RX bytes est.", self.rx_var)
        self._metric(health, 1, 3, "TX bytes est.", self.tx_var)
        self._metric(health, 2, 0, "Polls", self.polls_var)
        self._metric(health, 2, 1, "Last Error", self.last_error_var)
        self._metric(health, 2, 2, "Firmware", self.firmware_var)
        self._metric(health, 2, 3, "Proto Profile", self.proto_profile_var)

        log_frame = ttk.LabelFrame(root, text="Log", padding=8)
        log_frame.grid(row=6, column=0, columnspan=2, sticky="nsew", pady=(16, 0))
        log_frame.columnconfigure(0, weight=1)
        log_frame.rowconfigure(0, weight=1)
        self.log = tk.Text(log_frame, height=12, wrap="word", state="disabled")
        self.log.grid(row=0, column=0, sticky="nsew")
        scrollbar = ttk.Scrollbar(log_frame, orient="vertical", command=self.log.yview)
        scrollbar.grid(row=0, column=1, sticky="ns")
        self.log.configure(yscrollcommand=scrollbar.set)
        self.after(1000, self._tick_last_read)

    def _metric(self, parent: ttk.Frame, row: int, col: int, label: str, var: tk.StringVar) -> None:
        frame = ttk.Frame(parent)
        frame.grid(row=row, column=col, sticky="ew", padx=6, pady=5)
        ttk.Label(frame, text=label).grid(row=0, column=0, sticky="w")
        ttk.Label(frame, textvariable=var, font=("", 10, "bold")).grid(row=1, column=0, sticky="w")

    def _refresh_ports(self) -> None:
        try:
            ports = wg_api.list_serial_ports()
        except Exception as exc:
            self._log(f"Port refresh failed: {exc}")
            return

        values = [f"{port['device']} - {port['description']}" for port in ports]
        self.port_combo.configure(values=values)
        if values and not self.port_var.get():
            self.port_var.set(values[0])
        self._log(f"Found {len(values)} serial port(s).")

    def _browse_config(self) -> None:
        filename = filedialog.askopenfilename(
            title="Select WireGuard config",
            filetypes=[("WireGuard config", "*.conf"), ("All files", "*.*")],
        )
        if filename:
            self.config_path_var.set(filename)

    def _selected_port(self) -> str:
        value = self.port_var.get().strip()
        return value.split(" - ", 1)[0] if value else ""

    def _clear_health(self, *, reset_failures: bool = True) -> None:
        self._last_success_at = None
        self._health["connected"] = False
        self._health["polls"] = 0
        self._health["rx_bytes"] = 0
        self._health["tx_bytes"] = 0
        if reset_failures:
            self._health["failures"] = 0
        self.connection_var.set("Disconnected")
        self.wg_status_var.set("-")
        self.firmware_var.set("-")
        self.proto_profile_var.set("-")
        self.address_var.set("-")
        self.endpoint_var.set("-")
        self.last_error_var.set("-")
        self._sync_health()

    def _clear_profile(self) -> None:
        if self._busy:
            self._cancel_operation()
        self.config_path_var.set("")
        self.host_var.set("")
        self.tcp_port_var.set("4403")
        self.status_var.set("Idle")
        self._clear_health()
        self._log("Cleared current profile and status.")

    def _connection_kwargs(self) -> dict[str, Any]:
        if self.transport_var.get() == "tcp":
            host = self.host_var.get().strip()
            if not host:
                raise ValueError("Enter a network host or IP address.")
            try:
                tcp_port = int(self.tcp_port_var.get().strip() or "4403")
            except ValueError as exc:
                raise ValueError("TCP port must be a number.") from exc
            if tcp_port <= 0 or tcp_port > 65535:
                raise ValueError("TCP port must be between 1 and 65535.")
            try:
                target_host, _ = wg_api._parse_tcp_target(host, tcp_port)
            except BaseException as exc:
                raise ValueError(str(exc)) from exc
            if all(char.isdigit() or char == "." for char in target_host):
                try:
                    ipaddress.ip_address(target_host)
                except ValueError as exc:
                    raise ValueError("Network host looks like an incomplete or invalid IP address.") from exc
            return {"port": None, "host": host, "tcp_port": tcp_port, "timeout": 5}

        port = self._selected_port()
        if not port:
            raise ValueError("Select a serial port.")
        return {"port": port}

    def _set_active_iface(self, op_id: int, iface: Any) -> None:
        if op_id == self._operation_id:
            self._active_iface = iface

    def _cancel_operation(self) -> None:
        if not self._busy:
            return
        self._operation_id += 1
        if self._cancel_event:
            self._cancel_event.set()
        if self._active_iface:
            try:
                self._active_iface.close()
            except Exception:
                pass
        self._active_iface = None
        self._busy = False
        self.cancel_button.configure(state="disabled")
        self.status_var.set("Cancelled")
        self._log("Cancelled current operation. Any late response from that worker will be ignored.")

    def _status_callback(self, op_id: int) -> Callable[[str], None]:
        return lambda message: self._events.put(("status", (op_id, message)))

    def _ping_host(self, host: str, tcp_port: int, status: Callable[[str], None]) -> None:
        target_host, _ = wg_api._parse_tcp_target(host, tcp_port)
        status(f"Pinging {target_host}...")
        if sys.platform == "win32":
            command = ["ping", "-n", "1", "-w", "1000", target_host]
        else:
            command = ["ping", "-c", "1", "-W", "1", target_host]
        result = subprocess.run(command, capture_output=True, text=True)
        if result.returncode == 0:
            status(f"Ping successful: {target_host}")
        else:
            status(f"Ping failed for {target_host}; trying TCP anyway.")

    def _run_worker(self, name: str, connection: dict[str, Any], target: Callable[[threading.Event, Callable[[str], None], Callable[[Any], None]], Any]) -> None:
        if self._busy:
            self._log("Another device operation is already running.")
            return
        self._operation_id += 1
        op_id = self._operation_id
        cancel_event = threading.Event()
        self._cancel_event = cancel_event
        self._active_iface = None
        self._busy = True
        self._clear_health()
        self.status_var.set(name)
        self.cancel_button.configure(state="normal")

        def runner() -> None:
            status = self._status_callback(op_id)
            try:
                if connection.get("host"):
                    self._ping_host(connection["host"], int(connection.get("tcp_port", 4403)), status)
                if cancel_event.is_set():
                    self._events.put(("cancelled", (op_id, name)))
                    return
                self._events.put(("result", (op_id, name, target(cancel_event, status, lambda iface: self._set_active_iface(op_id, iface)))))
            except BaseException as exc:
                if cancel_event.is_set():
                    self._events.put(("cancelled", (op_id, name)))
                else:
                    self._events.put(("error", (op_id, name, exc)))

        threading.Thread(target=runner, daemon=True).start()

    def _push_config(self) -> None:
        config_path = self.config_path_var.get().strip()
        if not config_path:
            messagebox.showerror("Missing Config", "Select a WireGuard config file.")
            return
        try:
            connection = self._connection_kwargs()
        except ValueError as exc:
            messagebox.showerror("Missing Connection", str(exc))
            return

        self._run_worker(
            "Pushing config...",
            connection,
            lambda cancel, status, iface_cb: wg_api.set_wireguard_config(
                config_path=config_path,
                enable=True,
                progress=status,
                cancel_event=cancel,
                interface_callback=iface_cb,
                **connection,
            ),
        )
        self._health["tx_bytes"] += Path(config_path).stat().st_size
        self._sync_health()

    def _read_device(self) -> None:
        try:
            connection = self._connection_kwargs()
        except ValueError as exc:
            messagebox.showerror("Missing Connection", str(exc))
            return

        self._run_worker(
            "Reading device...",
            connection,
            lambda cancel, status, iface_cb: wg_api.read_wireguard_config(
                progress=status,
                cancel_event=cancel,
                interface_callback=iface_cb,
                **connection,
            ),
        )
        self._health["tx_bytes"] += 64
        self._sync_health()

    def _toggle_monitor(self) -> None:
        self._monitoring = not self._monitoring
        self.monitor_button.configure(text="Stop Monitor" if self._monitoring else "Start Monitor")
        if self._monitoring:
            self._schedule_monitor(0)
        elif self._monitor_job:
            self.after_cancel(self._monitor_job)
            self._monitor_job = None

    def _schedule_monitor(self, delay_ms: int | None = None) -> None:
        if not self._monitoring:
            return
        delay = int(self._monitor_interval * 1000) if delay_ms is None else delay_ms
        self._monitor_job = self.after(delay, self._monitor_tick)

    def _monitor_tick(self) -> None:
        self._monitor_job = None
        if self._busy:
            self._schedule_monitor()
            return
        try:
            connection = self._connection_kwargs()
        except ValueError:
            self._schedule_monitor()
            return
        self._run_worker(
            "Polling health...",
            connection,
            lambda cancel, status, iface_cb: wg_api.read_wireguard_config(
                progress=status,
                cancel_event=cancel,
                interface_callback=iface_cb,
                **connection,
            ),
        )
        self._health["tx_bytes"] += 64
        self._sync_health()
        self._schedule_monitor()

    def _drain_events(self) -> None:
        while True:
            try:
                event, payload = self._events.get_nowait()
            except queue.Empty:
                break
            if event == "result":
                self._handle_result(*payload)
            elif event == "error":
                self._handle_error(*payload)
            elif event == "status":
                self._handle_status(*payload)
            elif event == "cancelled":
                self._handle_cancelled(*payload)
        self.after(100, self._drain_events)

    def _operation_is_current(self, op_id: int) -> bool:
        return op_id == self._operation_id

    def _finish_operation(self) -> None:
        self._busy = False
        self._active_iface = None
        self._cancel_event = None
        self.cancel_button.configure(state="disabled")
        self.status_var.set("Idle")

    def _handle_status(self, op_id: int, message: str) -> None:
        if not self._operation_is_current(op_id):
            return
        self.status_var.set(message)
        self._log(message)

    def _handle_cancelled(self, op_id: int, name: str) -> None:
        if not self._operation_is_current(op_id):
            return
        self._finish_operation()
        self.status_var.set("Cancelled")
        self._log(f"{name} cancelled.")

    def _handle_result(self, op_id: int, name: str, payload: Any) -> None:
        if not self._operation_is_current(op_id):
            return
        self._finish_operation()
        if isinstance(payload, dict) and "confirmed" in payload:
            self._log_json("Written", payload["written"])
            self._log_json("Confirmed", payload["confirmed"])
            self._update_config_status(payload["confirmed"])
        else:
            self._log_json(name, payload)
            self._update_config_status(payload)

    def _handle_error(self, op_id: int, name: str, exc: Exception) -> None:
        if not self._operation_is_current(op_id):
            return
        self._finish_operation()
        self.status_var.set("Failed")
        self._health["connected"] = False
        self._health["failures"] += 1
        self.connection_var.set("Disconnected")
        self.failures_var.set(str(self._health["failures"]))
        self._log(f"{name} failed: {exc}")

    def _update_config_status(self, config: dict[str, Any]) -> None:
        self._health["connected"] = True
        self._health["polls"] += 1
        self._last_success_at = time.monotonic()
        self._health["rx_bytes"] += len(json.dumps(config))

        self.connection_var.set("Connected")
        self.wg_status_var.set(str(config.get("status", "-")))
        self.firmware_var.set(str(config.get("firmware_version", "-") or "-"))
        self.proto_profile_var.set(str(config.get("protobuf_profile", "-") or "-"))
        self.address_var.set(str(config.get("address", "-")) or "-")
        server = str(config.get("server_addr", "") or "")
        port = str(config.get("server_port", "") or "")
        self.endpoint_var.set(f"{server}:{port}" if server and port else "-")
        self.last_error_var.set(str(config.get("last_error", "") or "-"))
        self._sync_health()

    def _sync_health(self) -> None:
        self.last_read_var.set(self._format_last_read())
        self.rx_var.set(str(self._health["rx_bytes"]))
        self.tx_var.set(str(self._health["tx_bytes"]))
        self.polls_var.set(str(self._health["polls"]))
        self.failures_var.set(str(self._health["failures"]))

    def _format_last_read(self) -> str:
        if self._last_success_at is None:
            return "-"
        age = max(0, int(time.monotonic() - self._last_success_at))
        if age < 2:
            return "just now"
        if age < 60:
            return f"{age}s ago"
        minutes = age // 60
        if minutes < 60:
            return f"{minutes}m ago"
        hours = minutes // 60
        minutes = minutes % 60
        return f"{hours}h {minutes}m ago"

    def _tick_last_read(self) -> None:
        self.last_read_var.set(self._format_last_read())
        self.after(1000, self._tick_last_read)

    def _log_json(self, title: str, payload: Any) -> None:
        self._log(f"{title}:\n{json.dumps(payload, indent=2)}")

    def _log(self, message: str) -> None:
        timestamp = time.strftime("%H:%M:%S")
        self.log.configure(state="normal")
        self.log.insert("end", f"[{timestamp}] {message}\n")
        self.log.see("end")
        self.log.configure(state="disabled")


def main() -> None:
    app = WireGuardClient()
    app.mainloop()


if __name__ == "__main__":
    main()
