#!/usr/bin/env python3
"""Simple desktop client for Meshtastic WireGuard configuration."""

from __future__ import annotations

import importlib.util
import ipaddress
import json
import ctypes
import queue
import re
import subprocess
import sys
import threading
import time
import tkinter as tk
import urllib.error
import urllib.request
import webbrowser
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from typing import Any, Callable


SCRIPT_DIR = Path(__file__).resolve().parent
BUNDLE_DIR = Path(getattr(sys, "_MEIPASS", SCRIPT_DIR))
CONFIG_SCRIPT = BUNDLE_DIR / "wireguard-config.py"
ASSET_DIR = BUNDLE_DIR / "assets" if (BUNDLE_DIR / "assets").exists() else SCRIPT_DIR.parent / "assets"
LOGO_PATH = ASSET_DIR / "zoomnet-logo.png"
APP_VERSION = "0.4.0"
APP_BUILD = "networktab4"
RELEASES_API_URL = "https://api.github.com/repos/TheWISPRer/Meshtastic-Wireguard-Configurator/releases/latest"
HTTP_TIMEOUT_SECONDS = 8
DOWNLOAD_TIMEOUT_SECONDS = 60

COLOR_BG = "#071018"
COLOR_PANEL = "#0d1824"
COLOR_PANEL_2 = "#111f2d"
COLOR_BORDER = "#1d3b50"
COLOR_ACCENT = "#25a8e0"
COLOR_ACCENT_DARK = "#1279a8"
COLOR_ACCENT_SOFT = "#16475c"
COLOR_TEXT = "#edf7fb"
COLOR_MUTED = "#8aa8b7"
COLOR_DANGER = "#f25f5c"


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
        self.title("ZoomNet WireGuard Configurator")
        self.minsize(920, 540)
        self.configure(bg=COLOR_BG)

        self._events: queue.Queue[tuple[str, Any]] = queue.Queue()
        self._monitoring = False
        self._monitor_interval = 10.0
        self._monitor_job: str | None = None
        self._busy = False
        self._operation_id = 0
        self._cancel_event: threading.Event | None = None
        self._active_iface: Any | None = None
        self._latest_release: dict[str, Any] | None = None
        self._latest_release_asset: dict[str, Any] | None = None
        self._logo_image: tk.PhotoImage | None = None
        self._icon_image: tk.PhotoImage | None = None
        self._log_visible = False
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
        self._log(f"App version {APP_VERSION} build {APP_BUILD}.")
        self._refresh_ports()
        self.after(100, self._drain_events)
        self.after(500, self._check_for_updates)

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
        self.update_notice_var = tk.StringVar(value="")
        self.network_wifi_enabled_var = tk.BooleanVar(value=False)
        self.network_wifi_ssid_var = tk.StringVar()
        self.network_wifi_psk_var = tk.StringVar()
        self.network_ntp_server_var = tk.StringVar()
        self.network_eth_enabled_var = tk.BooleanVar(value=False)
        self.network_ipv6_enabled_var = tk.BooleanVar(value=False)
        self.network_bluetooth_enabled_var = tk.BooleanVar(value=False)
        self.network_rsyslog_server_var = tk.StringVar()
        self.network_address_mode_var = tk.StringVar(value="-")
        self.network_firmware_var = tk.StringVar(value="-")
        self.network_status_var = tk.StringVar(value="Not loaded")
        self.wg_note_var = tk.StringVar(value="Each node needs its own unique WireGuard configuration.")

    def _build_ui(self) -> None:
        self._configure_style()

        root = ttk.Frame(self, padding=18, style="App.TFrame")
        root.grid(row=0, column=0, sticky="nsew")
        self.columnconfigure(0, weight=1)
        self.rowconfigure(0, weight=1)
        root.columnconfigure(0, weight=1)
        root.rowconfigure(5, weight=0)
        self.after(50, self._apply_window_chrome)
        self.after(500, self._apply_window_chrome)
        self.bind("<Map>", lambda _event: self.after(50, self._apply_window_chrome), add="+")
        self.bind("<FocusIn>", lambda _event: self.after(50, self._apply_window_chrome), add="+")

        header = ttk.Frame(root, padding=(14, 14), style="Header.TFrame")
        header.grid(row=0, column=0, sticky="ew")
        header.columnconfigure(1, weight=1)
        self._logo_image = self._load_logo_image()
        if self._logo_image:
            tk.Label(header, image=self._logo_image, bg=COLOR_PANEL, bd=0).grid(row=0, column=0, rowspan=2, padx=(0, 14))
        ttk.Label(header, text="ZoomNet WireGuard Configurator", style="Title.TLabel").grid(row=0, column=1, sticky="w")
        ttk.Label(
            header,
            text="Meshtastic tunnel provisioning, health checks, and 2.8 protobuf trial support",
            style="Subtitle.TLabel",
        ).grid(row=1, column=1, sticky="w", pady=(3, 0))
        ttk.Label(header, text=f"v{APP_VERSION} / {APP_BUILD}", style="Pill.TLabel").grid(row=0, column=2, sticky="ne")

        self.update_frame = ttk.Frame(root)
        self.update_frame.grid(row=1, column=0, sticky="ew", pady=(12, 0))
        self.update_frame.columnconfigure(0, weight=1)
        self.update_frame.configure(style="Update.TFrame", padding=10)
        ttk.Label(self.update_frame, textvariable=self.update_notice_var, style="Update.TLabel").grid(row=0, column=0, sticky="w")
        ttk.Button(self.update_frame, text="Download", command=self._download_update, style="Accent.TButton").grid(row=0, column=1, padx=(8, 0))
        ttk.Button(self.update_frame, text="Release Notes", command=self._open_update_release, style="Ghost.TButton").grid(row=0, column=2, padx=(8, 0))
        ttk.Button(self.update_frame, text="Dismiss", command=self._dismiss_update, style="Ghost.TButton").grid(row=0, column=3, padx=(8, 0))
        self.update_frame.grid_remove()

        nav = ttk.Frame(root, padding=(0, 2), style="App.TFrame")
        nav.grid(row=2, column=0, sticky="ew", pady=(12, 0))
        self.wireguard_nav_button = ttk.Button(nav, text="WireGuard", command=lambda: self._show_page("wireguard"), style="NavActive.TButton")
        self.wireguard_nav_button.grid(row=0, column=0)
        self.network_nav_button = ttk.Button(nav, text="Network", command=lambda: self._show_page("network"), style="Nav.TButton")
        self.network_nav_button.grid(row=0, column=1, padx=(8, 0))

        _, connection = self._section(root, "Device Link", row=3)
        connection.columnconfigure(1, weight=1)
        connection.columnconfigure(3, weight=1)

        ttk.Label(connection, text="Connection", style="FieldLabel.TLabel").grid(row=0, column=0, sticky="w")
        mode_row = ttk.Frame(connection, style="Card.TFrame")
        mode_row.grid(row=0, column=1, sticky="w", padx=(10, 18))
        ttk.Radiobutton(mode_row, text="Serial", value="serial", variable=self.transport_var).grid(row=0, column=0)
        ttk.Radiobutton(mode_row, text="Network", value="tcp", variable=self.transport_var).grid(row=0, column=1, padx=(10, 0))

        ttk.Label(connection, text="Port", style="FieldLabel.TLabel").grid(row=1, column=0, sticky="w", pady=(12, 0))
        port_row = ttk.Frame(connection, style="Card.TFrame")
        port_row.grid(row=1, column=1, sticky="ew", padx=(10, 18), pady=(12, 0))
        port_row.columnconfigure(0, weight=1)
        self.port_combo = ttk.Combobox(port_row, textvariable=self.port_var, state="readonly")
        self.port_combo.grid(row=0, column=0, sticky="ew")
        ttk.Button(port_row, text="Refresh", command=self._refresh_ports, style="Ghost.TButton").grid(row=0, column=1, padx=(8, 0))

        ttk.Label(connection, text="Network", style="FieldLabel.TLabel").grid(row=0, column=2, sticky="w", padx=(8, 0))
        network_row = ttk.Frame(connection, style="Card.TFrame")
        network_row.grid(row=0, column=3, sticky="ew", padx=(10, 0))
        network_row.columnconfigure(0, weight=1)
        ttk.Entry(network_row, textvariable=self.host_var).grid(row=0, column=0, sticky="ew")
        ttk.Label(network_row, text="TCP", style="Muted.TLabel").grid(row=0, column=1, padx=(8, 4))
        ttk.Entry(network_row, width=8, textvariable=self.tcp_port_var).grid(row=0, column=2)

        self.page_container = ttk.Frame(root, style="App.TFrame")
        self.page_container.grid(row=4, column=0, sticky="nsew", pady=(12, 0))
        self.page_container.columnconfigure(0, weight=1)
        self.wireguard_page = ttk.Frame(self.page_container, style="App.TFrame")
        self.network_page = ttk.Frame(self.page_container, style="App.TFrame")
        for page in (self.wireguard_page, self.network_page):
            page.grid(row=0, column=0, sticky="nsew")
            page.columnconfigure(0, weight=1)

        actions = ttk.Frame(self.wireguard_page)
        actions.configure(style="App.TFrame")
        actions.grid(row=0, column=0, sticky="ew")
        ttk.Button(actions, text="Push Config", command=self._push_config, style="Accent.TButton").grid(row=0, column=0)
        ttk.Button(actions, text="Read Device", command=self._read_device, style="Ghost.TButton").grid(row=0, column=1, padx=(8, 0))
        self.monitor_button = ttk.Button(actions, text="Start Monitor", command=self._toggle_monitor, style="Ghost.TButton")
        self.monitor_button.grid(row=0, column=2, padx=(8, 0))
        self.cancel_button = ttk.Button(actions, text="Cancel", command=self._cancel_operation, state="disabled", style="Danger.TButton")
        self.cancel_button.grid(row=0, column=3, padx=(8, 0))
        ttk.Button(actions, text="Clear", command=self._clear_profile, style="Ghost.TButton").grid(row=0, column=4, padx=(8, 0))
        self.log_toggle_button = ttk.Button(actions, text="Show Log", command=self._toggle_log, style="Ghost.TButton")
        self.log_toggle_button.grid(row=0, column=5, padx=(8, 0))
        ttk.Label(actions, textvariable=self.status_var, style="Status.TLabel").grid(row=0, column=6, padx=(14, 0), sticky="w")

        ttk.Label(self.wireguard_page, textvariable=self.wg_note_var, style="Hint.TLabel").grid(row=1, column=0, sticky="ew", pady=(10, 0))

        _, wg_config = self._section(self.wireguard_page, "WireGuard Config", row=2)
        wg_config.columnconfigure(1, weight=1)
        ttk.Label(wg_config, text="Config File", style="FieldLabel.TLabel").grid(row=0, column=0, sticky="w")
        config_row = ttk.Frame(wg_config, style="Card.TFrame")
        config_row.grid(row=0, column=1, sticky="ew", padx=(12, 0))
        config_row.columnconfigure(0, weight=1)
        ttk.Entry(config_row, textvariable=self.config_path_var).grid(row=0, column=0, sticky="ew")
        ttk.Button(config_row, text="Browse", command=self._browse_config, style="Ghost.TButton").grid(row=0, column=1, padx=(8, 0))

        _, health = self._section(self.wireguard_page, "Health", row=3)
        for col in range(6):
            health.columnconfigure(col, weight=1)

        self._metric(health, 0, 0, "Connection", self.connection_var)
        self._metric(health, 0, 1, "WireGuard", self.wg_status_var)
        self._metric(health, 0, 2, "Last Read", self.last_read_var)
        self._metric(health, 0, 3, "Failures", self.failures_var)
        self._metric(health, 0, 4, "RX bytes est.", self.rx_var)
        self._metric(health, 0, 5, "TX bytes est.", self.tx_var)
        self._metric(health, 1, 0, "Address", self.address_var)
        self._metric(health, 1, 1, "Endpoint", self.endpoint_var)
        self._metric(health, 1, 2, "Polls", self.polls_var)
        self._metric(health, 1, 3, "Last Error", self.last_error_var)
        self._metric(health, 1, 4, "Firmware", self.firmware_var)
        self._metric(health, 1, 5, "Proto Profile", self.proto_profile_var)

        self._build_network_page(self.network_page)
        self._show_page("wireguard")

        self.log_frame, log_body = self._section(root, "Log", row=5, sticky="nsew", pady=(12, 0), body_padding=(0, 0))
        self.log_frame.grid(row=5, column=0, sticky="nsew", pady=(12, 0))
        log_body.rowconfigure(0, weight=1)
        self.log = tk.Text(
            log_body,
            height=12,
            wrap="word",
            state="disabled",
            bg="#08131d",
            fg=COLOR_TEXT,
            insertbackground=COLOR_ACCENT,
            relief="flat",
            bd=0,
            padx=10,
            pady=8,
        )
        self.log.grid(row=0, column=0, sticky="nsew")
        scrollbar = ttk.Scrollbar(log_body, orient="vertical", command=self.log.yview)
        scrollbar.grid(row=0, column=1, sticky="ns")
        self.log.configure(yscrollcommand=scrollbar.set)
        self.log_frame.grid_remove()
        self.after(1000, self._tick_last_read)

    def _show_page(self, page: str) -> None:
        if page == "network":
            self.network_page.tkraise()
            self.network_nav_button.configure(style="NavActive.TButton")
            self.wireguard_nav_button.configure(style="Nav.TButton")
            self.status_var.set(self.network_status_var.get())
        else:
            self.wireguard_page.tkraise()
            self.wireguard_nav_button.configure(style="NavActive.TButton")
            self.network_nav_button.configure(style="Nav.TButton")

    def _section(
        self,
        parent: ttk.Frame,
        title: str,
        *,
        row: int,
        column: int = 0,
        sticky: str = "ew",
        pady: tuple[int, int] = (12, 0),
        body_padding: tuple[int, int] = (0, 0),
    ) -> tuple[ttk.Frame, ttk.Frame]:
        outer = ttk.Frame(parent, padding=(16, 12), style="Section.TFrame")
        outer.grid(row=row, column=column, sticky=sticky, pady=pady)
        outer.columnconfigure(0, weight=1)
        outer.rowconfigure(1, weight=1)
        ttk.Label(outer, text=title, style="SectionTitle.TLabel").grid(row=0, column=0, sticky="w", pady=(0, 10))
        body = ttk.Frame(outer, padding=body_padding, style="Card.TFrame")
        body.grid(row=1, column=0, sticky="nsew")
        body.columnconfigure(0, weight=1)
        return outer, body

    def _build_network_page(self, parent: ttk.Frame) -> None:
        actions = ttk.Frame(parent, style="App.TFrame")
        actions.grid(row=0, column=0, sticky="ew")
        ttk.Button(actions, text="Read Network", command=self._read_network_config, style="Accent.TButton").grid(row=0, column=0)
        ttk.Button(actions, text="Apply Network", command=self._apply_network_config, style="Ghost.TButton").grid(row=0, column=1, padx=(8, 0))
        ttk.Button(actions, text="Clear Fields", command=self._clear_network_fields, style="Ghost.TButton").grid(row=0, column=2, padx=(8, 0))
        ttk.Label(actions, textvariable=self.network_status_var, style="Status.TLabel").grid(row=0, column=3, padx=(14, 0), sticky="w")

        ttk.Label(
            parent,
            text="Network writes can interrupt the active management path. Read first, apply one device at a time, then confirm after reconnect.",
            style="Hint.TLabel",
        ).grid(row=1, column=0, sticky="ew", pady=(10, 0))

        _, wifi = self._section(parent, "Wi-Fi", row=2)
        wifi.columnconfigure(1, weight=1)
        ttk.Checkbutton(wifi, text="Enable Wi-Fi", variable=self.network_wifi_enabled_var).grid(row=0, column=0, sticky="w")
        ttk.Label(wifi, text="SSID", style="FieldLabel.TLabel").grid(row=1, column=0, sticky="w", pady=(12, 0))
        ttk.Entry(wifi, textvariable=self.network_wifi_ssid_var).grid(row=1, column=1, sticky="ew", padx=(12, 0), pady=(12, 0))
        ttk.Label(wifi, text="Password", style="FieldLabel.TLabel").grid(row=2, column=0, sticky="w", pady=(12, 0))
        ttk.Entry(wifi, textvariable=self.network_wifi_psk_var, show="*").grid(row=2, column=1, sticky="ew", padx=(12, 0), pady=(12, 0))
        ttk.Label(wifi, text="Leave password blank to keep the device's existing Wi-Fi password.", style="CardHint.TLabel").grid(
            row=3,
            column=0,
            columnspan=2,
            sticky="ew",
            pady=(8, 0),
        )
        ttk.Checkbutton(wifi, text="Enable Bluetooth", variable=self.network_bluetooth_enabled_var).grid(
            row=4,
            column=0,
            sticky="w",
            pady=(12, 0),
        )
        ttk.Label(
            wifi,
            text="Turn Bluetooth off before enabling Wi-Fi on devices that cannot run both reliably.",
            style="CardHint.TLabel",
        ).grid(row=4, column=1, sticky="ew", padx=(12, 0), pady=(12, 0))

        _, services = self._section(parent, "Services", row=3)
        services.columnconfigure(1, weight=1)
        services.columnconfigure(3, weight=1)
        ttk.Label(services, text="NTP Server", style="FieldLabel.TLabel").grid(row=0, column=0, sticky="w")
        ttk.Entry(services, textvariable=self.network_ntp_server_var).grid(row=0, column=1, sticky="ew", padx=(12, 18))
        ttk.Label(services, text="Rsyslog", style="FieldLabel.TLabel").grid(row=0, column=2, sticky="w")
        ttk.Entry(services, textvariable=self.network_rsyslog_server_var).grid(row=0, column=3, sticky="ew", padx=(12, 0))
        ttk.Checkbutton(services, text="Enable Ethernet", variable=self.network_eth_enabled_var).grid(row=1, column=0, sticky="w", pady=(12, 0))
        ttk.Checkbutton(services, text="Enable IPv6", variable=self.network_ipv6_enabled_var).grid(row=1, column=1, sticky="w", pady=(12, 0))
        ttk.Label(services, text="Address Mode", style="FieldLabel.TLabel").grid(row=2, column=0, sticky="w", pady=(12, 0))
        ttk.Label(services, textvariable=self.network_address_mode_var, style="MetricValue.TLabel").grid(row=2, column=1, sticky="w", pady=(12, 0))
        ttk.Label(services, text="Firmware", style="FieldLabel.TLabel").grid(row=2, column=2, sticky="w", pady=(12, 0))
        ttk.Label(services, textvariable=self.network_firmware_var, style="MetricValue.TLabel").grid(row=2, column=3, sticky="w", pady=(12, 0))

    def _metric(self, parent: ttk.Frame, row: int, col: int, label: str, var: tk.StringVar) -> None:
        frame = ttk.Frame(parent, padding=(8, 6), style="Metric.TFrame")
        frame.grid(row=row, column=col, sticky="ew", padx=4, pady=4)
        ttk.Label(frame, text=label, style="MetricTitle.TLabel").grid(row=0, column=0, sticky="w")
        ttk.Label(frame, textvariable=var, style="MetricValue.TLabel").grid(row=1, column=0, sticky="w", pady=(2, 0))

    def _configure_style(self) -> None:
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure(".", background=COLOR_BG, foreground=COLOR_TEXT, fieldbackground=COLOR_PANEL_2)
        style.configure("App.TFrame", background=COLOR_BG)
        style.configure("Card.TFrame", background=COLOR_PANEL)
        style.configure("Section.TFrame", background=COLOR_PANEL, bordercolor=COLOR_ACCENT_SOFT, relief="flat")
        style.configure("Header.TFrame", background=COLOR_PANEL, relief="flat")
        style.configure("Update.TFrame", background="#102d3b")
        style.configure("Metric.TFrame", background=COLOR_PANEL, relief="flat")
        style.configure("TLabel", background=COLOR_BG, foreground=COLOR_TEXT)
        style.configure("Title.TLabel", background=COLOR_PANEL, foreground=COLOR_TEXT, font=("Segoe UI", 18, "bold"))
        style.configure("Subtitle.TLabel", background=COLOR_PANEL, foreground=COLOR_MUTED, font=("Segoe UI", 10))
        style.configure("Pill.TLabel", background=COLOR_ACCENT_DARK, foreground=COLOR_TEXT, padding=(10, 5), font=("Segoe UI", 9, "bold"))
        style.configure("Muted.TLabel", background=COLOR_PANEL, foreground=COLOR_MUTED)
        style.configure("FieldLabel.TLabel", background=COLOR_PANEL, foreground=COLOR_MUTED, font=("Segoe UI", 9, "bold"))
        style.configure("SectionTitle.TLabel", background=COLOR_PANEL, foreground=COLOR_ACCENT, font=("Segoe UI", 10, "bold"))
        style.configure("Status.TLabel", background=COLOR_BG, foreground=COLOR_ACCENT, font=("Segoe UI", 10, "bold"))
        style.configure("Hint.TLabel", background=COLOR_BG, foreground=COLOR_MUTED, font=("Segoe UI", 9))
        style.configure("CardHint.TLabel", background=COLOR_PANEL, foreground=COLOR_MUTED, font=("Segoe UI", 9))
        style.configure("Update.TLabel", background="#102d3b", foreground=COLOR_TEXT, font=("Segoe UI", 9, "bold"))
        style.configure("MetricTitle.TLabel", background=COLOR_PANEL, foreground=COLOR_MUTED, font=("Segoe UI", 8, "bold"))
        style.configure("MetricValue.TLabel", background=COLOR_PANEL, foreground=COLOR_TEXT, font=("Segoe UI", 10, "bold"))
        style.configure(
            "TButton",
            background=COLOR_PANEL_2,
            foreground=COLOR_TEXT,
            bordercolor=COLOR_ACCENT_SOFT,
            lightcolor=COLOR_PANEL_2,
            darkcolor=COLOR_PANEL_2,
            focusthickness=0,
            focuscolor=COLOR_PANEL_2,
            relief="flat",
            padding=(12, 7),
        )
        style.map("TButton", background=[("active", "#183045"), ("disabled", "#101a24")], foreground=[("disabled", "#5f7180")])
        style.configure(
            "Ghost.TButton",
            background=COLOR_BG,
            foreground=COLOR_TEXT,
            bordercolor=COLOR_BG,
            lightcolor=COLOR_BG,
            darkcolor=COLOR_BG,
            focusthickness=0,
            focuscolor=COLOR_BG,
            relief="flat",
            padding=(11, 7),
        )
        style.map(
            "Ghost.TButton",
            background=[("active", "#102334"), ("pressed", "#132b3f"), ("disabled", COLOR_BG)],
            foreground=[("active", COLOR_ACCENT), ("pressed", COLOR_ACCENT), ("disabled", "#5f7180")],
        )
        style.configure(
            "Nav.TButton",
            background=COLOR_BG,
            foreground=COLOR_MUTED,
            bordercolor=COLOR_BG,
            lightcolor=COLOR_BG,
            darkcolor=COLOR_BG,
            focusthickness=0,
            focuscolor=COLOR_BG,
            relief="flat",
            padding=(18, 8),
        )
        style.map("Nav.TButton", background=[("active", "#102334")], foreground=[("active", COLOR_TEXT)])
        style.configure(
            "NavActive.TButton",
            background=COLOR_ACCENT_SOFT,
            foreground=COLOR_TEXT,
            bordercolor=COLOR_ACCENT_SOFT,
            lightcolor=COLOR_ACCENT_SOFT,
            darkcolor=COLOR_ACCENT_SOFT,
            focusthickness=0,
            focuscolor=COLOR_ACCENT_SOFT,
            relief="flat",
            padding=(18, 8),
        )
        style.map("NavActive.TButton", background=[("active", COLOR_ACCENT_DARK)], foreground=[("active", COLOR_TEXT)])
        style.configure(
            "Accent.TButton",
            background=COLOR_ACCENT_DARK,
            foreground=COLOR_TEXT,
            bordercolor=COLOR_ACCENT,
            lightcolor=COLOR_ACCENT_DARK,
            darkcolor=COLOR_ACCENT_DARK,
            focusthickness=0,
            focuscolor=COLOR_ACCENT_DARK,
            relief="flat",
            padding=(14, 7),
        )
        style.map("Accent.TButton", background=[("active", COLOR_ACCENT), ("disabled", "#123242")])
        style.configure(
            "Danger.TButton",
            background="#321720",
            foreground=COLOR_TEXT,
            bordercolor="#5a2630",
            lightcolor="#321720",
            darkcolor="#321720",
            focusthickness=0,
            focuscolor="#321720",
            relief="flat",
        )
        style.map("Danger.TButton", background=[("active", "#5a2430"), ("disabled", "#161d24")])
        style.configure("TRadiobutton", background=COLOR_PANEL, foreground=COLOR_TEXT, indicatorcolor=COLOR_BG)
        style.map("TRadiobutton", background=[("active", COLOR_PANEL)], foreground=[("active", COLOR_ACCENT)])
        style.configure("TCheckbutton", background=COLOR_PANEL, foreground=COLOR_TEXT, indicatorcolor=COLOR_BG)
        style.map("TCheckbutton", background=[("active", COLOR_PANEL)], foreground=[("active", COLOR_ACCENT)])
        style.configure(
            "TEntry",
            fieldbackground=COLOR_PANEL_2,
            foreground=COLOR_TEXT,
            insertcolor=COLOR_ACCENT,
            bordercolor=COLOR_ACCENT_SOFT,
            lightcolor=COLOR_PANEL_2,
            darkcolor=COLOR_PANEL_2,
        )
        style.configure(
            "TCombobox",
            fieldbackground=COLOR_PANEL_2,
            foreground=COLOR_TEXT,
            arrowcolor=COLOR_ACCENT,
            bordercolor=COLOR_ACCENT_SOFT,
            lightcolor=COLOR_PANEL_2,
            darkcolor=COLOR_PANEL_2,
        )
        style.map("TCombobox", fieldbackground=[("readonly", COLOR_PANEL_2)], foreground=[("readonly", COLOR_TEXT)])
        style.configure("Vertical.TScrollbar", background=COLOR_PANEL_2, arrowcolor=COLOR_ACCENT, troughcolor=COLOR_BG)
        style.configure("Card.TLabelframe", background=COLOR_PANEL, bordercolor=COLOR_ACCENT_SOFT, relief="flat")
        style.configure("Card.TLabelframe.Label", background=COLOR_PANEL, foreground=COLOR_ACCENT, font=("Segoe UI", 10, "bold"), padding=(12, 0, 0, 0))

    def _load_logo_image(self) -> tk.PhotoImage | None:
        if not LOGO_PATH.exists():
            return None
        try:
            image = tk.PhotoImage(file=str(LOGO_PATH))
        except tk.TclError:
            return None
        scale = max(image.width() // 82, image.height() // 82, 1)
        return image.subsample(scale, scale)

    def _apply_window_chrome(self) -> None:
        self.update_idletasks()
        if LOGO_PATH.exists():
            try:
                self._icon_image = tk.PhotoImage(file=str(LOGO_PATH))
                self.iconphoto(True, self._icon_image)
            except tk.TclError:
                self._icon_image = None

        if sys.platform != "win32":
            return
        try:
            user32 = ctypes.windll.user32
            dwmapi = ctypes.windll.dwmapi
            handles = [self.winfo_id()]
            parent = user32.GetParent(self.winfo_id())
            if parent and parent not in handles:
                handles.append(parent)
            dark = ctypes.c_int(1)
            caption = ctypes.c_int(self._colorref("#0d1824"))
            caption_text = ctypes.c_int(self._colorref(COLOR_TEXT))
            for hwnd in handles:
                for attribute in (20, 19):
                    dwmapi.DwmSetWindowAttribute(hwnd, attribute, ctypes.byref(dark), ctypes.sizeof(dark))
                dwmapi.DwmSetWindowAttribute(hwnd, 35, ctypes.byref(caption), ctypes.sizeof(caption))
                dwmapi.DwmSetWindowAttribute(hwnd, 36, ctypes.byref(caption_text), ctypes.sizeof(caption_text))
        except (AttributeError, OSError, tk.TclError):
            return

    @staticmethod
    def _colorref(hex_color: str) -> int:
        value = hex_color.lstrip("#")
        red = int(value[0:2], 16)
        green = int(value[2:4], 16)
        blue = int(value[4:6], 16)
        return red | (green << 8) | (blue << 16)

    def _toggle_log(self) -> None:
        self._log_visible = not self._log_visible
        parent = self.log_frame.master
        if self._log_visible:
            self.log_frame.grid()
            parent.rowconfigure(5, weight=1)
            self.log_toggle_button.configure(text="Hide Log")
        else:
            self.log_frame.grid_remove()
            parent.rowconfigure(5, weight=0)
            self.log_toggle_button.configure(text="Show Log")

    def _clear_network_fields(self) -> None:
        self.network_wifi_enabled_var.set(False)
        self.network_wifi_ssid_var.set("")
        self.network_wifi_psk_var.set("")
        self.network_ntp_server_var.set("")
        self.network_eth_enabled_var.set(False)
        self.network_ipv6_enabled_var.set(False)
        self.network_bluetooth_enabled_var.set(False)
        self.network_rsyslog_server_var.set("")
        self.network_address_mode_var.set("-")
        self.network_firmware_var.set("-")
        self.network_status_var.set("Fields cleared")
        self.status_var.set("Fields cleared")

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

    @staticmethod
    def _version_tuple(version: str) -> tuple[int, int, int]:
        parts = [int(part) for part in re.findall(r"\d+", version)[:3]]
        while len(parts) < 3:
            parts.append(0)
        return tuple(parts)

    @classmethod
    def _is_newer_version(cls, candidate: str, current: str) -> bool:
        return cls._version_tuple(candidate) > cls._version_tuple(current)

    @staticmethod
    def _find_windows_asset(release: dict[str, Any]) -> dict[str, Any] | None:
        for asset in release.get("assets", []):
            name = str(asset.get("name", ""))
            if name.lower().endswith(".exe"):
                return asset
        return None

    def _check_for_updates(self) -> None:
        def runner() -> None:
            try:
                request = urllib.request.Request(
                    RELEASES_API_URL,
                    headers={"Accept": "application/vnd.github+json", "User-Agent": f"MeshtasticWireGuardConfigurator/{APP_VERSION}"},
                )
                with urllib.request.urlopen(request, timeout=HTTP_TIMEOUT_SECONDS) as response:
                    release = json.loads(response.read().decode("utf-8"))
                if release.get("draft") or release.get("prerelease"):
                    return
                tag = str(release.get("tag_name", ""))
                if not tag or not self._is_newer_version(tag, APP_VERSION):
                    return
                asset = self._find_windows_asset(release)
                self._events.put(("update_available", (release, asset)))
            except (OSError, urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
                self._events.put(("update_check_failed", exc))

        threading.Thread(target=runner, daemon=True).start()

    def _show_update(self, release: dict[str, Any], asset: dict[str, Any] | None) -> None:
        self._latest_release = release
        self._latest_release_asset = asset
        tag = str(release.get("tag_name", "new version"))
        self.update_notice_var.set(f"Configurator {tag} is available.")
        self.update_frame.grid()
        self._log(f"Configurator update available: {tag}")

    def _dismiss_update(self) -> None:
        self.update_frame.grid_remove()

    def _open_update_release(self) -> None:
        release_url = ""
        if self._latest_release:
            release_url = str(self._latest_release.get("html_url", ""))
        if release_url:
            webbrowser.open(release_url)

    def _download_update(self) -> None:
        if not self._latest_release_asset:
            self._open_update_release()
            return
        asset_url = str(self._latest_release_asset.get("browser_download_url", ""))
        asset_name = str(self._latest_release_asset.get("name", "MeshtasticWireGuardConfigurator.exe"))
        if not asset_url:
            self._open_update_release()
            return
        filename = filedialog.asksaveasfilename(
            title="Save configurator update",
            initialfile=asset_name,
            defaultextension=".exe",
            filetypes=[("Windows executable", "*.exe"), ("All files", "*.*")],
        )
        if not filename:
            return

        self.status_var.set("Downloading update...")

        def runner() -> None:
            try:
                request = urllib.request.Request(asset_url, headers={"User-Agent": f"MeshtasticWireGuardConfigurator/{APP_VERSION}"})
                with urllib.request.urlopen(request, timeout=DOWNLOAD_TIMEOUT_SECONDS) as response:
                    data = response.read()
                Path(filename).write_bytes(data)
                self._events.put(("update_downloaded", filename))
            except BaseException as exc:
                self._events.put(("update_download_failed", exc))

        threading.Thread(target=runner, daemon=True).start()

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

    def _read_network_config(self) -> None:
        try:
            connection = self._connection_kwargs()
        except ValueError as exc:
            messagebox.showerror("Missing Connection", str(exc))
            return

        self.network_status_var.set("Reading network...")
        self._run_worker(
            "Reading network config...",
            connection,
            lambda cancel, status, iface_cb: wg_api.read_network_config(
                progress=status,
                cancel_event=cancel,
                interface_callback=iface_cb,
                **connection,
            ),
        )
        self._health["tx_bytes"] += 64
        self._sync_health()

    def _apply_network_config(self) -> None:
        try:
            connection = self._connection_kwargs()
        except ValueError as exc:
            messagebox.showerror("Missing Connection", str(exc))
            return

        wifi_enabled = self.network_wifi_enabled_var.get()
        wifi_ssid = self.network_wifi_ssid_var.get().strip()
        wifi_psk = self.network_wifi_psk_var.get()
        if wifi_enabled and not wifi_ssid:
            messagebox.showerror("Missing Wi-Fi SSID", "Enter a Wi-Fi SSID before enabling Wi-Fi.")
            return
        if connection.get("host"):
            confirmed = messagebox.askyesno(
                "Apply Network Config",
                "Changing Wi-Fi or network settings over TCP can disconnect this device. Apply and confirm by readback?",
            )
            if not confirmed:
                return

        self.network_status_var.set("Applying network...")
        self._run_worker(
            "Applying network config...",
            connection,
            lambda cancel, status, iface_cb: wg_api.set_network_config(
                progress=status,
                cancel_event=cancel,
                interface_callback=iface_cb,
                wifi_enabled=wifi_enabled,
                wifi_ssid=wifi_ssid,
                wifi_psk=wifi_psk or None,
                ntp_server=self.network_ntp_server_var.get().strip(),
                eth_enabled=self.network_eth_enabled_var.get(),
                rsyslog_server=self.network_rsyslog_server_var.get().strip(),
                ipv6_enabled=self.network_ipv6_enabled_var.get(),
                bluetooth_enabled=self.network_bluetooth_enabled_var.get(),
                **connection,
            ),
        )
        self._health["tx_bytes"] += 128 + len(wifi_ssid) + len(wifi_psk)
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
            elif event == "update_available":
                self._show_update(*payload)
            elif event == "update_check_failed":
                self._log(f"Update check failed: {payload}")
            elif event == "update_downloaded":
                self.status_var.set("Update downloaded")
                self._log(f"Downloaded update to {payload}")
                messagebox.showinfo("Update Downloaded", f"Downloaded update to:\n{payload}\n\nClose this app before launching the new EXE.")
            elif event == "update_download_failed":
                self.status_var.set("Update download failed")
                self._log(f"Update download failed: {payload}")
                messagebox.showerror("Update Download Failed", str(payload))
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
            if self._is_network_payload(payload["confirmed"]):
                self._update_network_status(payload["confirmed"])
            else:
                self._update_config_status(payload["confirmed"])
        else:
            self._log_json(name, payload)
            if self._is_network_payload(payload):
                self._update_network_status(payload)
            else:
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

    @staticmethod
    def _is_network_payload(payload: Any) -> bool:
        return isinstance(payload, dict) and "wifi_enabled" in payload and "ntp_server" in payload

    def _update_network_status(self, config: dict[str, Any]) -> None:
        self._health["connected"] = True
        self._health["polls"] += 1
        self._last_success_at = time.monotonic()
        self._health["rx_bytes"] += len(json.dumps(config))

        self.connection_var.set("Connected")
        self.network_wifi_enabled_var.set(bool(config.get("wifi_enabled", False)))
        self.network_wifi_ssid_var.set(str(config.get("wifi_ssid", "") or ""))
        self.network_wifi_psk_var.set("")
        self.network_ntp_server_var.set(str(config.get("ntp_server", "") or ""))
        self.network_eth_enabled_var.set(bool(config.get("eth_enabled", False)))
        self.network_ipv6_enabled_var.set(bool(config.get("ipv6_enabled", False)))
        self.network_bluetooth_enabled_var.set(bool(config.get("bluetooth_enabled", False)))
        self.network_rsyslog_server_var.set(str(config.get("rsyslog_server", "") or ""))
        self.network_address_mode_var.set(str(config.get("address_mode", "-")))
        self.network_firmware_var.set(str(config.get("firmware_version", "-") or "-"))
        self.network_status_var.set("Network loaded")
        self.status_var.set("Network loaded")
        self._sync_health()

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
