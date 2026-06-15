# Meshtastic WireGuard Configurator

Simple Windows-friendly configurator for experimental Meshtastic firmware builds that expose `ModuleConfig.wireguard`.

This tool lets users import a standard single-peer WireGuard `.conf`, connect over serial or the Meshtastic TCP API, push the config to a device, confirm readback, tune basic network settings, and monitor basic tunnel health from a gui.

<img width="970" height="715" alt="image" src="https://github.com/user-attachments/assets/d69e2c58-bac6-42a3-9d71-9a0296cffd8d" />


## Quick Start

1. Install Python 3 for Windows.
2. Clone or download this repo.
3. Run the one-time setup:

```powershell
bin\setup-wireguard-gui.cmd
```

4. Launch the GUI:

```powershell
bin\wireguard-gui.cmd
```

In the GUI, choose `Serial` for USB-connected devices or `Network` for devices reachable through the Meshtastic TCP API. The default TCP API port is `4403`. Use the top menu to switch between the `WireGuard` and `Network` sections.

The GUI shows progress for each device operation, including network ping status, connection open, request sent, waiting for response, and confirmed response. Use `Cancel` if a device operation is stuck or the wrong IP/port was entered; the app will ignore late results from the cancelled operation and allow a new action. The detailed log is collapsed by default and can be expanded when troubleshooting.

The `WireGuard` section keeps device actions at the top, followed by the selected `.conf` file and device health. Each node should use a unique WireGuard client config; do not reuse the same private key or tunnel address across multiple devices.

The `Network` section can read and apply common Meshtastic network settings:

- Wi-Fi enabled state, SSID, and password
- Wi-Fi/Bluetooth conflict handling for devices that cannot reliably run both radios together
- NTP server
- Rsyslog server
- Ethernet enabled state
- IPv6 enabled state
- Bluetooth enabled state, pairing mode, and fixed PIN

Read the current device config before applying changes. Leaving the Wi-Fi password blank keeps the device's existing password. Some ESP-based devices cannot reliably keep Wi-Fi and Bluetooth enabled at the same time, so the Network section includes explicit options to disable Bluetooth before enabling Wi-Fi, or disable Wi-Fi before enabling Bluetooth. The Wi-Fi-off-before-Bluetooth option is disabled when the configurator is connected over Network/TCP because it would break the active management path before Bluetooth can be confirmed. Radio conflict warnings are shown inside the app instead of as separate system dialogs. Verify readback after the device reconnects.

On startup, the GUI checks the latest GitHub Release. When a newer configurator version is available, it shows a small update banner with options to download the new Windows EXE or open the release notes. The app does not replace itself while running; close the current configurator before launching a downloaded update.

## Build A Windows EXE

To package a single-file executable:

```powershell
bin\build-wireguard-gui-exe.cmd
```

The executable is written to:

```text
dist\MeshtasticWireGuardConfigurator.exe
```

Generated `dist`, `build`, `.spec`, and `.wireguard-gui-venv` files are local artifacts and should not be committed.

## Command Line Usage

Import a WireGuard config file over serial:

```powershell
python bin\wireguard-config.py --port COM12 set --config wg0.conf --enable
```

Import over the Meshtastic TCP API:

```powershell
python bin\wireguard-config.py --host 192.168.1.50 set --config wg0.conf --enable
```

Use a non-default TCP API port:

```powershell
python bin\wireguard-config.py --host 192.168.1.50 --tcp-port 4403 get
```

Use a shorter or longer network timeout:

```powershell
python bin\wireguard-config.py --host 192.168.1.50 --timeout 5 get
```

You can also include the port in the host value:

```powershell
python bin\wireguard-config.py --host 192.168.1.50:4403 get
```

Read the saved device config and runtime status over serial:

```powershell
python bin\wireguard-config.py --port COM12 get
```

Disable automatic startup without erasing saved keys:

```powershell
python bin\wireguard-config.py --port COM12 disable
```

The importer reads:

- `Interface.Address`
- `Interface.PrivateKey`
- `Peer.PublicKey`
- `Peer.PresharedKey`
- `Peer.Endpoint`

CLI flags override imported values. Private and preshared keys are redacted from output unless `--show-secrets` is passed.

When configuring over the network, the app pings the selected host before opening the Meshtastic TCP API connection. A failed ping is logged, but the app still tries TCP because some networks block ICMP. Enabling or changing a WireGuard tunnel can alter routing or briefly interrupt the management connection. If the write succeeds but readback disconnects, reconnect over serial or the pre-existing network path and verify the saved config.

## Future Improvements

Likely next additions:

- Rebuild onto Electron
- Web-based client
- Batch/Fleet deployment and maintenance: load a CSV or JSON device list, apply one config per device, and export a success/failure report.
- Fallback configuration (FIRMWARE DEPENDENT): save the last confirmed working VPN config before remote writes and restore it if post-change verification fails.
- Release automation: build and attach `MeshtasticWireGuardConfigurator.exe` to GitHub Releases from CI.
- Full self-update flow: download, verify, replace the running EXE through a helper process, and restart.
- Firmware Maintenance to support flashing and updating WireGuard-capable firmware on verified ESP and Linux based nodes (compatible with Batch mode and ability to inject custom Linux patches)

For any future batch deployment workflow, each node must receive its own unique WireGuard client configuration. Reusing the same WireGuard private key or tunnel address across multiple nodes will cause routing and identity conflicts.

## Compatibility

`bin\setup-wireguard-gui.py` downloads the Meshtastic protobuf sources from the experimental WireGuard firmware branch, generates Python bindings, and overlays them into the local Python environment so the configurator can use `ModuleConfig.wireguard` before upstream Meshtastic clients support it natively.

The default setup profile targets the current experimental WireGuard branch. For trial firmware based on Meshtastic 2.8 development protos, rebuild the local environment with:

```powershell
python bin\setup-wireguard-gui.py --recreate --proto-profile 2.8-wireguard-trial
```

To test against a local 2.8 firmware checkout, pass both the profile and local protobuf directory:

```powershell
python bin\setup-wireguard-gui.py --recreate --proto-profile 2.8-wireguard-trial --proto-dir C:\path\to\Meshtastic\protobufs\meshtastic
```

During each device read or push, the configurator asks the device for metadata first. Firmware versions `2.8.0` and newer are labeled with the `2.8-wireguard-trial` protobuf profile in CLI output and the GUI health panel.

To use a local protobuf checkout instead of downloading:

```powershell
python bin\setup-wireguard-gui.py --proto-dir C:\path\to\Meshtastic\protobufs\meshtastic
```

Once WireGuard configuration lands in official Meshtastic protobufs and `meshtastic-python`, this compatibility layer can be simplified or removed.

## Firmware Requirement

The target device must run a Meshtastic firmware build that includes the WireGuard module config fields and firmware support for runtime WireGuard configuration.

## License

GPL-3.0, matching the Meshtastic firmware repository this tool was split from.
