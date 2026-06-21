# Meshtastic WireGuard Configurator

Cross-platform configurator for experimental Meshtastic firmware builds that expose `ModuleConfig.wireguard`. Runs on Windows, macOS, and Linux.

This tool lets users import a standard single-peer WireGuard `.conf`, connect over serial or the Meshtastic TCP API, push the config to a device, confirm readback, tune basic network settings, and monitor basic tunnel health from a gui.

<img width="970" height="715" alt="image" src="https://github.com/user-attachments/assets/d69e2c58-bac6-42a3-9d71-9a0296cffd8d" />


## Quick Start

1. Install Python 3.
2. Clone or download this repo.
3. Run the one-time setup:

```powershell
bin\setup-wireguard-gui.cmd
```

4. Launch the GUI:

```powershell
bin\wireguard-gui.cmd
```

On macOS or Linux, use the shell-script launchers instead — see
[Running on macOS and Linux](#running-on-macos-and-linux).

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

## Running on macOS and Linux

> **Note:** The macOS/Linux launchers and build path have not yet been tested on
> real macOS or Linux hardware — the code is platform-neutral by construction, but
> treat this path as experimental and please report any issues.

The engine and GUI are pure Python (the GUI uses tkinter), so they run on macOS
and Linux as well. Use the `.sh` launchers instead of the `.cmd` ones:

```bash
# One-time setup
bin/setup-wireguard-gui.sh

# Launch the GUI
bin/wireguard-gui.sh
```

Requirements:

- **Python 3** with **tkinter**. tkinter ships with the python.org installers on
  macOS and Windows, but on many Linux distributions it is a separate package —
  e.g. `sudo apt install python3-tk` (Debian/Ubuntu) or `sudo dnf install
  python3-tkinter` (Fedora).
- Serial access on Linux usually requires your user to be in the `dialout` (or
  `uucp`) group so the device shows up as `/dev/ttyUSB*` / `/dev/ttyACM*`.

Everything else — CLI usage, RPC mode, and the protobuf setup profiles below —
works identically; just swap the Windows path separators in the examples.

## Build A Standalone Executable

To package a single-file executable for the current platform:

```powershell
bin\build-wireguard-gui-exe.cmd
```

```bash
bin/build-wireguard-gui-exe.sh
```

PyInstaller is not a cross-compiler, so the build produces a binary for whatever
OS you run it on:

```text
dist\MeshtasticWireGuardConfigurator.exe   # Windows
dist/MeshtasticWireGuardConfigurator.app   # macOS
dist/MeshtasticWireGuardConfigurator       # Linux
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

List available serial ports as JSON (no device connection required):

```powershell
python bin\wireguard-config.py list-ports
```

Validate a WireGuard `.conf` and preview the parsed fields without connecting to a
device (useful for UI validation; secrets redacted unless `--show-secrets`):

```powershell
python bin\wireguard-config.py parse-conf --config wg0.conf
```

All commands emit JSON on stdout and report errors on stderr with a non-zero exit
code, so the tool can be driven as a subprocess by another front-end.

### RPC mode (newline-delimited JSON)

Pass the global `--rpc` flag to switch stdout from a single pretty-printed result
to a stream of newline-delimited JSON events. This is the contract a front-end
(e.g. the planned Electron app) binds to when running the engine as a subprocess:

```powershell
python bin\wireguard-config.py --rpc --port COM12 get
```

Each line is one self-contained JSON object carrying the schema version `v`:

```json
{"v":1,"type":"progress","message":"Opening device connection."}
{"v":1,"type":"progress","message":"Connected to device."}
{"v":1,"type":"result","data":{ "...the same payload the command prints by default..." }}
```

Exactly one terminal event is emitted per run: `result` (exit 0) or, on failure,
an `error` event (exit 1) on **stdout** instead of stderr:

```json
{"v":1,"type":"error","message":"WireGuard config is missing an [Interface] section.","kind":"parse_error"}
```

The `kind` lets a front-end react programmatically instead of parsing English:

| `kind` | Cause |
| --- | --- |
| `parse_error` | Invalid arguments or `.conf` (missing section, bad endpoint/address, `--port` and `--host` together) |
| `connection_error` | Cannot reach the device — socket/host resolution failure, or `meshtastic-python`/`pyserial` not installed |
| `timeout` | TCP connect or config readback timed out |
| `cancelled` | The operation was cancelled (host-cancel path) |
| `internal` | Any other unexpected error |

`--rpc` is additive and opt-in; without it the default single-JSON / stderr
behavior is unchanged. The `v` field is the event-contract version (currently
`1`); a non-additive change to the envelope bumps it so a client can reject an
incompatible engine.

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

### Protobuf contract verification

Regardless of which proto source is used (firmware branch download, upstream 2.8
protos plus overlay, or a local `--proto-dir`), setup ends by verifying the
generated Python protobufs against a single declared contract
(`WIREGUARD_CONTRACT` in `bin/setup-wireguard-gui.py`):

- `ModuleConfig.wireguard` = field 17
- `LocalModuleConfig.wireguard` = field 18
- `AdminMessage.ModuleConfigType.WIREGUARD_CONFIG` = 16
- `WireGuardConfig` fields 1-9: `address`, `server_addr`, `server_port`,
  `private_key`, `public_key`, `preshared_key`, `enabled`, `status`, `last_error`

These tag numbers must match the firmware's generated nanopb headers
(`src/mesh/generated/meshtastic/*.pb.h`). If any tag has drifted, setup **fails
with a precise diff** instead of silently producing a client that is
wire-incompatible with the device. This guards against the scenario where
upstream Meshtastic assigns one of these (currently unreserved) tags to a
different module. See [discussion #10716](https://github.com/meshtastic/firmware/discussions/10716).

Once WireGuard configuration lands in official Meshtastic protobufs and
`meshtastic-python` — ideally with these tags reserved upstream — this
compatibility layer can be simplified or removed.

## Firmware Requirement

The target device must run a Meshtastic firmware build that includes the WireGuard module config fields and firmware support for runtime WireGuard configuration.

## License

GPL-3.0, matching the Meshtastic firmware repository this tool was split from.
