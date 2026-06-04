# Meshtastic WireGuard Configurator

Simple Windows-friendly configurator for experimental Meshtastic firmware builds that expose `ModuleConfig.wireguard`.

This tool lets users import a standard single-peer WireGuard `.conf`, connect over serial or the Meshtastic TCP API, push the config to a device, confirm readback, and monitor basic tunnel health.

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

In the GUI, choose `Serial` for USB-connected devices or `Network` for devices reachable through the Meshtastic TCP API. The default TCP API port is `4403`.

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

When configuring over the network, remember that enabling or changing a WireGuard tunnel can alter routing or briefly interrupt the management connection. If the write succeeds but readback disconnects, reconnect over serial or the pre-existing network path and verify the saved config.

## Future Improvements

Likely next additions:

- UniFi import: connect to UniFi Network's API, list WireGuard VPN clients, and import a selected client config.
- Batch deployment: load a CSV or JSON device list, apply one config per device, and export a success/failure report.
- Release automation: build and attach `MeshtasticWireGuardConfigurator.exe` to GitHub Releases from CI.

## Compatibility

`bin\setup-wireguard-gui.py` downloads the Meshtastic protobuf sources from the experimental WireGuard firmware branch, generates Python bindings, and overlays them into the local Python environment so the configurator can use `ModuleConfig.wireguard` before upstream Meshtastic clients support it natively.

To use a local protobuf checkout instead of downloading:

```powershell
python bin\setup-wireguard-gui.py --proto-dir C:\path\to\Meshtastic\protobufs\meshtastic
```

Once WireGuard configuration lands in official Meshtastic protobufs and `meshtastic-python`, this compatibility layer can be simplified or removed.

## Firmware Requirement

The target device must run a Meshtastic firmware build that includes the WireGuard module config fields and firmware support for runtime WireGuard configuration.

## License

GPL-3.0, matching the Meshtastic firmware repository this tool was split from.
