# Meshtastic WireGuard Configurator

Simple Windows-friendly configurator for experimental Meshtastic firmware builds that expose `ModuleConfig.wireguard`.

This tool lets users import a standard single-peer WireGuard `.conf`, select a serial port, push the config to a device, confirm readback, and monitor basic tunnel health.

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

Import a WireGuard config file:

```powershell
python bin\wireguard-config.py --port COM12 set --config wg0.conf --enable
```

Read the saved device config and runtime status:

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

## Compatibility

This repository includes the Meshtastic protobuf sources needed for the experimental WireGuard config fields. `bin\setup-wireguard-gui.py` generates Python bindings from those `.proto` files and overlays them into the local Python environment so the configurator can use `ModuleConfig.wireguard` before upstream Meshtastic clients support it natively.

Once WireGuard configuration lands in official Meshtastic protobufs and `meshtastic-python`, this compatibility layer can be simplified or removed.

## Firmware Requirement

The target device must run a Meshtastic firmware build that includes the WireGuard module config fields and firmware support for runtime WireGuard configuration.

## License

GPL-3.0, matching the Meshtastic firmware repository this tool was split from.
