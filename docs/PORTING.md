# Architecture & Cross-Platform Roadmap

Status as of 2026-06-14. This document records the architecture decisions for
making the configurator cleaner, cross-platform, and easy for the community to
develop on. It is a living plan, not a finished spec.

## 1. Current architecture

```
bin/wireguard-config.py   Engine (~740 lines)
                          - Transports: serial + Meshtastic TCP API (meshtastic-python)
                          - Admin protobuf get/set of ModuleConfig.wireguard
                          - WireGuard .conf parsing + validation (configparser)
                          - Device-metadata probe -> per-firmware proto profile
                          - Emits JSON on stdout (get/set), errors on stderr
                          - Library entrypoints take progress + cancel callbacks
bin/wireguard-gui.py      Tk GUI (~524 lines) calling the engine's library API
bin/setup-wireguard-gui.py  Builds a venv, fetches/generates protobufs, verifies contract
bin/build-wireguard-gui-exe.py  PyInstaller single-file binary (Win/macOS/Linux)
bin/*.cmd                       Windows launchers
bin/*.sh                        macOS/Linux launchers (mirror the .cmd files)
```

The engine already separates a **library API** (`read_wireguard_config`,
`set_wireguard_config`, with `progress`/`cancel_event`/`interface_callback`)
from a **CLI** (`get`/`set`/`disable` subcommands that JSON-serialize results).
The Tk GUI uses the library API directly. This separation is what makes a future
sidecar / IPC boundary cheap.

## 2. The protobuf contract (the load-bearing dependency)

`ModuleConfig.wireguard` is **not** in upstream Meshtastic protobufs. The wire
contract is currently defined in three hand-synced places:

1. Firmware `protobufs` submodule (the real, compiled contract) — but pinned to a
   local/fork commit not pushed to a reachable remote.
2. String literals in `bin/setup-wireguard-gui.py` (patched onto upstream 2.8 protos).
3. A download from the firmware's `Wireguard` branch.

They agree today by manual discipline only.

### Canonical tags (verified against firmware `*.pb.h`)

| Location | Field/value | Tag |
| --- | --- | --- |
| `ModuleConfig` oneof | `wireguard` | 17 |
| `LocalModuleConfig` | `wireguard` | 18 |
| `AdminMessage.ModuleConfigType` | `WIREGUARD_CONFIG` | 16 |
| `WireGuardConfig` | address, server_addr, server_port, private_key, public_key, preshared_key, enabled, status, last_error | 1-9 |

### Imminent collision risk

On upstream `develop` (checked 2026-06-14) the highest used tags are
`ModuleConfig.tak = 16` and `ModuleConfigType.TAK_CONFIG = 15`, with **no
`reserved` statements**. WireGuard's tags (17 / 16) are therefore the *next free
integers* — the next module merged upstream would collide and force a renumber
that breaks every deployed client and saved config at once.

### Strategy

- **Single source of truth (interim):** a dedicated protobufs fork
  (`TheWISPRer/protobufs`), tagged (e.g. `wireguard-2.8-v1`), pinned by both the
  firmware submodule and this configurator. Chosen over vendoring into this repo
  (would create a 4th copy) or a brand-new proto repo (more ceremony).
- **Single source of truth (endgame):** an upstream PR that *reserves* tags
  17 / 18 / 16 for WireGuard in `meshtastic/protobufs`. Cheapest, highest-value
  stability action; protects all clients regardless of build channel. Tracked in
  [discussion #10716](https://github.com/meshtastic/firmware/discussions/10716).
- **Drift guard (DONE):** `bin/setup-wireguard-gui.py` now declares the contract
  once (`WIREGUARD_CONTRACT`) and verifies the generated protobufs against it at
  the end of setup, failing with a precise diff on any drift. See README →
  Compatibility → "Protobuf contract verification".

## 3. Cross-platform strategy

Goal: a polished, cross-platform (Windows/macOS/Linux) client that is
maintainable and aligned with the Meshtastic ecosystem.

Note: the **current** Python tool already runs from source on all three OSes —
the engine and Tk GUI are platform-neutral, and `bin/*.sh` launchers plus a
`tkinter`/`dialout` note in the README cover macOS/Linux. The Electron decision
below is about the *polished, packaged* end state, not a prerequisite for using
the tool off Windows.

### Decision: Electron, no Python sidecar

The Meshtastic ecosystem now ships modular official TypeScript libraries:

- `@meshtastic/core` — protocol / admin messaging
- `@meshtastic/transport-web-serial` — serial (works in Node **and** browser)
- `@meshtastic/transport-node` — TCP from Node
- `@meshtastic/transport-web-bluetooth`, `@meshtastic/transport-http`

Because Electron's main process gets serial + TCP natively via these maintained
transports, there is **no protocol layer to hand-roll and no need to ship
Python**. (This reverses an earlier "keep a Python sidecar" lean, which only made
sense if the protocol layer had to be reimplemented from scratch.)

The **only** custom code is the WireGuard proto overlay, generated to TypeScript
from the *same* protobufs fork the firmware compiles — one source of truth shared
across firmware, Python tool, and the TS client.

### Validation spike (do before deleting the Python path)

Confirm `@meshtastic/core`'s admin API can send a `get/set_module_config` for the
custom `WIREGUARD_CONFIG` type and return the raw `wireguard` sub-message. Should
work generically since the generated protobufs from the fork include the field —
but verify before committing.

### Target structure

```
Frontend     React/Vite inside Electron
Device layer @meshtastic/core + transports (serial/TCP/BLE/HTTP)
Protocol     WireGuard proto overlay generated from the protobufs fork
Config       WireGuard .conf parse/validate + per-node safety checks (port from Python logic)
Packaging    electron-builder -> Win/macOS/Linux
```

## 4. Engine boundary assessment (for the porting effort)

The Python engine logic that must be reproduced (or reused short-term) in the TS
client:

- `.conf` parsing/validation: `_read_wireguard_config`, `_strip_cidr`,
  `_parse_endpoint` (IPv4-only address, single `[Peer]`, host:port endpoint).
- Per-firmware proto profile selection from device metadata.
- Redaction of private/preshared keys unless explicitly shown.
- Readback-after-write confirmation flow.

CLI surface gaps that any UI (Electron or otherwise) will need exposed at the
process boundary, currently only available as internal helpers / library calls:

- `list-ports` — DONE (CLI subcommand wrapping `list_serial_ports()`).
- `parse-conf` (dry run) — DONE (validate a `.conf` without a device connection).
- Structured streaming progress on the CLI path — DONE. The global `--rpc` flag
  switches stdout to newline-delimited JSON events; the existing `progress`
  callback is wired into `do_get`/`do_set` to emit `{"type":"progress",...}`
  events live (CLI runs are no longer silent until the final result).
- Machine-readable error envelope — DONE. In `--rpc` mode every failure becomes a
  terminal `{"type":"error","message":...,"kind":...}` event on stdout (exit 1).

### The RPC event contract (`--rpc`)

This is the IPC contract a TS/Electron front-end binds to when running the engine
as a subprocess. It is **additive and opt-in**: without `--rpc` the default
single-pretty-JSON / `Error: <text>`-on-stderr behavior is byte-for-byte
unchanged, so nothing existing (the Tk GUI, scripts) breaks.

In `--rpc` mode, stdout is one JSON object per line, each carrying a schema
version `v` (currently `1`; bumped on any non-additive envelope change):

```
{"v":1,"type":"progress","message":"..."}            zero or more, streamed live
{"v":1,"type":"result","data":{...}}                 exactly one on success (exit 0)
{"v":1,"type":"error","message":"...","kind":"..."}  on failure (exit 1), on stdout
```

`result.data` is the *same* payload the command prints in default mode, so the
two modes share one schema — only the framing differs.

Error `kind` is mapped from the engine's existing exception paths, giving a TS
client stable classes to switch on:

| `kind` | Mapped from |
| --- | --- |
| `parse_error` | `SystemExit("...")` — argument/`.conf` validation |
| `connection_error` | non-cancel `RuntimeError` — socket/resolve failure, missing `meshtastic-python`/`pyserial` |
| `timeout` | `TimeoutError` — TCP connect / config readback |
| `cancelled` | `RuntimeError("Operation cancelled.")` — cancel-event path (library-only today) |
| `internal` | any other unexpected `Exception` |

Tested device-independently in `tests/test_rpc_engine.py` (`parse-conf` success +
error, `list-ports`, the `kind` mapping, and that default mode is unchanged); run
with `python -m unittest discover -s tests`.

These define the eventual sidecar/IPC contract and the surface a TS rewrite must
match. The shared `result.data`/error schema means a TS port can validate against
this contract before the Python path is removed — useful for keeping the 2.8
implementation aligned as it heads toward core.

## 5. Roadmap & ownership

| # | Item | Status | Owner |
| --- | --- | --- | --- |
| 1 | Build-time protobuf contract verification | DONE | — |
| 2 | Push `TheWISPRer/protobufs` fork + tag | TODO | **user** (GitHub) |
| 3 | Repoint canonical setup profile to fork+tag | blocked on #2 | one-line change |
| 4 | Upstream PR to reserve tags 17/18/16 | TODO | **user** (upstream) |
| 5 | Post softened-claim follow-up on discussion #10716 | drafted | **user** |
| 6 | Document contract + canonical path (README) | DONE | — |
| 7 | Engine boundary: `list-ports` / `parse-conf` CLI | DONE | — |
| 8 | Engine boundary: `--rpc` streaming events + error envelope | DONE | — |
| 9 | Electron scaffold on `@meshtastic/core` + WG overlay | future | after #2-#4 |

Sequencing rationale: do the in-repo, fully-controlled work (1, 6, 7, 8) now; the
fork push (2-3) and upstream reservation (4-5) are latency-bound and user-owned;
the Electron build (8) sits on a stable contract and should follow it.
