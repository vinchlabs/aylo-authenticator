# T3T1 headless USB development application

This project is a development-only Trezor Safe 5 (`T3T1`) application for a
board without a display or touch panel. It exposes a Windows USB virtual COM
port and deliberately supports only three text commands. It is not wallet or
production firmware and must never protect funds or valuable credentials.

## Interface

Commands are ASCII and newline terminated:

| Command | Reply | Effect |
|---|---|---|
| `ping [text]` | `OK [text]` | Echoes one argument of at most 64 bytes. |
| `version` | `OK ts5-headless-dev 0.1.0 T3T1` | Reports this application. |
| `reboot-to-bootloader` | `OK`, then reset | Requests persistent bootloader mode through the existing boot argument mechanism. |

The maximum input line is 128 bytes. Unknown, malformed, 129-byte, and
oversized-ping inputs return `ERROR` and are not dispatched. No manufacturing,
OTP, storage, provisioning, FIDO, or wallet command is linked.

## Build and offline checks

Use the repository's pinned Nix and uv environment:

```sh
nix-shell
uv sync --locked
source .venv/bin/activate

xtask build headless -m t3t1 --bootloader-devel
xtask build bootloader -m t3t1 --bootloader-devel --headless-dev
```

The physical rev.F PCB uses the current T3T1 firmware board mapping `revE`.
`--headless-dev` is a dedicated bootloader-only opt-in; a plain
`--bootloader-devel` build retains the normal upstream display workflow.
Outputs are:

```text
core/build-xtask/artifacts/T3T1/headless.bin
core/build-xtask/artifacts/T3T1/bootloader.bin
```

Both must report model `T3T1`, development signatures, and valid hashes:

```sh
headertool --dry-run --verbose core/build-xtask/artifacts/T3T1/headless.bin
headertool --dry-run --verbose core/build-xtask/artifacts/T3T1/bootloader.bin
sha256sum core/build-xtask/artifacts/T3T1/{headless,bootloader}.bin
```

Current reviewed offline outputs from the dirty detached checkout at `676049d`:

```text
headless.bin   57856 bytes   422ec0e3cd2066414031af04b6ead9c2e0790405a8c4d0ce6fc57c59a32fd5ca
bootloader.bin 131072 bytes  3f8abba2163a13c50c5f0e0b7a98163c106fa8390a2cf4285936df955d892c66
```

Rebuild and re-record hashes after every source or commit change. Run the
repeatable gate from the repository root inside the Nix/uv environment:

```sh
core/embed/projects/headless/tools/run-offline-checks.sh
```

This runner performs host tests, plain-development/production regression
checks, both signed builds, header/symbol/source/call-path audits, and contains
no upload, flash, reset, or OpenOCD command.

## Boot and update behavior

With no valid application, or after `reboot-to-bootloader`, the development
bootloader remains available indefinitely. With a valid application and no
forced loader request, it exposes its USB update interface for five seconds.
A recognized bootloader protocol request latches update mode; USB enumeration
alone does not. On timeout it repeats firmware verification, deinitializes USB,
and jumps without display/touch presentation.

After the one-time reviewed bootloader update, normal application updates use
the bootloader USB interface, not SWD:

```sh
xtask upload headless -m t3t1
```

Do not run this until the device is confirmed in bootloader mode and the exact
binary/header/hash have been reviewed. A first installation on an empty device
uses the upstream bootloader policy: it erases the complete firmware area and
may erase storage/regenerate BHK. This is a persistent operation and requires
explicit approval.

## Windows COM smoke test

Find the application COM port in Device Manager or PowerShell, then run:

```powershell
powershell -ExecutionPolicy Bypass -File .\core\embed\projects\headless\tools\headless-com-smoke.ps1 -SelfTest
powershell -ExecutionPolicy Bypass -File .\core\embed\projects\headless\tools\headless-com-smoke.ps1 -Port COM7
```

The default live smoke test does not reboot. Explicitly return to the updater
only when intended:

```powershell
powershell -ExecutionPolicy Bypass -File .\core\embed\projects\headless\tools\headless-com-smoke.ps1 -Port COM7 -RebootToBootloader
```

## Wiring and recovery

For emergency SWD recovery only:

| TS5 J102 pad | Signal | Raspberry Pi 5 |
|---:|---|---|
| 2 | SWDIO | physical pin 24 / GPIO8 |
| 3 | GND | physical pin 20 / GND |
| 4 | SWCLK | physical pin 23 / GPIO11 |

Power the TS5 independently through USB-C. Never connect Pi 3.3 V or 5 V.
NRST/pad 10 is not required. Raspberry Pi 5 must use OpenOCD linuxgpiod, not
`bcm2835gpio`.

If the application is broken, start the host updater and reconnect USB-C so it
can claim the five-second bootloader window. Use SWD only if USB recovery fails.
Before every SWD write, repeat read-only MCU/protection checks and full
bootloader readback, present exact erase/write ranges, and obtain explicit
approval.

Never use mass erase, `stm32l4x unlock`, RDP transitions, option-byte changes,
production provisioning, OTP writes, or secret/storage reads as a shortcut.
The existing boardloader and development TrustZone configuration are outside
this application's update scope.
