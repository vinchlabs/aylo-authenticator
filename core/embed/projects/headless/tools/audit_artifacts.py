#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import re
import shutil
import struct
import subprocess
from pathlib import Path
from typing import Any

from elftools.elf.elffile import ELFFile

ROOT = Path(__file__).resolve().parents[5]
ARTIFACTS = ROOT / "core/build-xtask/artifacts/T3T1"
HEADLESS_BIN = ARTIFACTS / "headless.bin"
HEADLESS_ELF = ARTIFACTS / "headless.elf"
HEADLESS_CC = ARTIFACTS / "headless.cc.json"
BOOTLOADER_BIN = ARTIFACTS / "bootloader.bin"
BOOTLOADER_ELF = ARTIFACTS / "bootloader.elf"
BOOTLOADER_CC = ARTIFACTS / "bootloader.cc.json"
HEADLESS_USB_SERIAL = b"TS5HEADLESSDEV0001\x00"


def require_tool(name: str) -> str:
    path = shutil.which(name)
    if path is None:
        raise RuntimeError(f"required tool is not on PATH: {name}")
    return path


def symbols(elf: Path, nm: str) -> dict[str, int]:
    output = subprocess.check_output(
        [nm, "--defined-only", "--format=posix", str(elf)], text=True
    )
    result: dict[str, int] = {}
    for line in output.splitlines():
        fields = line.split()
        if len(fields) >= 3:
            result[fields[0]] = int(fields[2], 16)
    return result


def disassemble(elf: Path, symbol: str, objdump: str) -> str:
    return subprocess.check_output(
        [objdump, "-d", f"--disassemble={symbol}", str(elf)], text=True
    )


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def compile_entry(path: Path, suffix: str) -> dict[str, Any]:
    entries = json.loads(path.read_text())
    matches = [entry for entry in entries if entry.get("file", "").endswith(suffix)]
    if len(matches) != 1:
        raise RuntimeError(
            f"expected one compile entry for {suffix}, got {len(matches)}"
        )
    return matches[0]


def preprocess(entry: dict[str, Any]) -> str:
    arguments = list(entry["arguments"])
    filtered: list[str] = []
    index = 1
    while index < len(arguments):
        argument = arguments[index]
        if argument == "-c":
            index += 1
            continue
        if argument == "-o":
            index += 2
            continue
        filtered.append(argument)
        index += 1
    return subprocess.check_output(
        [arguments[0], "-E", "-P", *filtered],
        cwd=str(entry["directory"]),
        text=True,
    )


def read_virtual(elf: ELFFile, address: int, size: int) -> bytes:
    for section in elf.iter_sections():
        start = section["sh_addr"]
        end = start + section["sh_size"]
        if section["sh_type"] != "SHT_NOBITS" and start <= address <= end - size:
            offset = address - start
            return section.data()[offset : offset + size]
    raise RuntimeError(f"ELF address range is unavailable: 0x{address:08x}+{size}")


def read_c_string(elf: ELFFile, address: int, max_size: int = 128) -> str:
    raw = bytearray()
    for offset in range(max_size):
        value = read_virtual(elf, address + offset, 1)[0]
        if value == 0:
            return raw.decode("ascii")
        raw.append(value)
    raise RuntimeError(f"unterminated ELF string at 0x{address:08x}")


def audit_headless(nm: str, objdump: str) -> None:
    data = HEADLESS_BIN.read_bytes()
    if data[:4] != b"TRZV" or data[1024:1028] != b"TRZF":
        raise RuntimeError("headless image does not contain TRZV+TRZF headers")
    if len(data) > 0x1A0000:
        raise RuntimeError("headless image exceeds FIRMWARE_MAXSIZE")

    syms = symbols(HEADLESS_ELF, nm)
    section_size = (
        syms["_prodtest_cli_cmd_section_end"] - syms["_prodtest_cli_cmd_section_start"]
    )
    expected_handlers = {
        "headless_ping",
        "headless_version",
        "headless_reboot_to_bootloader",
    }
    if section_size != 48 or not expected_handlers.issubset(syms):
        raise RuntimeError("headless CLI section is not exactly three ARM records")

    symbols_by_address: dict[int, set[str]] = {}
    for name, address in syms.items():
        symbols_by_address.setdefault(address & ~1, set()).add(name)

    decoded_records: set[tuple[str, str]] = set()
    with HEADLESS_ELF.open("rb") as elf_file:
        elf = ELFFile(elf_file)
        records = read_virtual(
            elf, syms["_prodtest_cli_cmd_section_start"], section_size
        )
        for offset in range(0, section_size, 16):
            name_ptr, handler_ptr, _info_ptr, _args_ptr = struct.unpack_from(
                "<IIII", records, offset
            )
            command_name = read_c_string(elf, name_ptr)
            handler_names = symbols_by_address.get(handler_ptr & ~1, set())
            matching_handlers = handler_names & expected_handlers
            if len(matching_handlers) != 1:
                raise RuntimeError(
                    f"cannot resolve handler for CLI command {command_name!r}: "
                    f"{sorted(handler_names)}"
                )
            decoded_records.add((command_name, matching_handlers.pop()))

    expected_records = {
        ("ping", "headless_ping"),
        ("version", "headless_version"),
        ("reboot-to-bootloader", "headless_reboot_to_bootloader"),
    }
    if decoded_records != expected_records:
        raise RuntimeError(f"unexpected linked CLI records: {sorted(decoded_records)}")

    forbidden_symbols = sorted(
        name
        for name in syms
        if name.startswith(("prodtest_", "unit_test_"))
        or re.search(r"(?:^|_)otp(?:_|$)|provision|manufacturing_lock", name, re.I)
        or re.search(
            r"(?:flash|storage|secret).*(?:erase|write|provision|wipe)",
            name,
            re.I,
        )
    )
    if forbidden_symbols:
        raise RuntimeError(f"forbidden headless symbols: {forbidden_symbols}")

    compile_commands = json.loads(HEADLESS_CC.read_text())
    usb_entry = compile_entry(HEADLESS_CC, "/io/usb/usb_config.c")
    usb_arguments = set(usb_entry["arguments"])
    if "-DUSE_USB_IFACE_VCP=1" not in usb_arguments:
        raise RuntimeError("headless usb_config.c was not compiled with VCP")
    if {
        "-DUSE_USB_IFACE_WIRE=1",
        "-DUSE_USB_IFACE_DEBUG=1",
    } & usb_arguments:
        raise RuntimeError("headless unexpectedly enables a WinUSB interface")
    if not re.search(
        r"dev_info\.usb21_enabled\s*=\s*0x00000000U\s*;",
        preprocess(usb_entry),
    ):
        raise RuntimeError("headless build does not disable interface-0 WCID")
    if data.count(HEADLESS_USB_SERIAL) != 1:
        raise RuntimeError("headless image lacks one stable cache-busting USB serial")

    project_sources = {
        Path(entry.get("file", "")).name
        for entry in compile_commands
        if "/projects/headless/" in entry.get("file", "")
    }
    prodtest_sources = [
        entry.get("file", "")
        for entry in compile_commands
        if "/projects/prodtest/" in entry.get("file", "")
    ]
    expected_sources = {"main.c", "commands.c", "protocol.c", "header.S"}
    if project_sources != expected_sources or prodtest_sources:
        raise RuntimeError(
            f"unexpected project source set: {project_sources}, {prodtest_sources}"
        )

    main_disassembly = disassemble(HEADLESS_ELF, "main", objdump)
    required_calls = [
        name
        for name in ("usb_configure", "usb_start", "cli_set_line_limit")
        if name not in main_disassembly
    ]
    if required_calls:
        raise RuntimeError(f"missing headless main calls: {required_calls}")
    forbidden_calls = [
        name
        for name in (
            "display_init",
            "touch_init",
            "secure_aes_init",
            "optiga_init",
            "flash_area_erase",
            "storage_init",
        )
        if name in main_disassembly
    ]
    if forbidden_calls:
        raise RuntimeError(f"forbidden headless main calls: {forbidden_calls}")


def audit_bootloader(nm: str, objdump: str) -> None:
    data = BOOTLOADER_BIN.read_bytes()
    if data[:4] != b"TRZB":
        raise RuntimeError("bootloader image does not contain a TRZB header")
    if len(data) != 0x20000:
        raise RuntimeError("bootloader image is not exactly BOOTLOADER_MAXSIZE")

    usb_entry = compile_entry(BOOTLOADER_CC, "/io/usb/usb_config.c")
    usb_arguments = set(usb_entry["arguments"])
    if "-DUSE_USB_IFACE_WIRE=1" not in usb_arguments:
        raise RuntimeError("bootloader usb_config.c lacks its Wire interface")
    if re.search(
        r"dev_info\.usb21_enabled\s*=\s*0x00000000U\s*;",
        preprocess(usb_entry),
    ):
        raise RuntimeError("Wire bootloader unexpectedly disables interface-0 WCID")

    syms = symbols(BOOTLOADER_ELF, nm)
    required_symbols = {
        "headless_should_jump",
        "headless_poll_deadline",
        "headless_is_recognized_message",
        "bootloader_process_usb",
        "real_jump_to_firmware",
        "fw_run_prepare",
    }
    missing = sorted(required_symbols - syms.keys())
    if missing:
        raise RuntimeError(f"missing bootloader symbols: {missing}")

    main_disassembly = disassemble(BOOTLOADER_ELF, "main", objdump)
    required_main_calls = {
        "fw_check",
        "workflow_ifaces_init",
        "bootloader_process_usb",
        "headless_should_jump",
        "headless_poll_deadline",
        "workflow_ifaces_deinit",
    }
    missing_main = sorted(
        name for name in required_main_calls if name not in main_disassembly
    )
    forbidden_main = [
        name
        for name in ("display_init", "touch_init", "display_touch_init")
        if name in main_disassembly
    ]
    if missing_main or forbidden_main:
        raise RuntimeError(
            f"bootloader main audit failed: missing={missing_main}, "
            f"forbidden={forbidden_main}"
        )

    jump_disassembly = disassemble(BOOTLOADER_ELF, "real_jump_to_firmware", objdump)
    required_jump_calls = {
        "fw_run_prepare",
        "secret_prepare_fw",
        "system_deinit",
        "jump_to_next_stage",
    }
    missing_jump = sorted(
        name for name in required_jump_calls if name not in jump_disassembly
    )
    forbidden_jump = [
        name
        for name in ("display_", "touch_", "ui_screen_", "ui_fade")
        if name in jump_disassembly
    ]
    if missing_jump or forbidden_jump:
        raise RuntimeError(
            f"bootloader jump audit failed: missing={missing_jump}, "
            f"forbidden={forbidden_jump}"
        )


def main() -> None:
    nm = require_tool("arm-none-eabi-nm")
    objdump = require_tool("arm-none-eabi-objdump")
    headertool = require_tool("headertool")

    for path in (
        HEADLESS_BIN,
        HEADLESS_ELF,
        HEADLESS_CC,
        BOOTLOADER_BIN,
        BOOTLOADER_ELF,
        BOOTLOADER_CC,
    ):
        if not path.is_file():
            raise RuntimeError(f"missing artifact: {path}")

    audit_headless(nm, objdump)
    audit_bootloader(nm, objdump)

    subprocess.run([headertool, "--dry-run", "--quiet", str(HEADLESS_BIN)], check=True)
    subprocess.run(
        [headertool, "--dry-run", "--quiet", str(BOOTLOADER_BIN)], check=True
    )

    print(f"headless.bin   {HEADLESS_BIN.stat().st_size:6d} {sha256(HEADLESS_BIN)}")
    print(f"bootloader.bin {BOOTLOADER_BIN.stat().st_size:6d} {sha256(BOOTLOADER_BIN)}")
    print("artifact audit: PASS")


if __name__ == "__main__":
    main()
