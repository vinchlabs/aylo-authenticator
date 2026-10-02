"""Audit the linked application, embedded kernel, USB contract, and image identity.

Development and production are separate policies. Production remains unavailable
until a reviewed USB allocation is committed to approved_usb_allocations.txt.
"""

import argparse
import hashlib
import re
from pathlib import Path

OFFICIAL_AAGUID = bytes.fromhex("d6d0bdc362eec4dbde8d7a656e4a4487")
PROJECT_AAGUID = bytes.fromhex("7c31d8c28e6049298976a86f9c124bb1")
DEV_IDENTITY = (0x1209, 0x53C1)
DEV_PRODUCT = b"aylo AUTH-DEV"
PROD_PRODUCT = b"aylo AUTH"
# The other two strings a host shows about this device. Neither decides anything
# about security, and both are checked anyway: an image that still called itself
# somebody else's would be telling every platform that lists it something untrue.
MANUFACTURER = b"vinchlabs"
FOREIGN_IDENTITY = (b"SatoshiLabs", b"Trezor Company", b"Trezor DIY",
                    b"TREZOR Interface", b"TS5 Authenticator")
HID_REPORT = bytes.fromhex(
    "06d0f10901a1010920150026ff007508954081020921150026ff00750895409102c0"
)
REQUIRED_FROZEN = {
    "apps/__init__.py",
    "apps/authenticator/__init__.py",
    "apps/authenticator/cbor_codec.py",
    "apps/authenticator/client_pin.py",
    "apps/authenticator/command_types.py",
    "apps/authenticator/credential.py",
    "apps/authenticator/credential_management.py",
    "apps/authenticator/dispatcher.py",
    "apps/authenticator/get_assertion.py",
    "apps/authenticator/get_info.py",
    "apps/authenticator/make_credential.py",
    "apps/authenticator/pin_protocol.py",
    "apps/authenticator/policy.py",
    "apps/authenticator/presence.py",
    "apps/authenticator/protocol.py",
    "apps/authenticator/reset.py",
    "apps/authenticator/resident_store.py",
    "apps/authenticator/storage.py",
    "apps/authenticator/transport.py",
    "apps/authenticator/transport_types.py",
    "authenticator_boot.py",
    "authenticator_session.py",
    "trezor/__init__.py",
    "trezor/crypto.py",
    "trezor/loop.py",
    "storage/__init__.py",
    "storage/authenticator.py",
}
ALLOWED_FROZEN = REQUIRED_FROZEN
FORBIDDEN_NAME = re.compile(
    r"(display|touch|haptic|framebuffer|dma2d|layout|font|icon|wallet|"
    r"manufacturing|prodtest|factory_test|debuglink|usb_vcp|usb_webusb|usb_wire|cdc|"
    r"translations?_|"
    r"authenticator_test_(backend|presence)|auth_test_|integration_credentials)",
    re.I,
)
# The assets area holds the third vault replica on this project, so anything that
# writes or erases it as a UI resource would destroy a third of the redundancy.
# translations_write()/translations_erase() target ASSETS_AREA directly and are
# reachable from the unprivileged application as syscalls, so the whole subsystem
# is excluded from this build rather than merely left unused. Covered by
# FORBIDDEN_NAME above; named here so the reason is not lost.
ASSETS_WRITER_NAMES = (
    "translations_write",
    "translations_erase",
    "translations_read",
    "translations_area_bytesize",
)
# Replicas 0 and 1 are STORAGE_AREAS[0] and STORAGE_AREAS[1] -- the two areas
# ordinary storage owned before the vault took the raw bytes. They are no longer
# shared: storage_wipe() erases both of them, and storage_set() writes a NORCOW
# header over replica 0's snapshot. Both are reachable from the unprivileged
# application as syscalls behind the trezorconfig module, so one import would
# destroy two thirds of the redundancy the whole design exists to provide. The
# subsystem is therefore excluded from this image rather than merely left
# uncalled, and this is where that exclusion is enforced.
#
# Named here as well as matched by prefix below, so that the reason survives.
STORAGE_SUBSYSTEM_NAMES = (
    "storage_init",
    "storage_setup",
    "storage_wipe",
    "storage_set",
    "storage_delete",
    "storage_unlock",
    "storage_change_pin",
    "storage_change_wipe_code",
    "storage_set_counter",
    "storage_next_counter",
    "norcow_init",
    "norcow_set",
    "norcow_wipe",
    "norcow_delete",
)
# Case-sensitive on purpose. STORAGE_AREAS, STORAGE_1_SECTOR_START and the rest
# of the uppercase layout constants are what the replica binding uses to address
# replicas 0 and 1; they are the memory map, not the subsystem. Reusing the
# case-insensitive FORBIDDEN_NAME pattern would reject the binding itself.
STORAGE_SUBSYSTEM_NAME = re.compile(r"^(norcow_|storage_|check_storage_version)")
# The spine of the power-loss design, required in the kernel and forbidden in the
# application. Every one is reachable now that the storage facade calls it, so
# --gc-sections keeps it; absence means the image is not running this design.
REPLICA_VAULT_NAMES = (
    "flash_area_checked_read",
    # Without this an ECC double error would take the device down without
    # recording which replica caused it, and the next boot would die the same
    # way. Its absence is the difference between one lost boot and a brick.
    "flash_checked_record_eccd",
    "auth_replica_probe",
    "auth_replica_authenticate",
    "auth_records_unlock",
    "auth_replica_io_t3t1",
)
# The abandoned ECC double-error resume path: a naked-asm copy window whose
# stacked return address the NMI rewrote. It was removed once measurement showed
# on hardware that an ECCD cannot be produced by software at all, so its
# containment could never be validated. These names are still listed because a
# check that keeps a deleted design deleted is worth more than one that merely
# confirmed it was feature-gated: if any of them reappears in an image, someone
# has revived resuming out of an asynchronous fault.
PROBE_NAMES = (
    "flash_checked_load_begin",
    "flash_checked_load_end",
    "flash_checked_load_recovery",
    "flash_checked_copy",
    "flash_checked_try_handle_eccd",
    "flash_checked_decide_eccd",
)
# The physical confirmation is one GPIO input, read by a driver that is incapable
# of talking to a card: no SDMMC peripheral, no card power, no clock to the card,
# no command or data pins, no filesystem. These are the names that would appear if
# any of that came back, and a card slot that can be read from or written to is a
# second way into a device whose whole design is that there is only one. Listed
# rather than trusted, the same way PROBE_NAMES keeps a deleted design deleted.
#
# Case-sensitive membership, not a pattern: SD_DETECT_PORT and SD_DETECT_PIN are
# the macros this driver is built on, and a case-insensitive "sd" rule would
# reject the confirmation line itself.
SD_SUBSYSTEM_NAMES = (
    "sdcard_init",
    "sdcard_deinit",
    "sdcard_is_present",
    "sdcard_power_on",
    "sdcard_power_on_unchecked",
    "sdcard_power_off",
    "sdcard_read_blocks",
    "sdcard_write_blocks",
    "sdcard_get_capacity_in_bytes",
    "sdcard_default_pin_state",
    "sdcard_active_pin_state",
    "HAL_SD_Init",
    "HAL_SD_DeInit",
    "HAL_SD_MspInit",
    "HAL_SD_MspDeInit",
    "HAL_SD_ReadBlocks",
    "HAL_SD_WriteBlocks",
    "HAL_SD_ReadBlocks_DMA",
    "HAL_SD_WriteBlocks_DMA",
    "HAL_SD_GetCardState",
    "SDMMC_CmdAppCommand",
    "SDMMC_CmdSetClrCardDetect",
    # FatFs is not vendored in this tree today. The entry points are named anyway,
    # because the point of this list is the image it refuses tomorrow.
    "f_mount",
    "f_open",
    "f_read",
    "f_write",
    "disk_initialize",
    "disk_read",
    "disk_write",
)
FORBIDDEN_IMAGE_STRING = (
    b"apps/bitcoin/",
    b"apps/ethereum/",
    b"apps/webauthn/fido2.py",
    b"manufacturing_test",
    b"prodtest",
    b"debuglink",
)
OFFICIAL_CERT_FINGERPRINTS = {
    "core/tools/codegen/fido/att_cert.der": "06171521461d36d088ed1eb3eb9178cfaa840d4e6e63a82e70cec029fb7203cf",
    "core/embed/sec/secret/unix/certs/T3W1.der": "d6ab4e4371b9bb1de0399cc895da9c8750e05df69f3f72646941e128bb6e658d",
    "core/embed/sec/optiga/unix/certs/T2B1.der": "eeb363d0ae4658f0094309633221a6183bbebd810b2e0d049ff660d615c3cec3",
    "core/embed/sec/optiga/unix/certs/T3B1.der": "544579e03b3873704697ff3b9898f084fbed1eaaa7f80b845679ac9d1ad155bf",
    "core/embed/sec/optiga/unix/certs/T3T1.der": "e8456966682be783d12a02143d7bf75a15d3a2aac410426e54f9f1b5adf8a9b8",
    "core/embed/sec/optiga/unix/certs/T3W1.der": "125146b2836658d22fb5303858eb2cd1662cbc16da245369f56e8b23a246e310",
}
# Public development verification keys only. No private signing material is
# stored by this audit. Sources: trezorlib/firmware/models.py and sec/image.c.
DEVELOPMENT_PUBLIC_KEYS = tuple(
    bytes.fromhex(value)
    for value in (
        "db995fe25169d141cab9bbba92baa01f9f2e1ece7df4cb2ac05190f37fcc1f9d",
        "2152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db12",
        "22fc297792f0b6ffc0bfcfdb7edb0c0aa14e025a365ec0e342e86e3829cb74b6",
        "d759793bbc13a2819a827c76adb6fba8a49aee007f49f2d0992d99b825ad2c48",
        "6355691c178a8ff91007a7478afb955ef7352c63e7b25703984cf78b26e21a56",
        "ee93a4f66f8d16b819bb9beb9ffccdfcdc1412e87fee6a324c2a99a1e0e67148",
        "ec01e60263024f7e71728013b731f7ba1299f518c27ba3ed8f4a219974127c62",
        "8af8878085946ed8b116bd24c0f2aac48b7e8f11bf068725ccfbb152abf7a4cd",
    )
)


def parse_allocations(data: str) -> set[tuple[int, int]]:
    allocations = set()
    for line in data.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) != 2 or any(not re.fullmatch(r"0[xX][0-9a-fA-F]{4}", p) for p in parts):
            raise ValueError("malformed approved USB allocation")
        pair = (int(parts[0], 16), int(parts[1], 16))
        if pair == DEV_IDENTITY or any(value in (0, 0xFFFF) for value in pair) or pair in allocations:
            raise ValueError("development, reserved, or duplicate USB allocation")
        allocations.add(pair)
    return allocations


def load_official_certificates(repo: Path) -> list[bytes]:
    found = {
        str(path.relative_to(repo))
        for path in (repo / "core/embed/sec").glob("**/certs/*.der")
    }
    found.add("core/tools/codegen/fido/att_cert.der")
    if found != OFFICIAL_CERT_FINGERPRINTS.keys():
        raise ValueError("official DER certificate inventory changed; review fingerprints")
    certs = []
    for name, fingerprint in OFFICIAL_CERT_FINGERPRINTS.items():
        cert = (repo / name).read_bytes()
        if hashlib.sha256(cert).hexdigest() != fingerprint:
            raise ValueError(f"official DER certificate fingerprint changed: {name}")
        certs.append(cert)
    return certs


def _has_output_section(link_map: str, name: str) -> bool:
    return bool(re.search(rf"^{re.escape(name)}\s+0x[0-9a-f]+\s+0x[0-9a-f]+", link_map, re.M))


def check_artifacts(
    *,
    mode: str,
    app_map: str,
    kernel_map: str,
    app_symbols: set[str],
    kernel_symbols: set[str],
    image: bytes,
    kernel_image: bytes,
    app_elf_image: bytes,
    kernel_elf_image: bytes,
    app_header_range: tuple[int, int],
    build_metadata: bytes,
    usb_descriptor: bytes,
    frozen: set[str],
    signatures: tuple[bool, bool],
    approved_allocations: set[tuple[int, int]],
    official_certs: list[bytes],
) -> None:
    if mode not in ("development", "production"):
        raise ValueError("unknown audit mode")
    if not all(_has_output_section(app_map, name) for name in (".vendorheader", ".header", ".flash")):
        raise ValueError("application link map lacks firmware sections")
    if not all(_has_output_section(kernel_map, name) for name in (".header", ".flash")):
        raise ValueError("kernel link map lacks firmware sections")
    if not kernel_image or image.count(kernel_image) != 1:
        raise ValueError("audited kernel is not embedded in the application image")
    if kernel_elf_image != kernel_image:
        raise ValueError("kernel ELF does not match embedded kernel binary")
    header_start, header_end = app_header_range
    if not 0 <= header_start <= header_end <= len(image) or len(app_elf_image) != len(image):
        raise ValueError("application ELF/image length or header range mismatch")
    if (
        app_elf_image[:header_start] != image[:header_start]
        or app_elf_image[header_end:] != image[header_end:]
    ):
        raise ValueError("application ELF does not match signed upload binary outside its header")
    if not {"reset_handler", "g_authenticator_build_audit"} <= app_symbols:
        raise ValueError("application ELF lacks authenticator entry or audit marker")
    if "mp_module_trezorauth" not in app_symbols or not {
        "auth_vault_provision", "auth_vault_issue_token", "auth_call_issue",
        # The storage facade's own entry points. auth_store_inventory() was the
        # NORCOW-era record walk and no longer exists; admission, root recovery
        # and a resident write are what the facade offers now.
        "auth_store_open", "auth_store_unlock", "auth_store_record_write",
        "auth_credential_create", "auth_credential_sign", "auth_credential_hmac_secret",
        "auth_resident_set", "auth_resident_get", "auth_call_credential_sign"
    } <= kernel_symbols:
        raise ValueError("native binding or secure kernel vault missing")
    missing_vault = sorted(set(REPLICA_VAULT_NAMES) - kernel_symbols)
    if missing_vault:
        raise ValueError(f"replica vault symbol missing from kernel: {missing_vault[0]}")
    leaked_vault = sorted(set(REPLICA_VAULT_NAMES) & app_symbols)
    if leaked_vault:
        raise ValueError(
            f"replica vault implementation linked into application: {leaked_vault[0]}"
        )
    if {"credential_work"} & app_symbols or any(name.startswith(("auth_backend_", "auth_call_", "auth_store_")) for name in app_symbols) or re.search(
        r"libsec\.a\(authenticator(?:_backend|_call|_storage)?\.o\)", app_map
    ):
        raise ValueError("secret vault implementation linked into application")
    if not {
        "usb_configure",
        "usb_hid_add",
        "g_authenticator_usb_descriptors",
        "usb_authenticator_descriptors_match",
    } <= kernel_symbols:
        raise ValueError("USB WebAuthn HID path missing from linked kernel")
    linked_probe = sorted(set(PROBE_NAMES) & (app_symbols | kernel_symbols))
    if linked_probe:
        raise ValueError(
            f"unvalidated ECCD probe symbol linked: {linked_probe[0]}"
        )
    linked_assets_writer = sorted(
        set(ASSETS_WRITER_NAMES) & (app_symbols | kernel_symbols)
    )
    if linked_assets_writer:
        raise ValueError(
            "assets writer would overwrite a vault replica: "
            f"{linked_assets_writer[0]}"
        )
    linked_sd = sorted(set(SD_SUBSYSTEM_NAMES) & (app_symbols | kernel_symbols))
    if linked_sd:
        raise ValueError(
            "the confirmation line reads one pin; the SD subsystem must not be "
            f"linked: {linked_sd[0]}"
        )
    linked_storage = sorted(
        name
        for name in app_symbols | kernel_symbols
        if name in STORAGE_SUBSYSTEM_NAMES or STORAGE_SUBSYSTEM_NAME.search(name)
    )
    if linked_storage:
        raise ValueError(
            "ordinary storage would overwrite replicas 0 and 1: "
            f"{linked_storage[0]}"
        )
    for name in app_symbols | kernel_symbols:
        if FORBIDDEN_NAME.search(name):
            raise ValueError(f"forbidden linked symbol: {name}")
    if any(token.lower() in image.lower() for token in FORBIDDEN_IMAGE_STRING):
        raise ValueError("forbidden image string")
    if build_metadata[:7] != b"AUTHM1\x01" or len(build_metadata) != 8:
        raise ValueError("missing or invalid authenticator build metadata")
    flags = build_metadata[7]
    # Bit 8 is the production marker, which belongs there; bit 16 is assumed
    # presence, recognised here so that it earns its own message below instead of
    # being reported as a flag this tool has never heard of.
    if flags & 0x07 or flags & ~0x1F:
        raise ValueError("test backend, test presence, or integration credentials linked")
    if flags & 0x10:
        # Refused in both modes, not only production. The purpose of this tool is to
        # certify an image, and an image that confirms operations nobody confirmed
        # is not certifiable -- in any mode, for any purpose. The build guard stops
        # it reaching production; this stops it being called audited.
        raise ValueError(
            "assumed presence linked: this image confirms operations nobody confirmed"
        )
    # This is the packed, runtime-consumed device + configuration + HID +
    # report descriptor aggregate, not a separately handwritten audit record.
    device = usb_descriptor[:18]
    config = usb_descriptor[18:27]
    iface = usb_descriptor[27:36]
    hid = usb_descriptor[36:45]
    ep_in = usb_descriptor[45:52]
    ep_out = usb_descriptor[52:59]
    report = usb_descriptor[59:]
    if (
        len(usb_descriptor) != 93
        or device[:8] != bytes.fromhex("1201000200000040")
        or device[12:] != bytes.fromhex("000201020301")
        or config != bytes.fromhex("090229000101008032")
        or iface != bytes.fromhex("090400000203000005")
        or hid != bytes.fromhex("092111010001222200")
        or ep_in != bytes.fromhex("07058103400001")
        or ep_out != bytes.fromhex("07050103400001")
        or report != HID_REPORT
    ):
        raise ValueError("USB descriptor must contain exactly one valid WebAuthn HID interface")
    identity = (
        int.from_bytes(device[8:10], "little"),
        int.from_bytes(device[10:12], "little"),
    )
    if not frozen or frozen != ALLOWED_FROZEN:
        raise ValueError("frozen module manifest is not the minimal approved set")
    if OFFICIAL_AAGUID in image or PROJECT_AAGUID not in image:
        raise ValueError("official AAGUID present or project AAGUID missing")
    if MANUFACTURER not in image:
        raise ValueError("the image does not say who made it")
    for name in FOREIGN_IDENTITY:
        if name in image:
            raise ValueError(f"foreign identity string in the image: {name!r}")
    for cert in official_certs:
        if cert and cert in image:
            digest = hashlib.sha256(cert).hexdigest()
            raise ValueError(f"official DER certificate embedded: sha256={digest}")
    if b"-----BEGIN CERTIFICATE-----" in image:
        raise ValueError("PEM certificate embedded")
    dev_signed, prod_signed = signatures
    if mode == "development":
        if flags & 0x08 or identity != DEV_IDENTITY or DEV_PRODUCT not in image:
            raise ValueError("development USB identity or build mode mismatch")
        if not dev_signed or prod_signed:
            raise ValueError("development signature policy failed")
    else:
        if not flags & 0x08 or identity not in approved_allocations or identity == DEV_IDENTITY:
            raise ValueError("production USB identity is not an approved allocation")
        if PROD_PRODUCT not in image or DEV_PRODUCT in image or b"AUTH-DEV" in image:
            raise ValueError("development identity in production image")
        if not prod_signed or dev_signed:
            raise ValueError("production signature policy failed")
        if any(key in image or key in kernel_image for key in DEVELOPMENT_PUBLIC_KEYS):
            raise ValueError("embedded development key material in production artifact")


def _elf_facts(path: Path) -> tuple[set[str], dict[str, bytes]]:
    from elftools.elf.elffile import ELFFile

    with path.open("rb") as handle:
        elf = ELFFile(handle)
        table = elf.get_section_by_name(".symtab")
        if table is None:
            raise ValueError(f"{path}: ELF symbol table missing")
        symbols = set()
        data = {}
        for symbol in table.iter_symbols():
            if not symbol.name or symbol["st_info"]["bind"] == "STB_WEAK":
                continue
            section_index = symbol["st_shndx"]
            if not isinstance(section_index, int):
                continue
            section = elf.get_section(section_index)
            if not section["sh_flags"] & 0x2:  # SHF_ALLOC
                continue
            symbols.add(symbol.name)
            if symbol["st_size"] and symbol["st_info"]["type"] == "STT_OBJECT":
                offset = symbol["st_value"] - section["sh_addr"]
                data[symbol.name] = section.data()[offset : offset + symbol["st_size"]]
        return symbols, data


def _elf_flash_image(path: Path, *, signed_application: bool) -> tuple[bytes, tuple[int, int]]:
    """Recreate xtask's flash objcopy from PT_LOAD LMAs, excluding RAM-only data.

    The firmware signer changes the application .header after objcopy. Those
    bytes are normalized here; cryptographic signature verification separately
    authenticates the actual signed header and body.
    """
    from elftools.elf.elffile import ELFFile

    with path.open("rb") as handle:
        elf = ELFFile(handle)
        segments = sorted(
            (
                segment for segment in elf.iter_segments()
                if segment["p_type"] == "PT_LOAD"
                and segment["p_filesz"]
                and 0x0C000000 <= segment["p_paddr"] < 0x10000000
            ),
            key=lambda segment: segment["p_paddr"],
        )
        if not segments:
            raise ValueError("ELF has no flash load segments")
        base = segments[0]["p_paddr"]
        cursor = base
        chunks = []
        for segment in segments:
            if segment["p_paddr"] != cursor:
                raise ValueError("ELF flash load segments are not contiguous")
            data = segment.data()
            if len(data) != segment["p_filesz"]:
                raise ValueError("ELF flash load segment is truncated")
            chunks.append(data)
            cursor += len(data)
        image = b"".join(chunks)
        header_range = (0, 0)
        if signed_application:
            header = elf.get_section_by_name(".header")
            if header is None or header["sh_size"] != 0x400:
                raise ValueError("application ELF lacks canonical signing header")
            start = header["sh_addr"] - base
            header_range = (start, start + header["sh_size"])
        else:
            # xtask embeds the separately linked kernel from .flash onward;
            # its vendor/header sections are not part of kernel.bin.
            flash = elf.get_section_by_name(".flash")
            if flash is None or flash["sh_addr"] < base:
                raise ValueError("kernel ELF lacks flash section")
            image = image[flash["sh_addr"] - base :]
        return image, header_range


def _signatures(image: bytes) -> tuple[bool, bool]:
    from trezorlib import firmware

    parsed = firmware.parse(image)
    verified = []
    for dev_keys in (True, False):
        try:
            parsed.verify(dev_keys=dev_keys)
            verified.append(True)
        except firmware.FirmwareIntegrityError:
            verified.append(False)
    return verified[0], verified[1]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=("development", "production"), required=True)
    for option in ("map", "kernel-map", "app-elf", "kernel-elf", "image", "kernel-bin", "frozen"):
        parser.add_argument("--" + option, type=Path, required=True)
    args = parser.parse_args()
    app_symbols, app_data = _elf_facts(args.app_elf)
    kernel_symbols, kernel_data = _elf_facts(args.kernel_elf)
    frozen = set(
        re.findall(r"^// - frozen file name: (.+)$", args.frozen.read_text(), re.M)
    )
    repo = Path(__file__).resolve().parents[5]
    image = args.image.read_bytes()
    app_elf_image, app_header_range = _elf_flash_image(args.app_elf, signed_application=True)
    kernel_elf_image, _ = _elf_flash_image(args.kernel_elf, signed_application=False)
    check_artifacts(
        mode=args.mode,
        app_map=args.map.read_text(),
        kernel_map=args.kernel_map.read_text(),
        app_symbols=app_symbols,
        kernel_symbols=kernel_symbols,
        image=image,
        kernel_image=args.kernel_bin.read_bytes(),
        app_elf_image=app_elf_image,
        kernel_elf_image=kernel_elf_image,
        app_header_range=app_header_range,
        build_metadata=app_data.get("g_authenticator_build_audit", b""),
        usb_descriptor=kernel_data.get("g_authenticator_usb_descriptors", b""),
        frozen=frozen,
        signatures=_signatures(image),
        approved_allocations=parse_allocations(
            Path(__file__).with_name("approved_usb_allocations.txt").read_text()
        ),
        official_certs=load_official_certificates(repo),
    )
    print(f"authenticator {args.mode} image audit: PASS")


if __name__ == "__main__":
    main()
