import importlib.util
import pathlib
import unittest

AUDIT = pathlib.Path(__file__).with_name("audit_image.py")
SPEC = importlib.util.spec_from_file_location("audit_image_policy", AUDIT)
audit = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(audit)

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
HID_REPORT = bytes.fromhex(
    "06d0f10901a1010920150026ff007508954081020921150026ff00750895409102c0"
)
USB_DESCRIPTOR = (
    bytes.fromhex("12010002000000400912c153000201020301")
    + bytes.fromhex("090229000101008032090400000203000005")
    + bytes.fromhex("0921110100012222000705810340000107050103400001")
    + HID_REPORT
)


def fixture():
    result = {
        "mode": "development",
        "app_map": ".vendorheader 0x0c050000 0x400\n.header 0x0c050400 0x400\n.flash 0x0c050800 0x1000\n",
        "kernel_map": ".header 0x0c050000 0x400\n.flash 0x0c050400 0x1000\n",
        "app_symbols": {"reset_handler", "g_authenticator_build_audit", "mp_module_trezorauth"},
        "kernel_symbols": {
            "usb_configure",
            "usb_hid_add",
            "usb_webauthn_iface_init",
            "g_authenticator_usb_descriptors",
            "usb_authenticator_descriptors_match",
            "auth_vault_provision",
            "auth_vault_issue_token",
            "auth_call_issue",
            "auth_store_open",
            "auth_store_unlock",
            "auth_store_record_write",
            "auth_credential_create",
            "auth_credential_sign",
            "auth_credential_hmac_secret",
            "auth_resident_set",
            "auth_resident_get",
            "auth_call_credential_sign",
            "flash_area_checked_read",
            "flash_checked_record_eccd",
            "auth_replica_probe",
            "auth_replica_authenticate",
            "auth_records_unlock",
            "auth_replica_io_t3t1",
        },
        "image": b"TRZV vinchlabs aylo AUTH-DEV KERNEL"
        + bytes.fromhex("7c31d8c28e6049298976a86f9c124bb1"),
        "kernel_image": b"KERNEL",
        "build_metadata": b"AUTHM1\x01\x00",
        "usb_descriptor": USB_DESCRIPTOR,
        "frozen": REQUIRED_FROZEN,
        "signatures": (True, False),
        "approved_allocations": set(),
        "official_certs": [b"\x30\x82\x01\x00OFFICIAL_CERT"],
    }
    result["app_elf_image"] = result["image"]
    result["kernel_elf_image"] = result["kernel_image"]
    result["app_header_range"] = (0, 0)
    return result


class AuditPolicyTests(unittest.TestCase):
    def test_requires_credential_operations_in_secure_kernel(self):
        for symbol in ("auth_credential_create","auth_credential_sign","auth_credential_hmac_secret",
                       "auth_resident_set","auth_resident_get","auth_call_credential_sign"):
            with self.subTest(symbol=symbol),self.assertRaisesRegex(ValueError,"vault"):
                audit.check_artifacts(**(fixture()|{"kernel_symbols":fixture()["kernel_symbols"]-{symbol}}))

    def test_rejects_credential_work_buffer_in_application(self):
        with self.assertRaisesRegex(ValueError,"vault"):
            audit.check_artifacts(**(fixture()|{"app_symbols":fixture()["app_symbols"]|{"credential_work"}}))
    def test_rejects_secret_vault_implementation_in_application(self):
        for change in (
            {"app_symbols": fixture()["app_symbols"] | {"auth_backend_verify_pin"}},
            {"app_symbols": fixture()["app_symbols"] | {"auth_call_issue"}},
            {"app_symbols": fixture()["app_symbols"] | {"auth_store_record_read"}},
            {"app_map": fixture()["app_map"] + "libsec.a(authenticator_storage.o)"},
            {"app_map": fixture()["app_map"] + "libsec.a(authenticator.o)"},
        ):
            with self.subTest(change=change), self.assertRaisesRegex(ValueError, "vault"):
                audit.check_artifacts(**(fixture() | change))

    def test_requires_native_binding_and_secure_vault(self):
        for change in (
            {"app_symbols": fixture()["app_symbols"] - {"mp_module_trezorauth"}},
            {"kernel_symbols": fixture()["kernel_symbols"] - {"auth_vault_issue_token"}},
            {"kernel_symbols": fixture()["kernel_symbols"] - {"auth_store_open"}},
            {"kernel_symbols": fixture()["kernel_symbols"] - {"auth_store_unlock"}},
            {"kernel_symbols": fixture()["kernel_symbols"] - {"auth_store_record_write"}},
        ):
            with self.subTest(change=change), self.assertRaisesRegex(ValueError, "vault"):
                audit.check_artifacts(**(fixture() | change))

    def test_rejects_synthetic_native_backend_without_metadata_flag(self):
        sample = fixture() | {"kernel_symbols": fixture()["kernel_symbols"] | {"auth_test_record"}}
        with self.assertRaises(ValueError):
            audit.check_artifacts(**sample)

    def test_signer_header_normalization_does_not_mask_body_mismatch(self):
        sample = fixture()
        sample["app_header_range"] = (4, 8)
        sample["app_elf_image"] = sample["image"][:4] + b"XXXX" + sample["image"][8:]
        audit.check_artifacts(**sample)
        sample["app_elf_image"] = sample["app_elf_image"][:-1] + b"X"
        with self.assertRaisesRegex(ValueError, "application ELF"):
            audit.check_artifacts(**sample)

    def test_rejects_mismatched_app_elf_and_kernel_elf_bytes(self):
        for change in (
            {"app_elf_image": fixture()["image"] + b"stale"},
            {"kernel_elf_image": b"stale kernel"},
        ):
            with self.subTest(change=change), self.assertRaisesRegex(ValueError, "ELF|binary"):
                audit.check_artifacts(**(fixture() | change))

    def test_rejects_embedded_development_public_key_in_production(self):
        production = fixture() | {
            "mode": "production",
            "build_metadata": b"AUTHM1\x01\x08",
            "image": b"TRZV vinchlabs aylo AUTH KERNEL"
            + bytes.fromhex("7c31d8c28e6049298976a86f9c124bb1"),
            "usb_descriptor": USB_DESCRIPTOR[:8] + b"\x34\x12\x78\x56" + USB_DESCRIPTOR[12:],
            "approved_allocations": {(0x1234, 0x5678)},
            "signatures": (False, True),
        }
        production["app_elf_image"] = production["image"]
        production["image"] += bytes.fromhex(
            "d759793bbc13a2819a827c76adb6fba8a49aee007f49f2d0992d99b825ad2c48"
        )
        production["app_elf_image"] = production["image"]
        with self.assertRaisesRegex(ValueError, "development key"):
            audit.check_artifacts(**production)

    def test_allocation_manifest_rejects_reserved_development_and_duplicates(self):
        for source in (
            "0x1209 0x53C1",
            "0x0000 0x1234",
            "0x1234 0xFFFF",
            "0x1234 0x5678\n0x1234 0x5678",
            "0x1234",
        ):
            with self.subTest(source=source), self.assertRaises(ValueError):
                audit.parse_allocations(source)

    def test_official_der_inventory_has_pinned_fingerprints(self):
        repo = AUDIT.resolve().parents[5]
        self.assertEqual(len(audit.load_official_certificates(repo)), 6)

    def test_accepts_development_artifact(self):
        audit.check_artifacts(**fixture())

    def test_rejects_unbound_kernel_or_missing_link_map(self):
        for change in ({"kernel_image": b"OTHER"}, {"app_map": ".header only"}, {"kernel_map": ".flash only"}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                audit.check_artifacts(**(fixture() | change))

    def test_rejects_other_usb_interface_or_bad_hid_descriptor(self):
        for change in (
            {"kernel_symbols": fixture()["kernel_symbols"] | {"usb_vcp_add"}},
            {"usb_descriptor": USB_DESCRIPTOR[:22] + b"\x02" + USB_DESCRIPTOR[23:]},
            {"usb_descriptor": USB_DESCRIPTOR[:32] + b"\x02" + USB_DESCRIPTOR[33:]},
            {"usb_descriptor": USB_DESCRIPTOR[:-1] + b"\0"},
            {"usb_descriptor": USB_DESCRIPTOR + bytes.fromhex("090401000203000005")},
        ):
            with self.subTest(change=change), self.assertRaises(ValueError):
                audit.check_artifacts(**(fixture() | change))

    def test_rejects_test_flags_and_unapproved_sources_in_either_image(self):
        for change in (
            {"build_metadata": b"AUTHM1\x01\x01"},
            {"build_metadata": b"AUTHM1\x01\x02"},
            {"app_symbols": fixture()["app_symbols"] | {"layout_icon_bitmap"}},
            {"kernel_symbols": fixture()["kernel_symbols"] | {"manufacturing_test_entry"}},
            {"app_symbols": fixture()["app_symbols"] | {"display_init"}},
            {"kernel_symbols": fixture()["kernel_symbols"] | {"touch_init"}},
            {"app_symbols": fixture()["app_symbols"] | {"font_roboto"}},
            {"kernel_symbols": fixture()["kernel_symbols"] | {"debuglink_init"}},
            {"frozen": REQUIRED_FROZEN | {"apps/bitcoin/sign_tx.py"}},
        ):
            with self.subTest(change=change), self.assertRaises(ValueError):
                audit.check_artifacts(**(fixture() | change))

    def test_rejects_official_aaguid_and_der_certificate(self):
        for suffix in (
            bytes.fromhex("d6d0bdc362eec4dbde8d7a656e4a4487"),
            b"\x30\x82\x01\x00OFFICIAL_CERT",
        ):
            with self.subTest(suffix=suffix), self.assertRaises(ValueError):
                image = fixture()["image"] + suffix
                audit.check_artifacts(**(fixture() | {"image": image, "app_elf_image": image}))

    def test_rejects_assets_writer_that_would_overwrite_a_replica(self):
        # The third vault replica lives in the assets area, so a linked
        # translations writer could erase a third of the redundancy -- and its
        # syscalls are reachable from the unprivileged application.
        for symbol in ("translations_write", "translations_erase",
                       "translations_read", "translations_area_bytesize"):
            for side in ("app_symbols", "kernel_symbols"):
                change = {side: fixture()[side] | {symbol}}
                with self.subTest(symbol=symbol, side=side), \
                        self.assertRaisesRegex(ValueError, "assets writer"):
                    audit.check_artifacts(**(fixture() | change))
        # A translations symbol that is not one of the four named above still has
        # to be refused, by the name pattern rather than the exact list. Without
        # this case the pattern would be an untested second mechanism.
        for symbol in ("translations_init", "translation_blob_load"):
            with self.subTest(symbol=symbol), \
                    self.assertRaisesRegex(ValueError, "forbidden linked symbol"):
                audit.check_artifacts(
                    **(fixture() | {"kernel_symbols": fixture()["kernel_symbols"] | {symbol}})
                )

    def test_rejects_ordinary_storage_that_would_overwrite_two_replicas(self):
        # Replicas 0 and 1 are STORAGE_AREAS[0] and STORAGE_AREAS[1], the two
        # areas ordinary storage used to own. storage_wipe() erases both in one
        # unprivileged syscall and storage_set() writes a NORCOW header over
        # replica 0, so the subsystem must be absent from this image entirely --
        # not merely left uncalled.
        for symbol in ("storage_init", "storage_setup", "storage_wipe", "storage_set",
                       "storage_delete", "storage_unlock", "storage_change_pin",
                       "norcow_init", "norcow_set", "norcow_wipe", "norcow_delete"):
            for side in ("app_symbols", "kernel_symbols"):
                change = {side: fixture()[side] | {symbol}}
                with self.subTest(symbol=symbol, side=side), \
                        self.assertRaisesRegex(ValueError, "ordinary storage"):
                    audit.check_artifacts(**(fixture() | change))
        # A subsystem symbol outside the named list still has to be refused, by
        # the prefix rather than the exact tuple, so the pattern is not an
        # untested second mechanism.
        for symbol in ("storage_get_encrypted", "norcow_upgrade_finish",
                       "check_storage_version"):
            with self.subTest(symbol=symbol), \
                    self.assertRaisesRegex(ValueError, "ordinary storage"):
                audit.check_artifacts(
                    **(fixture() | {"kernel_symbols": fixture()["kernel_symbols"] | {symbol}})
                )
        # The layout constants are not the subsystem. The replica binding needs
        # STORAGE_AREAS and the sector bounds to address replicas 0 and 1 at all,
        # so the check has to be case-sensitive rather than reuse the
        # case-insensitive forbidden-name pattern.
        audit.check_artifacts(
            **(fixture() | {"kernel_symbols": fixture()["kernel_symbols"] | {
                "STORAGE_AREAS", "STORAGE_1_SECTOR_START", "STORAGE_2_MAXSIZE",
            }})
        )

    def test_requires_replica_vault_symbols_in_secure_kernel(self):
        # These five are the spine of the power-loss design: the checked reader,
        # the two admission decisions, the root recovery, and the T3T1 area
        # binding. All are reachable now that the facade calls them, so
        # --gc-sections keeps them, and their absence means the image fell back
        # to something else.
        for symbol in ("flash_area_checked_read", "flash_checked_record_eccd",
                       "auth_replica_probe",
                       "auth_replica_authenticate", "auth_records_unlock",
                       "auth_replica_io_t3t1"):
            with self.subTest(symbol=symbol), \
                    self.assertRaisesRegex(ValueError, "replica vault"):
                audit.check_artifacts(
                    **(fixture() | {"kernel_symbols": fixture()["kernel_symbols"] - {symbol}})
                )
        # The application must not carry them either: it would mean the vault
        # implementation crossed the privilege boundary.
        for symbol in ("auth_replica_probe", "auth_records_unlock",
                       "auth_replica_io_t3t1"):
            with self.subTest(symbol=symbol, side="app"), \
                    self.assertRaisesRegex(ValueError, "replica vault"):
                audit.check_artifacts(
                    **(fixture() | {"app_symbols": fixture()["app_symbols"] | {symbol}})
                )

    def test_rejects_unvalidated_eccd_probe_symbols(self):
        # The ECC double-error resume path is non-production: it must not be
        # present in an ordinary artifact at all.
        for symbol in ("flash_checked_load_begin", "flash_checked_load_end",
                       "flash_checked_load_recovery", "flash_checked_copy"):
            for side in ("app_symbols", "kernel_symbols"):
                change = {side: fixture()[side] | {symbol}}
                with self.subTest(symbol=symbol, side=side), \
                        self.assertRaisesRegex(ValueError, "ECCD probe"):
                    audit.check_artifacts(**(fixture() | change))

    def test_rejects_the_sd_subsystem_the_confirmation_line_does_not_need(self):
        # The physical confirmation is one GPIO input. A card slot that can be
        # read from or written to is a second way into a device whose whole design
        # is that there is only one, so the subsystem's absence is checked rather
        # than left to the feature list that currently excludes it.
        for symbol in ("sdcard_init", "sdcard_power_on", "sdcard_read_blocks",
                       "HAL_SD_Init", "f_mount", "disk_read"):
            for side in ("app_symbols", "kernel_symbols"):
                change = {side: fixture()[side] | {symbol}}
                with self.subTest(symbol=symbol, side=side), \
                        self.assertRaisesRegex(ValueError, "SD subsystem"):
                    audit.check_artifacts(**(fixture() | change))

    def test_accepts_the_confirmation_line_driver_itself(self):
        # The driver is built on SD_DETECT_PORT and SD_DETECT_PIN, so a rule
        # written as a case-insensitive "sd" pattern would reject the very thing
        # it exists to protect.
        for side in ("app_symbols", "kernel_symbols"):
            change = {side: fixture()[side] | {
                "auth_presence_init", "auth_presence_sample",
                "auth_presence_deinit",
            }}
            with self.subTest(side=side):
                audit.check_artifacts(**(fixture() | change))

    def test_rejects_an_image_that_confirms_what_nobody_confirmed(self):
        # This tool certifies images, and an image that grants presence by itself is
        # not certifiable for any purpose -- so the refusal is not gated on
        # production, unlike the build guard that stops it being compiled there.
        with self.assertRaisesRegex(ValueError, "assumed presence"):
            audit.check_artifacts(
                **(fixture() | {"build_metadata": b"AUTHM1\x01\x10"})
            )

    def test_an_unknown_build_flag_is_still_refused(self):
        # Widening the known set to recognise assumed presence must not have opened
        # the door to a flag this tool has never heard of.
        with self.assertRaisesRegex(ValueError, "test backend, test presence"):
            audit.check_artifacts(
                **(fixture() | {"build_metadata": b"AUTHM1\x01\x20"})
            )

    def test_rejects_development_key_in_production(self):
        production = fixture() | {
            "mode": "production",
            "build_metadata": b"AUTHM1\x01\x08",
            "image": b"TRZV vinchlabs aylo AUTH KERNEL"
            + bytes.fromhex("7c31d8c28e6049298976a86f9c124bb1"),
            "usb_descriptor": USB_DESCRIPTOR[:8] + b"\x34\x12\x78\x56" + USB_DESCRIPTOR[12:],
            "approved_allocations": {(0x1234, 0x5678)},
        }
        production["app_elf_image"] = production["image"]
        with self.assertRaisesRegex(ValueError, "signature"):
            audit.check_artifacts(**production)

    def test_rejects_unapproved_or_development_usb_identity_in_production(self):
        production = fixture() | {
            "mode": "production",
            "build_metadata": b"AUTHM1\x01\x08",
            "image": b"TRZV vinchlabs aylo AUTH KERNEL"
            + bytes.fromhex("7c31d8c28e6049298976a86f9c124bb1"),
            "usb_descriptor": USB_DESCRIPTOR[:8] + b"\x34\x12\x78\x56" + USB_DESCRIPTOR[12:],
            "signatures": (False, True),
        }
        production["app_elf_image"] = production["image"]
        with self.assertRaisesRegex(ValueError, "allocation"):
            audit.check_artifacts(**production)
        production["approved_allocations"] = {(0x1234, 0x5678)}
        audit.check_artifacts(**production)
        production["usb_descriptor"] = fixture()["usb_descriptor"]
        with self.assertRaisesRegex(ValueError, "USB|allocation"):
            audit.check_artifacts(**production)


if __name__ == "__main__":
    unittest.main()
