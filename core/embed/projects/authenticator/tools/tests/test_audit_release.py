"""The release gate, rule by rule.

One good record, and then one spoiled copy per rule. A fixture that fails for the
wrong reason is as useless as one that passes, so every negative case asserts the
reason it expects to see and not merely that something was refused.
"""

import hashlib
import importlib.util
import pathlib
import unittest

TOOLS = pathlib.Path(__file__).resolve().parents[1]

_spec = importlib.util.spec_from_file_location(
    "audit_release", TOOLS / "audit_release.py")
audit_release = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(audit_release)

IMAGE = b"\xf1\xd0" + bytes(range(256)) * 8


def good(mode="production", image=IMAGE):
    """A record that describes this image and answers everything."""
    return {
        "mode": mode,
        "model": "T3T1",
        "product": "authenticator",
        "source_commit": "a" * 40,
        "submodules": {"vendor/micropython": "b" * 40},
        "toolchain": {"rustc": "1.88.0", "arm-none-eabi-gcc": "13.2.0"},
        "build_command": "cargo run -p xtask -- build authenticator -m t3t1",
        "unsigned_sha256": hashlib.sha256(b"unsigned").hexdigest(),
        "image_sha256": hashlib.sha256(image).hexdigest(),
        "image_bytes": len(image),
        "security_version": 3,
        "usb_identity": {"vendor": 0x1209, "product": 0x0001},
        "signing_keys": {"generation": 1, "development": False},
        "checklist": {item: True
                      for item in audit_release.PRODUCTION_CHECKLIST},
    }


def reasons(record, image=IMAGE):
    return audit_release.check_release(record, image, "test.bin")


class ReleaseAuditTests(unittest.TestCase):
    def assertRefusedFor(self, record, fragment, image=IMAGE):
        found = reasons(record, image)
        self.assertTrue(found, "the record was accepted")
        self.assertTrue(any(fragment in reason for reason in found),
                        "refused, but not for %r: %r" % (fragment, found))

    def test_a_good_production_record_passes(self):
        self.assertEqual(reasons(good()), [])

    def test_a_good_development_record_passes(self):
        # Development is allowed the development keys and identity, and is still held
        # to the record describing the bytes.
        record = good(mode="development")
        record["signing_keys"] = {"generation": 0, "development": True}
        record["usb_identity"] = {"vendor": 0x1209, "product": 0x53C1}
        record["checklist"] = {}
        self.assertEqual(reasons(record), [])

    def test_every_required_field_is_required(self):
        for field in audit_release.REQUIRED_FIELDS:
            record = good()
            del record[field]
            self.assertRefusedFor(record, "does not say %s" % field)

    def test_a_record_describing_other_bytes_is_refused(self):
        # The rule that makes every other field mean something.
        record = good()
        record["image_sha256"] = hashlib.sha256(b"something else").hexdigest()
        self.assertRefusedFor(record, "hashes to")

    def test_a_truncated_image_is_refused(self):
        record = good(image=IMAGE)
        self.assertRefusedFor(record, "bytes, the image is", image=IMAGE[:-1])

    def test_a_digest_in_another_spelling_is_refused(self):
        record = good()
        record["image_sha256"] = "sha256:" + hashlib.sha256(IMAGE).hexdigest()
        self.assertRefusedFor(record, "lowercase hex sha256")
        record = good()
        record["image_sha256"] = hashlib.sha256(IMAGE).hexdigest().upper()
        self.assertRefusedFor(record, "lowercase hex sha256")

    def test_equal_signed_and_unsigned_hashes_are_refused(self):
        record = good()
        record["unsigned_sha256"] = record["image_sha256"]
        self.assertRefusedFor(record, "equal")

    def test_the_wrong_model_or_product_is_refused(self):
        record = good()
        record["model"] = "T2T1"
        self.assertRefusedFor(record, "not T3T1")
        record = good()
        record["product"] = "firmware"
        self.assertRefusedFor(record, "not authenticator")

    def test_an_unpinned_build_is_refused(self):
        record = good()
        record["source_commit"] = "abc123"
        self.assertRefusedFor(record, "not a full 40-character hash")
        record = good()
        record["toolchain"] = {}
        self.assertRefusedFor(record, "toolchain pins nothing")
        record = good()
        record["build_command"] = "   "
        self.assertRefusedFor(record, "build_command is empty")
        record = good()
        record["submodules"] = ["vendor/micropython"]
        self.assertRefusedFor(record, "not a map")

    def test_a_release_with_no_anti_rollback_value_is_refused(self):
        record = good()
        record["security_version"] = 0
        self.assertRefusedFor(record, "no anti-rollback")

    def test_a_security_version_the_counter_cannot_hold_is_refused(self):
        record = good()
        record["security_version"] = audit_release.MONOTONIC_MAX + 1
        self.assertRefusedFor(record, "refuse to boot")
        record = good()
        record["security_version"] = audit_release.MONOTONIC_MAX
        self.assertEqual(reasons(record), [])

    def test_a_boolean_security_version_is_not_an_integer(self):
        # True == 1 in Python, so a record saying true would otherwise pass as
        # version 1 and claim anti-rollback it never specified.
        record = good()
        record["security_version"] = True
        self.assertRefusedFor(record, "not an integer")

    def test_a_production_release_may_not_use_development_keys(self):
        record = good()
        record["signing_keys"] = {"generation": 1, "development": True}
        self.assertRefusedFor(record, "whose private halves are published")

    def test_a_production_release_must_name_a_key_generation(self):
        record = good()
        record["signing_keys"] = {"generation": 0, "development": False}
        self.assertRefusedFor(record, "signing key generation")

    def test_a_production_release_may_not_carry_the_development_identity(self):
        record = good()
        record["usb_identity"] = {"vendor": 0x1209, "product": 0x53C1}
        self.assertRefusedFor(record, "development USB identity")

    def test_every_checklist_item_must_be_answered_yes(self):
        for item in audit_release.PRODUCTION_CHECKLIST:
            record = good()
            record["checklist"][item] = False
            self.assertRefusedFor(record, item)
            record = good()
            del record["checklist"][item]
            self.assertRefusedFor(record, item)

    def test_a_missing_field_stops_the_audit_rather_than_guessing(self):
        # With no record to judge, reporting the other rules as passed would describe
        # an unjudgeable release as nearly valid.
        record = good()
        del record["image_sha256"]
        record["model"] = "T2T1"
        found = reasons(record)
        self.assertEqual(len(found), 1)
        self.assertIn("does not say image_sha256", found[0])


if __name__ == "__main__":
    unittest.main()
