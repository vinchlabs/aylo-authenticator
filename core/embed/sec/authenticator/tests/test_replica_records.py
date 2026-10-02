"""Compile and run the record/result translation layer over the real manager.

No flash and no platform headers: the layer reaches storage only through the
caller-supplied `auth_replica_io` table, so the fixture provides a simulated
STM32U5 medium (16-byte program granularity, 8 KiB erase, program-only-when-
erased) and the real `replica_store.c` / `replica_format.c` run on top of it.

What this pins down is the mapping from the manager's conditions onto
`auth_result`, and in particular that "no vault here" and "a vault I cannot
open" never collapse into the same answer -- the first authorises provisioning,
the second must refuse it.
"""
import pathlib
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[5]
TESTS_DIR = pathlib.Path(__file__).resolve().parent
AUTHENTICATOR_DIR = TESTS_DIR.parent


class ReplicaRecordsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="auth-replica-records-")
        cls.directory = pathlib.Path(cls.temporary.name)
        cls.executable = cls.directory / "test"
        command = [
            "cc",
            "-std=c11",
            "-O2",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-D_DEFAULT_SOURCE",
        ]
        for include in (
            ROOT / "crypto",
            AUTHENTICATOR_DIR,
            AUTHENTICATOR_DIR / "inc",
        ):
            command += ["-I", str(include)]
        sources = [
            TESTS_DIR / "test_replica_records.c",
            AUTHENTICATOR_DIR / "replica_records.c",
            AUTHENTICATOR_DIR / "replica_store.c",
            AUTHENTICATOR_DIR / "replica_format.c",
            ROOT / "crypto/hmac.c",
            ROOT / "crypto/sha2.c",
            ROOT / "crypto/memzero.c",
            ROOT / "crypto/consteq.c",
            ROOT / "crypto/fault_handler_noop.c",
            # The root envelope is a ChaCha20-Poly1305 AEAD, so the unlock path
            # needs the real construction rather than a stand-in.
            ROOT / "crypto/chacha20poly1305/rfc7539.c",
            ROOT / "crypto/chacha20poly1305/chacha20poly1305.c",
            ROOT / "crypto/chacha20poly1305/chacha_merged.c",
            ROOT / "crypto/chacha20poly1305/poly1305-donna.c",
        ]
        command += [str(source) for source in sources]
        command += ["-o", str(cls.executable)]
        subprocess.run(command, check=True)

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def test_result_mapping_and_record_round_trip(self):
        result = subprocess.run(
            [str(self.executable)], capture_output=True, text=True
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("replica records translation: PASS", result.stdout)


if __name__ == "__main__":
    unittest.main()
