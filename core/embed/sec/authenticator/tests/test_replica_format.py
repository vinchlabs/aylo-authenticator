"""Compile and run the real replica_format.{h,c} codec as a standalone binary.

No flash, storage, or backend involved: this exercises only the pure
canonical encode/decode/MAC codec against a fixed, independently-computed
(Python hmac/hashlib) test vector plus exhaustive negative/tamper cases.
"""
import pathlib
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[5]
TESTS_DIR = pathlib.Path(__file__).resolve().parent
AUTHENTICATOR_DIR = TESTS_DIR.parent


class ReplicaFormatTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="auth-replica-format-")
        cls.directory = pathlib.Path(cls.temporary.name)
        cls.executable = cls.directory / "test"
        command = ["cc", "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror",
                   "-D_DEFAULT_SOURCE"]
        for include in (ROOT / "crypto", AUTHENTICATOR_DIR, AUTHENTICATOR_DIR / "inc"):
            command += ["-I", str(include)]
        sources = [
            TESTS_DIR / "test_replica_format.c",
            AUTHENTICATOR_DIR / "replica_format.c",
            ROOT / "crypto/hmac.c",
            ROOT / "crypto/sha2.c",
            ROOT / "crypto/memzero.c",
            ROOT / "crypto/consteq.c",
            ROOT / "crypto/fault_handler_noop.c",
        ]
        command += [str(source) for source in sources]
        command += ["-o", str(cls.executable)]
        subprocess.run(command, check=True)

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def test_codec_matches_independent_vector_and_rejects_every_tamper(self):
        result = subprocess.run([str(self.executable)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
