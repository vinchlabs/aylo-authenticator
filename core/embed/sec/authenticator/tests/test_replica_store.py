"""Compile and run the real three-replica manager against a simulated flash.

The simulated device enforces STM32U5-shaped rules that matter for recovery:
program granularity is 16 bytes, erase granularity is 8 KiB, a line can only
be programmed while it reads erased, and reads can report corrected or
uncorrectable ECC. Only the physical medium is simulated -- the codec,
selector, and transaction logic under test are the production sources.

Byte-exact format correctness is pinned separately in test_replica_format.py
against an independently computed vector. What this module proves is
behavioural: which snapshot gets selected, what never gets written, and in
which order flash is touched.
"""
import pathlib
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[5]
TESTS_DIR = pathlib.Path(__file__).resolve().parent
AUTHENTICATOR_DIR = TESTS_DIR.parent


def build(directory, fixture, name):
    """Compiles one C fixture against the production replica sources."""
    executable = pathlib.Path(directory) / name
    command = ["cc", "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror",
               "-D_DEFAULT_SOURCE"]
    for include in (ROOT / "crypto", AUTHENTICATOR_DIR,
                    AUTHENTICATOR_DIR / "inc"):
        command += ["-I", str(include)]
    sources = [
        TESTS_DIR / fixture,
        AUTHENTICATOR_DIR / "replica_store.c",
        AUTHENTICATOR_DIR / "replica_format.c",
        ROOT / "crypto/hmac.c",
        ROOT / "crypto/sha2.c",
        ROOT / "crypto/memzero.c",
        ROOT / "crypto/consteq.c",
        ROOT / "crypto/fault_handler_noop.c",
    ]
    command += [str(source) for source in sources]
    command += ["-o", str(executable)]
    subprocess.run(command, check=True)
    return executable


class ReplicaStoreTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="auth-replica-store-")
        cls.executable = build(cls.temporary.name, "test_replica_store.c", "store")

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def test_selection_and_transaction_invariants_hold(self):
        result = subprocess.run([str(self.executable)], capture_output=True,
                                text=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("replica store: PASS", result.stdout)


class ReplicaPowerCutTests(unittest.TestCase):
    """Every single interruption must recover to old, new, or empty state."""

    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="auth-power-cut-")
        cls.executable = build(cls.temporary.name, "test_replica_power_cut.c",
                               "powercut")

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def test_single_power_cut_never_loses_the_vault(self):
        result = subprocess.run([str(self.executable)], capture_output=True,
                                text=True)
        print("\n" + result.stdout.strip())
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("unexpected_unavailable=0", result.stdout)
        self.assertIn("replica power-cut: PASS", result.stdout)


if __name__ == "__main__":
    unittest.main()
