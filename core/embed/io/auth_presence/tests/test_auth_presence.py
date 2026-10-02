"""Host-compiled check of the presence backend's fail-closed contract."""

import pathlib
import subprocess
import tempfile
import unittest

TESTS_DIR = pathlib.Path(__file__).resolve().parent
MODULE_DIR = TESTS_DIR.parent
EMBED_DIR = MODULE_DIR.parent.parent


def build(directory, fixture, name):
    """Compiles one C fixture against the production host backend."""
    executable = pathlib.Path(directory) / name
    command = [
        "cc", "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror",
        "-D_DEFAULT_SOURCE",
    ]
    for include in (MODULE_DIR / "inc", EMBED_DIR / "rtl/inc"):
        command += ["-I", str(include)]
    sources = [
        TESTS_DIR / fixture,
        # The real backend, not a copy of it. A test against a reimplementation
        # would pass while the shipped stub reported an empty slot.
        MODULE_DIR / "unix/auth_presence.c",
    ]
    command += [str(source) for source in sources]
    command += ["-o", str(executable)]
    subprocess.run(command, check=True)
    return executable


class AuthPresenceHostBackendTests(unittest.TestCase):
    """A build with no line to read must never report an empty slot."""

    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="auth-presence-")
        cls.executable = build(cls.temporary.name, "test_auth_presence.c",
                               "presence")

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def test_the_host_backend_reports_a_fault_in_every_state(self):
        result = subprocess.run([str(self.executable)], capture_output=True,
                                text=True)
        print("\n" + result.stdout.strip())
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("auth presence host backend: PASS", result.stdout)


if __name__ == "__main__":
    unittest.main()
