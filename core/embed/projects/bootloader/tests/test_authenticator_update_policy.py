"""Compile and run the bootloader's authenticator update policy on the host.

The policy is deliberately free of device headers, cryptography and parsing -- it
takes conclusions and returns a verdict -- so it builds with the host compiler and
can be tested as what it is: a decision.
"""

import pathlib
import subprocess
import sys
import tempfile
import unittest

TESTS_DIR = pathlib.Path(__file__).resolve().parent
BOOTLOADER_DIR = TESTS_DIR.parent


def build(directory, fixture, name, sources):
    """Compiles one C fixture against the production policy sources."""
    executable = pathlib.Path(directory) / name
    command = [
        "cc", "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror",
        "-D_DEFAULT_SOURCE",
        "-I", str(BOOTLOADER_DIR),
    ]
    command += [str(TESTS_DIR / fixture)]
    command += [str(BOOTLOADER_DIR / source) for source in sources]
    command += ["-o", str(executable)]
    subprocess.run(command, check=True)
    return executable


class AuthenticatorUpdatePolicyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="auth-update-policy-")
        cls.executable = build(
            cls.temporary.name, "test_authenticator_update_policy.c", "policy",
            ("authenticator_update_policy.c",),
        )

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def test_the_update_policy_holds(self):
        result = subprocess.run([str(self.executable)], capture_output=True,
                                text=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("authenticator update policy: PASS", result.stdout)


if __name__ == "__main__":
    unittest.main()
