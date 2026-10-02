"""Compile and run the real checked-flash reader as a standalone binary.

Links the actual policy layer, the actual emulator backend, and the actual
vendored ``flash_area.c``. Only the three lowest-level flash primitives
(``flash_sector_size``, ``flash_sector_find``, ``flash_get_address``) are faked
by the fixture, over a RAM buffer laid out like the T3T1 page map, so the area
sizing and sector arithmetic under test are production code.

No board, no ECC hardware, and no emulator profile directory are involved.
"""
import pathlib
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[5]
TESTS_DIR = pathlib.Path(__file__).resolve().parent
FLASH_DIR = TESTS_DIR.parent
EMBED = ROOT / "core/embed"
VENDOR = ROOT / "core/vendor"


class FlashCheckedTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="flash-checked-")
        cls.directory = pathlib.Path(cls.temporary.name)
        cls.executable = cls.directory / "test"

        # The vendored flash_ll.h asks for <secbool.h>. Reach the real firmware
        # definition through a one-line shim rather than putting
        # core/embed/rtl/inc on the include path: that directory also holds the
        # firmware's own assert.h, which would shadow the host <assert.h> this
        # fixture relies on.
        shim = cls.directory / "shim"
        shim.mkdir()
        real_secbool = EMBED / "rtl/inc/rtl/secbool.h"
        (shim / "secbool.h").write_text(f'#include "{real_secbool}"\n')

        command = [
            "cc",
            "-std=c11",
            "-O2",
            "-Wall",
            "-Wextra",
            "-Werror",
            # T3T1 writes flash in 128-bit blocks; match the real target so the
            # vendored flash_area.c is compiled the way the device builds it.
            "-DFLASH_BLOCK_WORDS=4",
        ]
        for include in (
            FLASH_DIR / "inc",  # <sys/flash_checked.h>
            VENDOR,  # <trezor-storage/flash_area.h>
            VENDOR / "trezor-storage",  # "flash_area.h", "flash_ll.h"
            shim,  # <secbool.h>
        ):
            command += ["-I", str(include)]
        sources = [
            TESTS_DIR / "test_flash_checked.c",
            FLASH_DIR / "flash_checked_policy.c",
            FLASH_DIR / "unix/flash_checked.c",
            VENDOR / "trezor-storage/flash_area.c",
        ]
        command += [str(source) for source in sources]
        command += ["-o", str(cls.executable)]
        subprocess.run(command, check=True)

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def test_reader_policy_and_eccd_containment_decision(self):
        result = subprocess.run(
            [str(self.executable)], capture_output=True, text=True
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("flash checked reader: PASS", result.stdout)


if __name__ == "__main__":
    unittest.main()
