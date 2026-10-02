"""Compile and run the real T3T1 replica IO adapter and the real wipe policy.

Links `stm32u5/authenticator_replica_io.c`, `sys/flash/flash_utils.c`, and the
real replica manager/codec against recording doubles for flash, the checked
reader, and the MPU.

The adapter pulls in `<trezor_model.h>`, `<sys/flash.h>` and `<sys/mpu.h>`,
which on a board drag in the whole BSP. Rather than stub the constants away,
this harness synthesises those three headers so that `trezor_model.h` includes
the *real* `core/embed/models/T3T1/memory.h`: the adapter's compile-time
assertions about sector numbers then hold against the production layout, and
the fixture's runtime assertions use independent literals. Synthesising build
headers for a host fixture follows the pattern already used by
`test_storage_integration.py`.
"""
import pathlib
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[5]
TESTS_DIR = pathlib.Path(__file__).resolve().parent
AUTHENTICATOR_DIR = TESTS_DIR.parent
EMBED = ROOT / "core/embed"
VENDOR = ROOT / "core/vendor"


class ReplicaIoTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="auth-replica-io-")
        cls.directory = pathlib.Path(cls.temporary.name)
        cls.executable = cls.directory / "test"

        shim = cls.directory / "shim"
        (shim / "sys").mkdir(parents=True)
        secbool = EMBED / "rtl/inc/rtl/secbool.h"
        memory = EMBED / "models/T3T1/memory.h"

        # <secbool.h> is what the vendored flash_ll.h asks for. Reached through a
        # shim rather than by putting core/embed/rtl/inc on the include path,
        # because that directory also holds the firmware's own assert.h, which
        # would shadow the host <assert.h> this fixture uses.
        (shim / "secbool.h").write_text(f'#include "{secbool}"\n')
        (shim / "trezor_types.h").write_text(
            "#pragma once\n"
            "#include <stdbool.h>\n"
            "#include <stddef.h>\n"
            "#include <stdint.h>\n"
            f'#include "{secbool}"\n'
        )
        (shim / "trezor_rtl.h").write_text(
            "#pragma once\n"
            "#include <trezor_types.h>\n"
            "#include <string.h>\n"
            "#ifndef ARRAY_LENGTH\n"
            "#define ARRAY_LENGTH(x) (sizeof(x) / sizeof((x)[0]))\n"
            "#endif\n"
        )
        # The real T3T1 layout, so the adapter's _Static_asserts are checked
        # against production sector numbers rather than against test constants.
        (shim / "trezor_model.h").write_text(
            f'#pragma once\n#include "{memory}"\n'
        )
        (shim / "sys/mpu.h").write_text(
            "#pragma once\n"
            "typedef enum {\n"
            "  MPU_MODE_DISABLED,\n"
            "  MPU_MODE_DEFAULT,\n"
            "  MPU_MODE_SECRET,\n"
            "  MPU_MODE_STORAGE,\n"
            "  MPU_MODE_ASSETS,\n"
            "  MPU_MODE_UNUSED_FLASH,\n"
            "} mpu_mode_t;\n"
            "mpu_mode_t mpu_get_mode(void);\n"
            "mpu_mode_t mpu_reconfig(mpu_mode_t mode);\n"
            "void mpu_restore(mpu_mode_t mode);\n"
        )
        (shim / "sys/flash.h").write_text(
            "#pragma once\n"
            "#include <trezor_types.h>\n"
            "#include <trezor-storage/flash_area.h>\n"
            "#include <trezor-storage/flash_ll.h>\n"
            "#define STORAGE_AREAS_COUNT 2\n"
            "extern const flash_area_t STORAGE_AREAS[STORAGE_AREAS_COUNT];\n"
            "extern const flash_area_t ASSETS_AREA;\n"
        )

        command = [
            "cc",
            "-std=c11",
            "-O1",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-DKERNEL_MODE=1",
            "-DSECURE_MODE=1",
            "-DFLASH_BLOCK_WORDS=4",
            "-D_DEFAULT_SOURCE",
        ]
        for include in (
            shim,  # synthesised build headers, must come first
            EMBED / "sys/flash/inc",  # real <sys/flash_checked.h>, <sys/flash_utils.h>
            VENDOR,  # <trezor-storage/flash_area.h>
            VENDOR / "trezor-storage",
            AUTHENTICATOR_DIR,
            AUTHENTICATOR_DIR / "inc",
            ROOT / "crypto",
        ):
            command += ["-I", str(include)]
        sources = [
            TESTS_DIR / "test_replica_io.c",
            AUTHENTICATOR_DIR / "stm32u5/authenticator_replica_io.c",
            AUTHENTICATOR_DIR / "replica_store.c",
            AUTHENTICATOR_DIR / "replica_format.c",
            EMBED / "sys/flash/flash_utils.c",
            # The real quarantine policy, so the adapter's release path is
            # exercised against production logic rather than a fake of it.
            EMBED / "sys/flash/flash_checked_policy.c",
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

    def test_index_binding_alignment_and_wipe_coverage(self):
        result = subprocess.run(
            [str(self.executable)], capture_output=True, text=True
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("replica io binding and wipe policy: PASS", result.stdout)


if __name__ == "__main__":
    unittest.main()
