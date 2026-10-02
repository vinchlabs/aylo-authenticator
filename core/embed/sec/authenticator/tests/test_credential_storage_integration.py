"""Credentials end to end over the real replica stack.

Standalone on purpose. The previous version borrowed its build from
test_storage_integration.py, which compiles NORCOW and the wallet storage layer;
that harness is still correct for what it tests and is left alone. This fixture
needs a different set of sources -- the replica stack instead of NORCOW -- so it
owns its own build.

What gets compiled is production code all the way down: authenticator.c, the
stm32u5 backend, the storage facade, replica_records, replica_store and
replica_format. The fixture doubles only the secure element, the hardware RNG,
and auth_replica_io_t3t1(), which addresses a RAM medium instead of flash.
"""
import pathlib
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[5]
TESTS_DIR = pathlib.Path(__file__).resolve().parent
AUTHENTICATOR_DIR = TESTS_DIR.parent
EMBED = ROOT / "core/embed"


class CredentialStorageIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="auth-credentials-")
        cls.directory = pathlib.Path(cls.temporary.name)
        cls.executable = cls.directory / "test"

        libcrypto = sorted(
            (ROOT / "core/build-xtask/debug/build").glob("crypto-*/out/libcrypto.a"),
            key=lambda path: path.stat().st_mtime,
        )
        if not libcrypto:
            raise RuntimeError(
                "Run `xtask test sec` once to build the real native crypto library"
            )

        command = [
            "cc",
            "-std=c11",
            "-O1",
            "-ffunction-sections",
            "-fdata-sections",
            "-DFLASH_BLOCK_WORDS=4",
            "-DCONFIDENTIAL=",
            "-DUSE_OPTIGA=1",
            "-DUSE_AUTH_VAULT=1",
            # Exposes the vault's test-only readers. On this suite it adds
            # nothing but those: the alternative in-memory backend behind the
            # same define belongs to unix/, and this build links the real one.
            "-DAUTH_TEST_BACKEND=1",
            "-D_DEFAULT_SOURCE",
        ]
        for include in (
            ROOT / "crypto",
            EMBED / "rtl/inc",
            EMBED / "sec/optiga/inc",
            EMBED / "sec/storage/inc",
            EMBED / "sec/rng/inc",
            EMBED / "sys/rng/inc",
            ROOT / "core/vendor",
            AUTHENTICATOR_DIR / "inc",
            AUTHENTICATOR_DIR,
        ):
            command += ["-I", str(include)]
        sources = [
            TESTS_DIR / "test_credential_storage_integration.c",
            AUTHENTICATOR_DIR / "authenticator.c",
            AUTHENTICATOR_DIR / "replica_records.c",
            AUTHENTICATOR_DIR / "replica_store.c",
            AUTHENTICATOR_DIR / "replica_format.c",
            AUTHENTICATOR_DIR / "stm32u5/authenticator_storage.c",
            AUTHENTICATOR_DIR / "stm32u5/authenticator_backend.c",
            # Listed before libcrypto.a so the linker resolves tc_fault_handler
            # here and never pulls the archive's real handler, which wants the
            # firmware's system_exit_error.
            ROOT / "crypto/fault_handler_noop.c",
        ]
        command += [str(source) for source in sources]
        command += [str(libcrypto[-1]), "-Wl,--gc-sections", "-o", str(cls.executable)]
        subprocess.run(command, check=True)

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def scenario(self, name):
        result = subprocess.run(
            [str(self.executable), name], capture_output=True, text=True
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("PASS", result.stdout)

    def test_records_round_trip_and_survive_a_reconnect(self):
        self.scenario("records")

    def test_replacement_keeps_other_slots_and_refuses_duplicates(self):
        self.scenario("replace")

    def test_the_vault_chooses_a_free_slot_and_says_when_there_is_none(self):
        """The caller cannot search, so the vault has to choose.

        Any refusal invalidates the session, which is asserted inside this
        scenario rather than assumed: it is the reason the search this replaced
        could never have worked.
        """
        self.scenario("choose")

    def test_a_creation_session_replaces_its_own_account_in_place(self):
        """The one replacement CTAP requires of a registration.

        Deletion and naming a slot both require the management permission, which a
        registration does not carry, so this had to become something the vault
        does inside the one call that stores: it finds this party's record for
        this account and writes the new one where it stands.
        """
        self.scenario("replace_account")

    def test_a_different_account_of_the_same_party_takes_a_free_slot(self):
        self.scenario("replace_other_account")

    def test_another_partys_record_for_the_same_account_is_untouched(self):
        self.scenario("replace_other_party")

    def test_a_full_store_replaces_but_still_refuses_a_new_account(self):
        self.scenario("replace_when_full")

    def test_mc_attests_and_ga_asserts_and_neither_buys_the_other(self):
        """Which permission signs what.

        A platform enrolling a credential may hold only mc -- libfido2 asks for
        exactly that -- so the attestation had to be authorized by the creation it
        belongs to. Nothing about that lets mc produce an assertion.
        """
        self.scenario("attest_permission")

    def test_deletion_keeps_other_slots_across_a_reconnect(self):
        self.scenario("delete")

    def test_wipe_leaves_a_reprovisionable_device(self):
        self.scenario("wipe")

    def test_oversize_credential_is_refused_without_mutation(self):
        self.scenario("oversize")

    def test_separate_management_assertion_and_creation_permissions(self):
        self.scenario("permissions")

    def test_a_reader_refusing_every_read_erases_nothing(self):
        self.scenario("unsupported")


if __name__ == "__main__":
    unittest.main()
