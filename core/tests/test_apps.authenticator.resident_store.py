import os
import sys
sys.path.remove(os.path.dirname(__file__))
import unittest
from apps.authenticator.resident_store import ResidentStore
from apps.authenticator.credential import CredentialUnavailable


class ResidentStoreTests(unittest.TestCase):
    def test_indices_are_exactly_zero_through_99(self):
        for index in (-1,100,256,True,"0",1.0):
            for operation in (ResidentStore.get,ResidentStore.delete):
                with self.assertRaises(ValueError):
                    operation(index)
            with self.assertRaises(ValueError):
                ResidentStore.set(index,None)

    def test_set_rejects_objects_that_are_not_authenticated_credentials(self):
        with self.assertRaises(ValueError):
            ResidentStore.set(0,b"opaque")

    def test_store_hands_the_choice_to_the_vault(self):
        """Index 100 is "wherever there is room", and the answers are distinct."""
        from types import ModuleType
        from apps.authenticator.credential import (
            CredentialLimitExceeded,
            CredentialStoreFull,
        )

        class Fake:
            id = bytes(78)
            rp_id_hash = bytes(32)

        asked = []
        package = ModuleType("storage")
        package.__path__ = []
        native = ModuleType("storage.authenticator")
        previous = {name: sys.modules.get(name) for name in
                    ("storage", "storage.authenticator")}
        sys.modules["storage"] = package
        sys.modules["storage.authenticator"] = native
        try:
            # A credential this side did not make is refused before any vault call.
            native.set = lambda index, identifier, rp_hash: 0
            with self.assertRaises(ValueError):
                ResidentStore.store(Fake())
            self.assertEqual(asked, [])

            from apps.authenticator.credential import Credential
            real = Credential._from_public(
                (0, bytes(78), bytes(32), -7,
                 b"\x01\x00\x03\x00\x01\x00\x00\x00\x00r", b"cose")
            )

            def accept(index, identifier, rp_hash):
                asked.append(index)
                return 0

            native.set = accept
            ResidentStore.store(real)
            self.assertEqual(asked, [100])

            # Too large for a slot, and full, are separate answers: a platform can
            # act on the first and cannot act on the second.
            native.set = lambda index, identifier, rp_hash: 8
            with self.assertRaises(CredentialLimitExceeded):
                ResidentStore.store(real)
            native.set = lambda index, identifier, rp_hash: 11
            with self.assertRaises(CredentialStoreFull):
                ResidentStore.store(real)
            native.set = lambda index, identifier, rp_hash: 6
            with self.assertRaises(CredentialUnavailable):
                ResidentStore.store(real)
        finally:
            for name, module in previous.items():
                if module is None:
                    del sys.modules[name]
                else:
                    sys.modules[name] = module

    def test_scan_filter_must_be_a_relying_party_hash(self):
        for value in (b"", bytes(31), bytes(33), "x" * 32, 0):
            with self.assertRaises(ValueError):
                ResidentStore.occupied(value)

    def test_native_nonmatch_is_skipped_but_denial_is_not_an_empty_slot(self):
        # Public native result fixtures exercise the Python status consumer;
        # real MC/GA/CM authorization is covered by native and binding tests.
        from types import ModuleType
        package = ModuleType("storage")
        package.__path__ = []
        native = ModuleType("storage.authenticator")
        public = (0, bytes(78), bytes(32), -7,
                  b"\x01\x00\x03\x00\x01\x00\x00\x00\x00r", b"cose")
        native.get = lambda index: public if index == 99 else (1, b"", b"", 0, b"", b"")
        occupancy = bytes(1 if i == 99 else 0 for i in range(100))
        asked = []

        def scan(rp_hash=None):
            asked.append(rp_hash)
            return 0, occupancy

        native.scan = scan
        previous = {name: sys.modules.get(name) for name in
                    ("storage", "storage.authenticator")}
        sys.modules["storage"] = package
        sys.modules["storage.authenticator"] = native
        try:
            self.assertEqual([(i, c.rp_id) for i, c in ResidentStore.enumerate()],
                             [(99, "r")])
            # One scan for the whole enumeration, and only the occupied slot is
            # read afterwards. Reading all hundred is the cost this replaced.
            self.assertEqual(len(asked), 1)
            self.assertEqual(ResidentStore.occupied(), [99])
            # The filter reaches the vault unchanged; narrowing is its decision,
            # not something this side simulates.
            self.assertEqual(ResidentStore.occupied(bytes(32)), [99])
            self.assertEqual(asked[-1], bytes(32))
            native.get = lambda index: (6, b"", b"", 0, b"", b"")
            with self.assertRaises(CredentialUnavailable):
                ResidentStore.get(0)
            # A refused scan is not an empty vault.
            native.scan = lambda rp_hash=None: (6, bytes(100))
            with self.assertRaises(CredentialUnavailable):
                ResidentStore.occupied()
            # Nor is a truncated one.
            native.scan = lambda rp_hash=None: (0, bytes(99))
            with self.assertRaises(CredentialUnavailable):
                ResidentStore.occupied()
        finally:
            for name, module in previous.items():
                if module is None:
                    del sys.modules[name]
                else:
                    sys.modules[name] = module


if __name__=="__main__":
    unittest.main()
