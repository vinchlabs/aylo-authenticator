import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[4] / "src"))
from apps.authenticator import credential, storage


class FacadeTests(unittest.TestCase):
    def test_credential_creation_denied_without_secure_service(self):
        with self.assertRaises(credential.CredentialUnavailable):
            credential.create(b"rp.example", b"\0" * 32)

    def test_credential_assertion_denied_without_secure_service(self):
        with self.assertRaises(credential.CredentialUnavailable):
            credential.assertion(b"\x01", b"\0" * 32)

    def test_storage_access_denied_without_secure_backend(self):
        with self.assertRaises(storage.StorageUnavailable):
            storage.read(1)
        with self.assertRaises(storage.StorageUnavailable):
            storage.write(1, b"secret")

    def test_facades_reject_unbounded_inputs(self):
        with self.assertRaises(ValueError):
            credential.create(b"r" * 254, b"\0" * 32)
        with self.assertRaises(ValueError):
            storage.write(1, b"x" * 1025)


if __name__ == "__main__":
    unittest.main()
