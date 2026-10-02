"""Bounded public model; native integration is exercised in the real emulator."""
import os
import sys
sys.path.remove(os.path.dirname(__file__))
import unittest
from apps.authenticator.credential import Credential


class CredentialTests(unittest.TestCase):
    def test_rejects_out_of_bounds_metadata_before_native_access(self):
        for kwargs in ({"rp_id":""},{"rp_id":"r"*254},{"user_id":b"u"*65},
                       {"rp_name":"é"*51},{"user_name":"n"*101},
                       {"user_display_name":"n"*101},{"algorithm":-9},
                       {"algorithm":True},{"cred_protect":2},{"hmac_secret":1},
                       {"user_id":"u"},{"rp_id":b"example.com"}):
            args={"rp_id":"example.com","user_id":b"u"}
            args.update(kwargs)
            with self.assertRaises(ValueError):
                Credential.create(**args)

    def test_open_rejects_unbounded_id_or_rp_before_native_access(self):
        for identifier,rp in ((b"",bytes(32)),(bytes(705),bytes(32)),
                              (bytes(89),bytes(31)),("id",bytes(32))):
            with self.assertRaises(ValueError):
                Credential.open(identifier,rp)


if __name__=="__main__":
    unittest.main()
