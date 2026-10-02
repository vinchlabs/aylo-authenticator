import importlib.util
import pathlib
import unittest


SOURCE = pathlib.Path(__file__).resolve().parents[4] / "src/apps/authenticator/protocol.py"
SPEC = importlib.util.spec_from_file_location("authenticator_protocol", SOURCE)
protocol = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(protocol)


class ProtocolTests(unittest.TestCase):
    def test_get_info_exposes_only_development_capabilities(self):
        response = protocol.dispatch_cbor(b"\x04")
        self.assertEqual(response[0], 0)
        self.assertIn(b"FIDO_2_1", response)
        self.assertIn(b"AUTH-DEV", response)
        self.assertEqual(
            response[15:31],
            bytes.fromhex("7c31d8c28e6049298976a86f9c124bb1"),
        )
        self.assertNotIn(bytes.fromhex("d6d0bdc362eec4dbde8d7a656e4a4487"), response)

    def test_other_cbor_commands_are_denied(self):
        for command in (1, 2, 6, 7, 8, 0x0A, 0x0C, 0x7F):
            self.assertEqual(protocol.dispatch_cbor(bytes([command])), b"\x27")

if __name__ == "__main__":
    unittest.main()
