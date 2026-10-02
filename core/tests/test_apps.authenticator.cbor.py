"""CTAP 2.1 canonical request and response boundary tests."""

import os
import sys

sys.path.remove(os.path.dirname(__file__))
import unittest

from apps.authenticator.cbor_codec import (
    CtapError, RawCbor, decode_request, encode_response,
)
from apps.authenticator.command_types import (
    ClientPinRequest,
    CredentialManagementRequest,
    GetAssertionRequest,
    MakeCredentialRequest,
    Request,
)


def cbor_uint(n):
    if n < 24:
        return bytes((n,))
    if n < 256:
        return bytes((24, n))
    return b"\x19" + n.to_bytes(2, "big")


def cbor_bytes(value):
    return bytes((0x40 + len(value),)) + value if len(value) < 24 else b"\x58" + bytes((len(value),)) + value


def cbor_text(value):
    value = value.encode()
    if len(value) < 24:
        return bytes((0x60 + len(value),)) + value
    if len(value) < 256:
        return b"\x78" + bytes((len(value),)) + value
    return b"\x79" + len(value).to_bytes(2, "big") + value


def cbor_array(items):
    return bytes((0x80 + len(items),)) + b"".join(items) if len(items) < 24 else b"\x98" + bytes((len(items),)) + b"".join(items)


def cbor_map(items):
    return bytes((0xA0 + len(items),)) + b"".join(k + v for k, v in items)


HASH = cbor_bytes(bytes(32))
RP = cbor_map(((cbor_text("id"), cbor_text("example.com")),))
USER = cbor_map(((cbor_text("id"), cbor_bytes(b"u")),))
PARAM = cbor_map(((cbor_text("alg"), b"\x26"), (cbor_text("type"), cbor_text("public-key"))))
DESC = cbor_map(((cbor_text("id"), cbor_bytes(b"x")), (cbor_text("type"), cbor_text("public-key"))))
COSE_KEY = cbor_map(((b"\x01", b"\x02"), (b"\x03", b"\x38\x18"), (b"\x20", b"\x01"), (b"\x21", cbor_bytes(bytes(32))), (b"\x22", cbor_bytes(bytes(32)))))
MAKE = cbor_map(((b"\x01", HASH), (b"\x02", RP), (b"\x03", USER), (b"\x04", cbor_array((PARAM,)))))
GET = cbor_map(((b"\x01", cbor_text("example.com")), (b"\x02", HASH)))


class CborSchemas(unittest.TestCase):
    def assert_code(self, command, payload, code):
        with self.assertRaises(CtapError) as caught:
            decode_request(command, payload)
        self.assertEqual(caught.exception.code, code)

    def test_typed_requests_and_forward_compatible_keys(self):
        make = decode_request(1, MAKE)
        self.assertIsInstance(make, Request)
        self.assertIsInstance(make, MakeCredentialRequest)
        self.assertEqual(make.rp.id, "example.com")
        self.assertEqual(make.algorithm, -7)
        self.assertIsInstance(decode_request(2, GET), GetAssertionRequest)
        self.assertIsInstance(decode_request(6, cbor_map(((b"\x02", b"\x01"),))), ClientPinRequest)
        self.assertIsInstance(decode_request(10, cbor_map(((b"\x01", b"\x03"),))), CredentialManagementRequest)
        self.assertEqual(decode_request(2, cbor_map(((b"\x01", cbor_text("example.com")), (b"\x02", HASH), (b"\x18\x63", b"\xf4")))).rp_id, "example.com")

    def test_unknown_commands_and_parameterless_commands(self):
        # largeBlobs, which CTAP defines and this firmware does not serve.
        # 0x41 used to stand here, and it is credential management now.
        self.assert_code(0x0C, b"", 0x01)
        for command in (4, 7, 8, 11):
            decode_request(command, b"")
            self.assert_code(command, b"\xa0", 0x02)

    def test_canonical_structure(self):
        for payload in (b"\xbf\xff", b"\xa1\x01\x9f\xff", b"\xa1\x01\xc0\x00", b"\xa1\x18\x01\x00", b"\xa2\x02\x00\x01\x00", b"\xa2\x01\x00\x01\x01", b"\xa1\x01\x00\x00"):
            self.assert_code(1, payload, 0x12)
        self.assert_code(2, cbor_map(((b"\x01", cbor_text("x")), (b"\x02", cbor_array((cbor_array((cbor_array((cbor_array((b"\x00",)),)),)),))))), 0x12)
        self.assert_code(2, bytes(1025), 0x39)

    def test_missing_and_wrong_types(self):
        self.assert_code(1, cbor_map(()), 0x14)
        self.assert_code(2, cbor_map(((b"\x01", b"\x01"), (b"\x02", HASH))), 0x11)
        self.assert_code(1, cbor_map(((b"\x01", HASH), (b"\x02", cbor_map(())), (b"\x03", USER), (b"\x04", cbor_array((PARAM,))))), 0x11)
        self.assert_code(1, cbor_map(((b"\x01", cbor_bytes(bytes(31))), (b"\x02", RP), (b"\x03", USER), (b"\x04", cbor_array((PARAM,))))), 0x03)

    def test_list_and_user_bounds_and_algorithms(self):
        self.assert_code(1, cbor_map(((b"\x01", HASH), (b"\x02", RP), (b"\x03", cbor_map(((cbor_text("id"), cbor_bytes(bytes(65))),))), (b"\x04", cbor_array((PARAM,))))), 0x03)
        self.assert_code(2, cbor_map(((b"\x01", cbor_text("example.com")), (b"\x02", HASH), (b"\x03", cbor_array((DESC,) * 11)))), 0x15)
        self.assert_code(1, cbor_map(((b"\x01", HASH), (b"\x02", RP), (b"\x03", USER), (b"\x04", cbor_array((PARAM,))), (b"\x05", cbor_array((DESC,) * 11)))), 0x15)
        unsupported = cbor_map(((cbor_text("alg"), b"\x28"), (cbor_text("type"), cbor_text("public-key"))))
        self.assert_code(1, cbor_map(((b"\x01", HASH), (b"\x02", RP), (b"\x03", USER), (b"\x04", cbor_array((unsupported,))))), 0x26)
        mixed = cbor_map(((b"\x01", HASH), (b"\x02", RP), (b"\x03", USER), (b"\x04", cbor_array((unsupported, PARAM)))))
        self.assertEqual(decode_request(1, mixed).algorithm, -7)

    def test_user_handle_boundary_is_one_to_sixty_four_bytes(self):
        empty_user = cbor_map(((cbor_text("id"), cbor_bytes(b"")),))
        empty_request = cbor_map(((b"\x01", HASH), (b"\x02", RP), (b"\x03", empty_user), (b"\x04", cbor_array((PARAM,)))))
        self.assert_code(1, empty_request, 0x03)
        for size in (1, 64):
            user = cbor_map(((cbor_text("id"), cbor_bytes(bytes(size))),))
            request = cbor_map(((b"\x01", HASH), (b"\x02", RP), (b"\x03", user), (b"\x04", cbor_array((PARAM,)))))
            self.assertEqual(len(decode_request(1, request).user.id), size)

    def test_pin_and_management_subcommands(self):
        self.assert_code(6, cbor_map(((b"\x02", b"\x03"),)), 0x14)
        self.assert_code(6, cbor_map(((b"\x02", b"\x08"),)), 0x3E)
        self.assert_code(10, cbor_map(((b"\x01", b"\x04"),)), 0x36)
        self.assert_code(10, cbor_map(((b"\x01", b"\x08"),)), 0x3E)

    def test_pin_protocol_two_encrypted_field_lengths(self):
        key = cbor_map(((b"\x01", b"\x02"), (b"\x03", b"\x38\x18"), (b"\x20", b"\x01"), (b"\x21", cbor_bytes(bytes(32))), (b"\x22", cbor_bytes(bytes(32)))))
        for protocol, new_pin in ((1, 80), (2, 64)):
            request = cbor_map(((b"\x01", cbor_uint(protocol)), (b"\x02", b"\x03"), (b"\x03", key), (b"\x04", cbor_bytes(bytes(16 if protocol == 1 else 32))), (b"\x05", cbor_bytes(bytes(new_pin)))))
            self.assert_code(6, request, 0x03)

    def test_present_null_pin_fields_are_wrong_types(self):
        self.assert_code(2, cbor_map(((b"\x01", cbor_text("example.com")), (b"\x02", HASH), (b"\x06", b"\xf6"))), 0x11)
        self.assert_code(2, cbor_map(((b"\x01", cbor_text("example.com")), (b"\x02", HASH), (b"\x07", b"\xf6"))), 0x11)
        self.assert_code(6, cbor_map(((b"\x01", b"\xf6"), (b"\x02", b"\x03"))), 0x11)
        self.assert_code(10, cbor_map(((b"\x01", b"\x01"), (b"\x03", b"\xf6"), (b"\x04", cbor_bytes(bytes(16))))), 0x11)

    def test_make_credential_accepts_empty_pin_auth_probe(self):
        request = cbor_map(((b"\x01", HASH), (b"\x02", RP), (b"\x03", USER), (b"\x04", cbor_array((PARAM,))), (b"\x08", b"\x40"), (b"\x09", b"\x01")))
        self.assertEqual(decode_request(1, request).pin_uv_auth_param, b"")

    def test_enterprise_attestation_request_is_rejected(self):
        request = cbor_map(((b"\x01", HASH), (b"\x02", RP), (b"\x03", USER), (b"\x04", cbor_array((PARAM,))), (b"\x0a", b"\x01")))
        self.assert_code(1, request, 0x02)

    def test_response_encoding_is_canonical_and_bounded(self):
        self.assertEqual(encode_response({2: False, 1: b"x"}), b"\xa2\x01\x41x\x02\xf4")
        # Bytes that are already canonical CBOR are spliced in as they stand, so
        # the vault's COSE key reaches a platform unparsed. Only handler code can
        # ask for that, and it has to hand over something that could be CBOR:
        # anything else would emit a response nothing can read.
        self.assertEqual(
            encode_response({1: RawCbor(b"\xa1\x01\x02")}), b"\xa1\x01\xa1\x01\x02"
        )
        for value in (b"", "a101", bytearray(b"\xa1"), None, 1):
            with self.assertRaises(CtapError) as caught:
                RawCbor(value)
            self.assertEqual(caught.exception.code, 0x02)
        # And it is still refused as a map key, where sorting decides the order.
        with self.assertRaises(CtapError):
            encode_response({RawCbor(b"\x01"): 1})
        with self.assertRaises(CtapError):
            encode_response({1: bytes(1024)})

    def test_unknown_canonical_float_and_simple_fields_are_ignored(self):
        request = cbor_map(((b"\x01", cbor_text("example.com")), (b"\x02", HASH), (b"\x18\x63", b"\xf9\x3c\x00"), (b"\xf4", b"\xf7")))
        self.assertEqual(decode_request(2, request).rp_id, "example.com")
        self.assert_code(2, cbor_map(((b"\x01", b"\xf9\x3c\x00"), (b"\x02", HASH))), 0x11)

    def test_management_metadata_and_rp_enumeration_auth_ignore_extra_params(self):
        for subcommand in (b"\x01", b"\x02"):
            for params in (None, b"\xa0", b"\xa1\x18\x63\xf4", b"\xa1\x18\x63\xf5"):
                fields = [(b"\x01", subcommand)]
                if params is not None:
                    fields.append((b"\x02", params))
                fields.extend(((b"\x03", b"\x01"), (b"\x04", cbor_bytes(bytes(16)))))
                request = decode_request(10, cbor_map(fields))
                self.assertIsInstance(request, CredentialManagementRequest)
                self.assertEqual(request.auth_material, subcommand)
                self.assertFalse(hasattr(request, "subcommand_params"))
            malformed = cbor_map(((b"\x01", subcommand), (b"\x02", b"\xa1\x18\x63\x18\x01"),
                                  (b"\x03", b"\x01"), (b"\x04", cbor_bytes(bytes(16)))))
            self.assert_code(10, malformed, 0x12)

    def test_management_parameter_operations_auth_preserves_unknown_canonical_params(self):
        for subcommand, fields in ((b"\x04", ((b"\x01", HASH),)),
                                   (b"\x06", ((b"\x02", DESC),)),
                                   (b"\x07", ((b"\x02", DESC), (b"\x03", USER)))):
            params = cbor_map(fields)
            extended = cbor_map(fields + ((b"\x18\x63", b"\xf9\x3c\x00"),))

            def request(body):
                return cbor_map(((b"\x01", subcommand), (b"\x02", body), (b"\x03", b"\x01"), (b"\x04", cbor_bytes(bytes(16)))))

            first = decode_request(10, request(params))
            second = decode_request(10, request(extended))
            self.assertIsInstance(first, CredentialManagementRequest)
            if subcommand == b"\x04":
                self.assertEqual(first.rp_id_hash, second.rp_id_hash)
            else:
                self.assertEqual(first.credential.id, second.credential.id)
            if subcommand == b"\x07":
                self.assertEqual(first.user.id, second.user.id)
            self.assertEqual(first.auth_material, subcommand + params)
            self.assertEqual(second.auth_material, subcommand + extended)
            self.assertNotEqual(first.auth_material, second.auth_material)
            self.assertFalse(hasattr(second, "subcommand_params"))
            self.assert_code(10, request(cbor_map(fields + ((b"\x18\x63", b"\x18\x01"),))), 0x12)

    def test_client_pin_key_agreement_requires_protocol(self):
        self.assert_code(6, cbor_map(((b"\x02", b"\x02"),)), 0x14)
        self.assertEqual(decode_request(6, cbor_map(((b"\x01", b"\x01"), (b"\x02", b"\x02")))).pin_uv_auth_protocol, 1)

    def test_hmac_secret_omitted_protocol_defaults_to_one(self):
        def assertion_input(salt_enc, salt_auth, protocol=None):
            fields = [(b"\x01", COSE_KEY), (b"\x02", cbor_bytes(bytes(salt_enc))), (b"\x03", cbor_bytes(bytes(salt_auth)))]
            if protocol is not None:
                fields.append((b"\x04", protocol))
            extension = cbor_map(((cbor_text("hmac-secret"), cbor_map(fields)),))
            return cbor_map(((b"\x01", cbor_text("example.com")), (b"\x02", HASH), (b"\x04", extension)))

        self.assertEqual(decode_request(2, assertion_input(32, 16)).hmac_secret.pin_protocol, 1)
        self.assertEqual(decode_request(2, assertion_input(32, 16, b"\x01")).hmac_secret.pin_protocol, 1)
        self.assertEqual(decode_request(2, assertion_input(48, 32, b"\x02")).hmac_secret.pin_protocol, 2)
        self.assert_code(2, assertion_input(32, 16, b"\x03"), 0x02)
        self.assert_code(2, assertion_input(32, 16, b"\xf4"), 0x11)

    def test_get_assertion_accepts_empty_pin_auth_probe(self):
        request = cbor_map(((b"\x01", cbor_text("example.com")), (b"\x02", HASH), (b"\x06", b"\x40"), (b"\x07", b"\x01")))
        self.assertEqual(decode_request(2, request).pin_uv_auth_param, b"")

    def test_management_missing_auth_precedes_other_missing_parameters(self):
        for subcommand in (1, 2, 4, 6, 7):
            self.assert_code(10, cbor_map(((b"\x01", cbor_uint(subcommand)),)), 0x36)
            self.assert_code(10, cbor_map(((b"\x01", cbor_uint(subcommand)), (b"\x03", b"\x01"))), 0x36)

    def test_long_rp_id_uses_message_bound_not_dns_limit(self):
        rp_id = "x" * 300
        assertion = cbor_map(((b"\x01", cbor_text(rp_id)), (b"\x02", HASH)))
        self.assertEqual(decode_request(2, assertion).rp_id, rp_id)
        rp = cbor_map(((cbor_text("id"), cbor_text(rp_id)),))
        make = cbor_map(((b"\x01", HASH), (b"\x02", rp), (b"\x03", USER), (b"\x04", cbor_array((PARAM,)))))
        self.assertEqual(decode_request(1, make).rp.id, rp_id)
        pin = cbor_map(((b"\x01", b"\x01"), (b"\x02", b"\x09"), (b"\x03", COSE_KEY),
                        (b"\x06", cbor_bytes(bytes(16))), (b"\x09", b"\x01"), (b"\x0a", cbor_text(rp_id))))
        self.assertEqual(decode_request(6, pin).rp_id, rp_id)
        oversized = cbor_map(((b"\x01", cbor_text("x" * 1000)), (b"\x02", HASH)))
        self.assert_code(2, oversized, 0x39)


if __name__ == "__main__":
    unittest.main()
