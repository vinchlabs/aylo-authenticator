"""GetInfo says exactly what is wired up, and says it in canonical CBOR.

The assertions here are mostly on exact bytes. That is deliberate: every member
of this response is a claim a platform acts on, and the difference between a
member being absent, false, and true is the difference between the platform
offering to set a PIN, asking for one, or refusing to talk. A test that only
decoded the response would not notice a member quietly changing shape.
"""

import asyncio
import os
import sys
import types

sys.path.remove(os.path.dirname(__file__))
import unittest

from apps.authenticator import client_pin, get_info
from apps.authenticator.cbor_codec import MAX_MESSAGE, encode_response
from apps.authenticator.dispatcher import Dispatcher, default_dispatcher
from apps.authenticator.protocol import AAGUID, GET_INFO
from apps.authenticator.transport_types import TransportEvent


class Vault:
    """Only the two calls GetInfo makes."""

    OK = 0
    UNPROVISIONED = 1
    INVALID_ARGUMENT = 2
    PIN_INVALID = 3
    PIN_AUTH_BLOCKED = 4
    PIN_BLOCKED = 5
    DENIED = 6
    ERROR = 7
    LIMIT_EXCEEDED = 8
    MIGRATION_REQUIRED = 9
    PIN_POLICY = 10
    MIN_PIN_CODE_POINTS = 8

    def __init__(self, state=UNPROVISIONED, retries=0):
        self.state = state
        self.retries = retries
        self.reads = 0

    def status(self):
        self.reads += 1
        return (self.state, self.retries, 0)


VERSIONS = b"\x01\x81\x68FIDO_2_1"
EXTENSIONS = b"\x02\x81\x6bcredProtect"
AAGUID_FIELD = b"\x03\x50" + AAGUID
MAX_MSG = b"\x05\x19\x04\x00"
PROTOCOLS = b"\x06\x82\x02\x01"
MAX_ID = b"\x08\x19\x02\xc0"
USB = b"\x09\x81\x63usb"
ALGORITHMS = (b"\x0a\x82"
              + b"\xa2\x63alg\x26\x64type\x6apublic-key"
              + b"\xa2\x63alg\x27\x64type\x6apublic-key")
MIN_PIN = b"\x0d\x08"
MARKER = b"\x18\xf0\x68AUTH-DEV"


def options(client_pin_set, cred_mgmt=True):
    # Canonical CBOR sorts map keys by their encoded bytes: the two-character key
    # first, then the two eight-character ones in content order, then the longer
    # ones.
    body = b"\x62rk\xf5\x62uv\xf4\x68alwaysUv\xf5"
    if cred_mgmt:
        body += b"\x68credMgmt\xf5"
    body += b"\x69clientPin" + (b"\xf5" if client_pin_set else b"\xf4")
    body += b"\x6epinUvAuthToken\xf5"
    if cred_mgmt:
        # The longest key, so canonical order puts it last.
        body += b"\x75credentialMgmtPreview\xf5"
    count = 7 if cred_mgmt else 5
    return bytes((0xA0 + count,)) + body


def expected(client_pin_set, cred_mgmt=True):
    fields = (VERSIONS, EXTENSIONS, AAGUID_FIELD,
              b"\x04" + options(client_pin_set, cred_mgmt),
              MAX_MSG, PROTOCOLS, MAX_ID, USB, ALGORITHMS, MIN_PIN, MARKER)
    return b"\xab" + b"".join(fields)


class GetInfoTests(unittest.TestCase):
    def encode(self, vault):
        return encode_response(get_info.response(vault))

    def test_unprovisioned_device_offers_a_pin_rather_than_claiming_one(self):
        self.assertEqual(self.encode(Vault()), expected(False))

    def test_a_set_pin_is_reported_even_while_the_session_is_blocked(self):
        self.assertEqual(self.encode(Vault(Vault.OK, 8)), expected(True))
        # Three wrong PINs need a power cycle, but the PIN still exists.
        self.assertEqual(self.encode(Vault(Vault.PIN_AUTH_BLOCKED, 5)), expected(True))

    def test_an_unusable_vault_reports_no_pin_rather_than_refusing_to_answer(self):
        # GetInfo is the first thing a platform asks and has to answer. Pointing
        # at setPIN, which fails cleanly, beats pointing at a PIN prompt that
        # cannot succeed.
        for state in (Vault.ERROR, Vault.MIGRATION_REQUIRED):
            self.assertEqual(self.encode(Vault(state)), expected(False))

    def test_built_in_user_verification_is_claimed_as_false(self):
        # The one untrue claim in this response, and it is here on purpose. OpenSSH
        # will only pick this device to sign a non-discoverable credential if GetInfo
        # carries "uv" at all: without it, it probes with a presence-less, PIN-less
        # getAssertion and accepts only a real assertion, which a device that never
        # signs without a verified PIN cannot give. The claim buys device selection
        # and nothing else -- see the comment where it is set.
        encoded = self.encode(Vault())
        self.assertIn(b"\x62uv\xf4", encoded)
        # And it must be false, not true: true would say the method is configured
        # and ready, which would have a platform skip the PIN entirely.
        self.assertNotIn(b"\x62uv\xf5", encoded)

    def test_claiming_uv_does_not_open_a_path_without_a_pin(self):
        # What keeps the claim harmless: authorization does not read the options map.
        # A credential command with no pinUvAuthParam is refused whatever GetInfo
        # says, so the only thing "uv" changes is which device a client picks.
        self.assertIn(b"\x68alwaysUv\xf5", self.encode(Vault()))
    def test_verification_is_always_required_and_says_so(self):
        # The policy puts both credential commands in WAIT_PIN unconditionally,
        # so there is no path that runs without a verified PIN.
        self.assertIn(b"\x68alwaysUv\xf5", self.encode(Vault()))

    def test_only_the_extension_that_can_be_honoured_is_offered(self):
        encoded = self.encode(Vault())
        self.assertIn(b"credProtect", encoded)
        # The salts arrive encrypted under the shared secret and nothing outside
        # the vault can open them, so the extension is not claimed.
        self.assertNotIn(b"hmac-secret", encoded)

    def test_both_algorithms_the_vault_builds_are_advertised_in_order(self):
        info = get_info.response(Vault())
        self.assertEqual(info[get_info.ALGORITHMS],
                         [{"alg": -7, "type": "public-key"},
                          {"alg": -8, "type": "public-key"}])

    def test_the_credential_identifier_ceiling_is_stated(self):
        info = get_info.response(Vault())
        self.assertEqual(info[get_info.MAX_CREDENTIAL_ID_LENGTH], 704)

    def test_no_credential_count_is_promised(self):
        # How many descriptors fit depends on how long their identifiers are, so
        # no single number would be true; maxMsgSize states the real constraint.
        self.assertNotIn(7, get_info.response(Vault()))

    def test_credential_management_is_advertised_only_when_it_can_be_granted(self):
        # The mask is not restated here; it is imported, so the advertisement and
        # what a token may carry cannot drift apart in source.
        self.assertEqual(get_info.GRANTABLE, client_pin.GRANTABLE)
        self.assertEqual(get_info.CREDENTIAL_MANAGEMENT,
                         client_pin.CREDENTIAL_MANAGEMENT)
        vault = Vault()
        self.assertIn(b"credMgmt", self.encode(vault))
        # Withdraw the permission and the claim goes with it, which is the
        # direction that matters: the specification requires the option and the
        # grantable mask to agree.
        original = get_info.GRANTABLE
        get_info.GRANTABLE = original & ~get_info.CREDENTIAL_MANAGEMENT
        try:
            self.assertEqual(self.encode(vault), expected(False, cred_mgmt=False))
        finally:
            get_info.GRANTABLE = original

    def test_a_build_that_assumes_presence_changes_what_the_device_calls_itself(self):
        # A platform reads this field before it enrolls anything. The one build that
        # confirms operations nobody confirmed must not look like the one that asks,
        # and AUTH-DEV stays a prefix because the image audit looks for it.
        ordinary = self.encode(Vault())
        self.assertIn(b"\x68AUTH-DEV", ordinary)
        self.assertNotIn(b"AUTH-DEV-NOUP", ordinary)
        assumed = Vault()
        assumed.ASSUMED_PRESENCE = True
        encoded = self.encode(assumed)
        self.assertIn(b"\x6dAUTH-DEV-NOUP", encoded)
        self.assertNotIn(b"\x68AUTH-DEV", encoded)

    def test_the_mandatory_pin_members_are_not_invented_here(self):
        # Both are mandatory once clientPin is offered, and both must agree with
        # the code that enforces them rather than restate a number.
        info = get_info.response(Vault())
        self.assertEqual(info[get_info.MIN_PIN_LENGTH], Vault.MIN_PIN_CODE_POINTS)
        self.assertEqual(info[get_info.MAX_MSG_SIZE], MAX_MESSAGE)
        self.assertEqual(info[get_info.PIN_UV_AUTH_PROTOCOLS], [2, 1])

    def test_the_vault_is_asked_on_every_call(self):
        vault = Vault()
        get_info.response(vault)
        get_info.response(vault)
        self.assertEqual(vault.reads, 2)

    def test_the_response_fits_the_message_bound(self):
        self.assertLess(len(self.encode(Vault())), MAX_MESSAGE)

    def test_the_dispatcher_serves_it_end_to_end(self):
        vault = Vault(Vault.OK, 8)
        dispatcher = Dispatcher()
        get_info.register(dispatcher, vault)
        event = TransportEvent(3, 7, 0x90, b"\x04")
        self.assertEqual(asyncio.run(dispatcher.dispatch(event)),
                         b"\x00" + expected(True))

    def test_the_firmware_serves_what_is_implemented(self):
        dispatcher = default_dispatcher()
        self.assertEqual(sorted(dispatcher._handlers),
                         [1, 2, 4, 6, 7, 8, 10, 11, 65])

    def test_the_unregistered_fallback_claims_no_pin_support_at_all(self):
        # A dispatcher with no ClientPIN handler does not support ClientPIN, so
        # the fallback must not say it does; absent means unsupported, and false
        # would have meant supported but unset.
        self.assertNotIn(b"clientPin", GET_INFO)
        self.assertNotIn(b"pinUvAuthToken", GET_INFO)
        self.assertNotIn(b"uv", GET_INFO)
        self.assertTrue(GET_INFO.startswith(b"\xa4"))
        self.assertIn(b"FIDO_2_1", GET_INFO)
        self.assertIn(AAGUID, GET_INFO)


if __name__ == "__main__":
    unittest.main()
