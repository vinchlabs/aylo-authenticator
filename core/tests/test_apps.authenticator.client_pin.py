"""ClientPIN routing, refusals, permission scoping and retry transitions.

The vault is stood in for here. What that buys is the ability to drive states a
real device reaches only destructively -- eight wrong PINs, a blocked session, a
migration-required medium -- and to check the exact bytes that go back on the
wire for each of them.

What it deliberately does not buy is evidence about the protocol cryptography.
The ECDH, both key derivations, the AES and the MACs live in the vault and are
exercised against the real one, with a platform implementation written
independently of it, in core/tests/test_trezorauth.py and in the native C suite.
The double models the vault's *state machine* faithfully and fakes its cipher
openly, so a test passing here never means "the crypto is right", only "the right
bytes were handed to it and the right answer came back out".
"""

import asyncio
import hashlib
import os
import sys
import types

sys.path.remove(os.path.dirname(__file__))
import unittest

# The handler reaches for the native module by name; under CPython it gets these.
# Both are public-value primitives -- an RP id hash and a transaction nonce -- so
# standing them in costs the suite nothing it was testing.
sys.modules["trezorcrypto"] = types.SimpleNamespace(
    sha256=hashlib.sha256, random=types.SimpleNamespace(bytes=bytes)
)

from apps.authenticator import client_pin
from apps.authenticator.dispatcher import Dispatcher, default_dispatcher
from apps.authenticator.policy import Policy, TransactionKey
from apps.authenticator.transport_types import TransportEvent

sys.modules["trezorio"] = types.SimpleNamespace(AUTH_TEST_PRESENCE=True)
from apps.authenticator.test_presence import TestPresenceProvider
del sys.modules["trezorio"]


def cbor_uint(n):
    return bytes((n,)) if n < 24 else bytes((24, n))


def cbor_bytes(value):
    if len(value) < 24:
        return bytes((0x40 + len(value),)) + value
    return b"\x58" + bytes((len(value),)) + value


def cbor_text(value):
    value = value.encode()
    if len(value) < 24:
        return bytes((0x60 + len(value),)) + value
    return b"\x78" + bytes((len(value),)) + value


def cbor_map(items):
    return bytes((0xA0 + len(items),)) + b"".join(k + v for k, v in items)


def code_points(value):
    """Count UTF-8 code points, or None when the encoding is not well formed.

    The authoritative version of this rule is utf8_code_points() in the vault;
    this one exists so that "send a malformed PIN" is a thing the test can
    actually do rather than a state it has to inject.
    """
    count = 0
    index = 0
    while index < len(value):
        lead = value[index]
        if lead < 0x80:
            width, point = 1, lead
        elif 0xC2 <= lead <= 0xDF:
            width, point = 2, lead & 0x1F
        elif 0xE0 <= lead <= 0xEF:
            width, point = 3, lead & 0x0F
        elif 0xF0 <= lead <= 0xF4:
            width, point = 4, lead & 0x07
        else:
            return None
        if index + width > len(value):
            return None
        for offset in range(1, width):
            following = value[index + offset]
            if following & 0xC0 != 0x80:
                return None
            point = (point << 6) | (following & 0x3F)
        if width == 3 and (point < 0x800 or 0xD800 <= point <= 0xDFFF):
            return None
        if width == 4 and not 0x10000 <= point <= 0x10FFFF:
            return None
        count += 1
        index += width
    return count


class Vault:
    """The native vault's observable behaviour, with an openly fake cipher."""

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

    PUBLIC = b"\x04" + bytes(range(1, 65))
    # (0, 0) solves no curve equation with a non-zero b, so P-256 has no such
    # point. It stands in for every peer key the real ECDH refuses.
    OFF_CURVE = b"\x04" + bytes(64)

    def __init__(self):
        self.pin = None
        self.retries = 0
        self.consecutive = 0
        self.agreement = False
        self.override = None
        self.calls = []
        self.issued = 0

    # -- the platform's half of the fake protocol ----------------------------
    @staticmethod
    def seal(protocol, plain, iv=b"\x11" * 16):
        body = bytes(b ^ 0x5A for b in plain)
        return iv + body if protocol == 2 else body

    @staticmethod
    def unseal(protocol, sealed):
        body = sealed[16:] if protocol == 2 else sealed
        return bytes(b ^ 0x5A for b in body)

    @staticmethod
    def mac(protocol, sealed):
        width = 32 if protocol == 2 else 16
        return bytes(sealed[i % len(sealed)] ^ 0x3C for i in range(width))

    @staticmethod
    def stored(pin):
        return hashlib.sha256(pin).digest()[:16]

    def provision(self, pin):
        self.pin = self.stored(pin)
        self.retries = 8
        self.consecutive = 0

    # -- the binding's surface ------------------------------------------------
    def status(self):
        if self.override is not None:
            return (self.override, self.retries, self.consecutive)
        if self.pin is None:
            return (self.UNPROVISIONED, 0, 0)
        if self.consecutive >= 3:
            return (self.PIN_AUTH_BLOCKED, self.retries, self.consecutive)
        return (self.OK, self.retries, self.consecutive)

    def key_agreement(self):
        self.calls.append(("key_agreement",))
        self.agreement = True
        return (self.OK, self.PUBLIC)

    def issue_token(self, pin_hash_enc, protocol, permissions, rp, peer):
        self.calls.append(
            ("issue_token", pin_hash_enc, protocol, permissions, rp, peer)
        )
        # Mirrors the binding, which raises rather than returning a code: any of
        # these means the application built the call wrong, not that the platform
        # sent something the application should forward.
        if protocol not in (1, 2):
            raise ValueError("invalid authenticator argument")
        if len(pin_hash_enc) != (32 if protocol == 2 else 16):
            raise ValueError("invalid authenticator argument")
        if not 1 <= permissions <= 0x3F:
            raise ValueError("invalid authenticator argument")
        if rp is not None and len(rp) != 32:
            raise ValueError("invalid authenticator argument")
        if permissions & 3 and rp is None:
            raise ValueError("invalid authenticator argument")
        if len(peer) != 65:
            raise ValueError("invalid authenticator argument")
        if self.consecutive >= 3:
            return (self.PIN_AUTH_BLOCKED, b"")
        if not self.agreement:
            return (self.DENIED, b"")
        self.agreement = False
        if peer[1:33] == bytes(32):
            return (self.INVALID_ARGUMENT, b"")
        if self.pin is None:
            return (self.UNPROVISIONED, b"")
        if self.unseal(protocol, pin_hash_enc) != self.pin:
            self.consecutive += 1
            self.retries -= 1
            if self.retries == 0:
                self.wipe()
                return (self.PIN_BLOCKED, b"")
            if self.consecutive == 3:
                return (self.PIN_AUTH_BLOCKED, b"")
            return (self.PIN_INVALID, b"")
        self.consecutive = 0
        self.retries = 8
        self.issued += 1
        return (self.OK, bytes((self.issued,)) * (48 if protocol == 2 else 32))

    def set_pin(self, protocol, new_pin_enc, param, peer):
        self.calls.append(("set_pin", protocol, new_pin_enc, param, peer))
        if protocol not in (1, 2):
            raise ValueError("invalid authenticator argument")
        if len(new_pin_enc) != (80 if protocol == 2 else 64):
            raise ValueError("invalid authenticator argument")
        if len(param) != (32 if protocol == 2 else 16):
            raise ValueError("invalid authenticator argument")
        if len(peer) != 65:
            raise ValueError("invalid authenticator argument")
        if not self.agreement:
            return self.DENIED
        self.agreement = False
        if peer[1:33] == bytes(32):
            return self.INVALID_ARGUMENT
        if param != self.mac(protocol, new_pin_enc):
            return self.DENIED
        padded = self.unseal(protocol, new_pin_enc)
        first = padded.find(b"\x00")
        if first < 0 or padded[first:] != bytes(len(padded) - first):
            return self.INVALID_ARGUMENT
        pin = padded[:first]
        points = code_points(pin)
        if points is None:
            return self.INVALID_ARGUMENT
        if points < self.MIN_PIN_CODE_POINTS:
            return self.PIN_POLICY
        if self.pin is not None:
            return self.DENIED
        self.provision(pin)
        return self.OK

    def disconnect(self):
        self.consecutive = 0
        self.agreement = False
        return self.OK

    def wipe(self):
        self.pin = None
        self.retries = 0
        self.consecutive = 0
        self.agreement = False
        return self.OK


def cose_key(public_key=Vault.PUBLIC):
    return cbor_map((
        (b"\x01", b"\x02"), (b"\x03", b"\x38\x18"), (b"\x20", b"\x01"),
        (b"\x21", cbor_bytes(public_key[1:33])),
        (b"\x22", cbor_bytes(public_key[33:65])),
    ))


def pin_request(subcommand, protocol=None, key=None, param=None, new_pin_enc=None,
                pin_hash_enc=None, permissions=None, rp_id=None):
    items = []
    if protocol is not None:
        items.append((b"\x01", cbor_uint(protocol)))
    items.append((b"\x02", cbor_uint(subcommand)))
    if key is not None:
        items.append((b"\x03", key))
    if param is not None:
        items.append((b"\x04", cbor_bytes(param)))
    if new_pin_enc is not None:
        items.append((b"\x05", cbor_bytes(new_pin_enc)))
    if pin_hash_enc is not None:
        items.append((b"\x06", cbor_bytes(pin_hash_enc)))
    if permissions is not None:
        items.append((b"\x09", cbor_uint(permissions)))
    if rp_id is not None:
        items.append((b"\x0a", cbor_text(rp_id)))
    return cbor_map(items)


class Clock:
    def __init__(self):
        self.now = 0

    def ticks(self):
        return self.now

    async def checkpoint(self):
        self.now += 1
        await asyncio.sleep(0)


PIN = b"12345678"
LONG_PIN = b"1234567890"
NONCE = bytes(32)
GENERATION = 3
CID = 7


class ClientPinTests(unittest.TestCase):
    def setUp(self):
        self.clock = Clock()
        self.presence = TestPresenceProvider(self.clock.ticks, self.clock.checkpoint)
        self.vault = Vault()
        self.dispatcher = Dispatcher()
        self.dispatcher.policy = Policy(self.presence, self.clock.ticks)
        client_pin.register(self.dispatcher, self.vault, lambda n: bytes(n))

    # -- plumbing -------------------------------------------------------------
    def send(self, payload):
        event = TransportEvent(GENERATION, CID, 0x90, b"\x06" + payload)
        return asyncio.run(self.dispatcher.dispatch(event))

    def send_with_edge(self, payload, edge=True, at=None):
        event = TransportEvent(GENERATION, CID, 0x90, b"\x06" + payload)
        key = TransactionKey(GENERATION, CID, NONCE)

        async def run():
            task = asyncio.create_task(self.dispatcher.dispatch(event))
            await asyncio.sleep(0)
            if at is not None:
                self.clock.now = at
            if edge:
                self.presence.test_event(key, True)
            return await task

        response = asyncio.run(run())
        # Drop the level so a following transaction sees a real rising edge.
        self.presence.test_event(key, False)
        return response

    def agree(self):
        response = self.send(pin_request(2, protocol=2))
        self.assertTrue(response.startswith(b"\x00"))
        return response

    def token_request(self, pin, protocol=2, permissions=0x02,
                      rp_id="example.com", public_key=Vault.PUBLIC):
        return pin_request(
            9, protocol=protocol, key=cose_key(public_key),
            pin_hash_enc=self.vault.seal(protocol, Vault.stored(pin)),
            permissions=permissions, rp_id=rp_id,
        )

    def set_pin_request(self, pin, protocol=2, param=None,
                        public_key=Vault.PUBLIC):
        sealed = self.vault.seal(protocol, pin + bytes(64 - len(pin)))
        return pin_request(
            3, protocol=protocol, key=cose_key(public_key),
            param=Vault.mac(protocol, sealed) if param is None else param,
            new_pin_enc=sealed,
        )

    # -- getPINRetries --------------------------------------------------------
    def test_retries_reports_count_and_power_cycle_state(self):
        self.assertEqual(self.send(pin_request(1)), b"\x35")
        self.vault.provision(PIN)
        self.assertEqual(self.send(pin_request(1)), b"\x00\xa2\x03\x08\x04\xf4")
        self.vault.consecutive = 3
        # A blocked session still has a truthful retry count; what it lacks is a
        # power cycle, and getRetries is the one response that may say so.
        self.assertEqual(self.send(pin_request(1)), b"\x00\xa2\x03\x08\x04\xf5")
        self.vault.consecutive = 0
        self.vault.retries = 5
        self.assertEqual(self.send(pin_request(1)), b"\x00\xa2\x03\x05\x04\xf4")

    def test_retries_forwards_states_that_are_not_a_working_pin(self):
        for state, code in ((Vault.MIGRATION_REQUIRED, b"\x7f"),
                            (Vault.ERROR, b"\x7f"),
                            (Vault.UNPROVISIONED, b"\x35")):
            self.vault.override = state
            self.assertEqual(self.send(pin_request(1)), code)

    # -- getKeyAgreement ------------------------------------------------------
    def test_key_agreement_returns_canonical_cose_key(self):
        expected = b"\x00\xa1\x01\xa5\x01\x02\x03\x38\x18\x20\x01"
        expected += b"\x21\x58\x20" + Vault.PUBLIC[1:33]
        expected += b"\x22\x58\x20" + Vault.PUBLIC[33:65]
        self.assertEqual(self.send(pin_request(2, protocol=2)), expected)
        self.assertEqual(self.send(pin_request(2, protocol=1)), expected)
        self.assertTrue(self.vault.agreement)

    def test_key_agreement_failure_istranslated_not_swallowed(self):
        self.vault.key_agreement = lambda: (Vault.ERROR, b"")
        self.assertEqual(self.send(pin_request(2, protocol=1)), b"\x7f")

    # -- refusals -------------------------------------------------------------
    def test_unimplemented_subcommands_are_refused_without_calling_the_vault(self):
        requests = (
            pin_request(4, protocol=1, key=cose_key(), param=bytes(16),
                        new_pin_enc=bytes(64), pin_hash_enc=bytes(16)),
            pin_request(5, protocol=1, key=cose_key(), pin_hash_enc=bytes(16)),
            pin_request(6, protocol=1, key=cose_key(), permissions=0x01,
                        rp_id="example.com"),
            pin_request(7),
        )
        for payload in requests:
            self.assertEqual(self.send(payload), b"\x3e")
        self.assertEqual(self.vault.calls, [])

    # -- setPIN ---------------------------------------------------------------
    def test_set_pin_needs_a_fresh_edge_and_forwards_the_ciphertext_intact(self):
        for protocol in (2, 1):
            self.setUp()
            self.agree()
            payload = self.set_pin_request(PIN, protocol)
            self.assertEqual(self.send_with_edge(payload), b"\x00")
            call = self.vault.calls[-1]
            self.assertEqual(call[0], "set_pin")
            self.assertEqual(call[1], protocol)
            self.assertEqual(call[2], Vault.seal(protocol, PIN + bytes(56)))
            self.assertEqual(call[3], Vault.mac(protocol, call[2]))
            self.assertEqual(call[4], Vault.PUBLIC)
            self.assertEqual(self.vault.pin, Vault.stored(PIN))
            self.assertEqual(self.vault.retries, 8)
            self.assertIsNone(self.dispatcher.policy.key)

    def test_set_pin_without_an_edge_is_denied_and_never_reaches_the_vault(self):
        self.agree()
        payload = self.set_pin_request(PIN)
        self.assertEqual(self.send_with_edge(payload, edge=False, at=30000), b"\x27")
        self.assertEqual([call[0] for call in self.vault.calls], ["key_agreement"])
        self.assertIsNone(self.vault.pin)
        self.assertIsNone(self.dispatcher.policy.key)

    def test_set_pin_on_a_provisioned_device_asks_for_no_card(self):
        self.vault.provision(PIN)
        self.agree()
        payload = self.set_pin_request(LONG_PIN)
        self.assertEqual(self.send(payload), b"\x33")
        self.assertEqual([call[0] for call in self.vault.calls], ["key_agreement"])
        self.assertIsNone(self.presence.key)
        self.assertEqual(self.vault.pin, Vault.stored(PIN))

    def test_set_pin_forwards_unusable_vault_states_before_asking_for_a_card(self):
        for state, code in ((Vault.MIGRATION_REQUIRED, b"\x7f"),
                            (Vault.ERROR, b"\x7f"),
                            (Vault.PIN_AUTH_BLOCKED, b"\x34")):
            self.vault.override = state
            self.assertEqual(self.send(self.set_pin_request(PIN)), code)
            self.assertIsNone(self.presence.key)

    def test_set_pin_rejections_keep_their_own_meaning(self):
        short = b"1234567"
        malformed = b"\xc3\x28abcdefgh"
        cases = (
            (self.set_pin_request(short), b"\x37"),
            (self.set_pin_request(malformed), b"\x02"),
            (self.set_pin_request(PIN, param=bytes(32)), b"\x33"),
            (self.set_pin_request(PIN, public_key=Vault.OFF_CURVE), b"\x02"),
        )
        for payload, code in cases:
            self.setUp()
            self.agree()
            self.assertEqual(self.send_with_edge(payload), code)
            self.assertIsNone(self.vault.pin)

    def test_set_pin_without_a_key_agreement_is_pin_auth_invalid(self):
        self.assertEqual(self.send_with_edge(self.set_pin_request(PIN)), b"\x33")
        self.assertIsNone(self.vault.pin)

    # -- token issuance -------------------------------------------------------
    def test_token_is_returned_for_both_protocols_with_the_rp_hashed(self):
        for protocol, width in ((2, 48), (1, 32)):
            self.setUp()
            self.vault.provision(PIN)
            self.agree()
            response = self.send(self.token_request(PIN, protocol))
            token = bytes((1,)) * width
            self.assertEqual(response, b"\x00\xa1\x02" + cbor_bytes(token))
            call = self.vault.calls[-1]
            self.assertEqual(call[1], Vault.seal(protocol, Vault.stored(PIN)))
            self.assertEqual(call[2], protocol)
            self.assertEqual(call[3], 0x02)
            self.assertEqual(call[4], hashlib.sha256(b"example.com").digest())
            self.assertEqual(call[5], Vault.PUBLIC)

    def test_unscoped_permission_passes_no_rp_rather_than_an_empty_one(self):
        # cm is the one permission that is not RP-scoped, and credential
        # management depends on it staying that way: a token bound to one relying
        # party cannot enumerate the others. The binding rejects a short buffer,
        # so only an absent relying party can mean "no relying party".
        self.vault.provision(PIN)
        self.agree()
        payload = self.token_request(PIN, permissions=0x04, rp_id=None)
        self.assertTrue(self.send(payload).startswith(b"\x00\xa1\x02"))
        self.assertIsNone(self.vault.calls[-1][4])

    def test_permissions_this_device_cannot_grant_are_refused(self):
        # be, lbw and acfg name bio enrollment, large blobs and authenticator
        # configuration. None is advertised, and the specification requires
        # UNAUTHORIZED_PERMISSION for a permission whose option is not offered --
        # including 0x3f, which asks for everything and so asks for those too.
        for permissions in (0x08, 0x10, 0x20, 0x3F):
            self.setUp()
            self.vault.provision(PIN)
            self.agree()
            payload = self.token_request(PIN, permissions=permissions)
            self.assertEqual(self.send(payload), b"\x40")
            self.assertEqual([call[0] for call in self.vault.calls], ["key_agreement"])

    def test_grantable_permissions_reach_the_vault_unchanged(self):
        for permissions in (0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07):
            self.setUp()
            self.vault.provision(PIN)
            self.agree()
            payload = self.token_request(PIN, permissions=permissions)
            self.assertTrue(self.send(payload).startswith(b"\x00\xa1\x02"))
            self.assertEqual(self.vault.calls[-1][3], permissions)

    def test_token_needs_a_key_agreement_per_request(self):
        self.vault.provision(PIN)
        self.agree()
        self.assertTrue(self.send(self.token_request(PIN)).startswith(b"\x00"))
        self.assertEqual(self.send(self.token_request(PIN)), b"\x33")

    def test_off_curve_peer_key_is_an_invalid_parameter(self):
        self.vault.provision(PIN)
        self.agree()
        payload = self.token_request(PIN, public_key=Vault.OFF_CURVE)
        self.assertEqual(self.send(payload), b"\x02")

    def test_token_on_an_unprovisioned_device_says_no_pin_is_set(self):
        self.agree()
        self.assertEqual(self.send(self.token_request(PIN)), b"\x35")

    # -- retry transitions ----------------------------------------------------
    def attempt(self, pin):
        self.agree()
        return self.send(self.token_request(pin))

    def test_three_wrong_hashes_block_the_session_until_disconnect(self):
        self.vault.provision(PIN)
        wrong = b"87654321"
        self.assertEqual(self.attempt(wrong), b"\x31")
        self.assertEqual(self.attempt(wrong), b"\x31")
        self.assertEqual(self.attempt(wrong), b"\x34")
        # A blocked session refuses even the right PIN, and refuses it without
        # spending a retry: that is what makes power cycling the cure.
        self.assertEqual(self.attempt(PIN), b"\x34")
        self.assertEqual(self.vault.retries, 5)
        self.vault.disconnect()
        self.assertTrue(self.attempt(PIN).startswith(b"\x00\xa1\x02"))

    def test_a_valid_pin_resets_both_counters(self):
        self.vault.provision(PIN)
        wrong = b"87654321"
        self.assertEqual(self.attempt(wrong), b"\x31")
        self.assertEqual(self.attempt(wrong), b"\x31")
        self.assertEqual((self.vault.retries, self.vault.consecutive), (6, 2))
        self.assertTrue(self.attempt(PIN).startswith(b"\x00\xa1\x02"))
        self.assertEqual((self.vault.retries, self.vault.consecutive), (8, 0))
        self.assertEqual(self.send(pin_request(1)), b"\x00\xa2\x03\x08\x04\xf4")

    def test_eight_failures_across_reconnects_destroy_the_root(self):
        self.vault.provision(PIN)
        wrong = b"87654321"
        codes = []
        for spent in range(8):
            if spent and spent % 3 == 0:
                self.vault.disconnect()
            codes.append(self.attempt(wrong))
        self.assertEqual(codes, [b"\x31", b"\x31", b"\x34"] * 2 + [b"\x31", b"\x32"])
        self.assertIsNone(self.vault.pin)
        self.assertEqual(self.vault.retries, 0)
        self.assertEqual(self.send(pin_request(1)), b"\x35")
        self.assertEqual(self.attempt(PIN), b"\x35")

    # -- wiring ---------------------------------------------------------------
    def test_default_dispatcher_serves_client_pin_among_what_exists(self):
        dispatcher = default_dispatcher()
        self.assertEqual(sorted(dispatcher._handlers),
                         [1, 2, 4, 6, 7, 8, 10, 11, 65])

    def test_the_native_module_is_imported_only_when_a_request_arrives(self):
        handler = client_pin.ClientPin(Policy(self.presence, self.clock.ticks))
        self.assertIsNone(handler._auth)


if __name__ == "__main__":
    unittest.main()
