"""getAssertion: what is signed, what is refused, and how a continuation ends.

The interesting assertions here are about the continuation. A follow-up assertion
is the one operation that does not collect its own physical edge, so the tests
say exactly what it inherits and exactly when it stops being allowed: a different
channel, an aborted transaction, a count that ran out, or a new assertion
arriving in the middle.
"""

import asyncio
import hashlib
import os
import sys
import types

sys.path.remove(os.path.dirname(__file__))
import unittest

sys.modules["trezorcrypto"] = types.SimpleNamespace(
    sha256=hashlib.sha256, random=types.SimpleNamespace(bytes=bytes)
)
sys.modules["trezor"] = types.ModuleType("trezor")
sys.modules["trezor.crypto"] = types.SimpleNamespace(
    hashlib=types.SimpleNamespace(sha256=hashlib.sha256)
)

# resident_store.py reaches storage.authenticator, and on the device the package
# around it is the frozen shim in core/src/authenticator_frozen/storage/. Under
# CPython the name resolves to the wallet package, which pulls in trezorconfig,
# so the real pass-through module is loaded on its own rather than reimplemented.
import importlib.util

sys.modules["storage"] = types.ModuleType("storage")
_spec = importlib.util.spec_from_file_location(
    "storage.authenticator",
    os.path.join(os.path.dirname(os.path.abspath(__file__)),
                 "..", "src", "storage", "authenticator.py"),
)
_module = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_module)
sys.modules["storage.authenticator"] = _module


from apps.authenticator import get_assertion
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
    if len(value) < 256:
        return b"\x58" + bytes((len(value),)) + value
    return b"\x59" + len(value).to_bytes(2, "big") + value


def cbor_text(value):
    value = value.encode()
    if len(value) < 24:
        return bytes((0x60 + len(value),)) + value
    return b"\x78" + bytes((len(value),)) + value


def cbor_array(items):
    return bytes((0x80 + len(items),)) + b"".join(items)


def cbor_map(items):
    return bytes((0xA0 + len(items),)) + b"".join(k + v for k, v in items)


RP_ID = "example.com"
RP_HASH = hashlib.sha256(RP_ID.encode()).digest()
OTHER_HASH = hashlib.sha256(b"other.com").digest()
CLIENT_DATA = bytes(range(32))
COSE_ES256 = bytes.fromhex("a5010203262001215820") + bytes(32) + \
    bytes.fromhex("225820") + bytes(32)


def credential_id(marker):
    return bytes((marker,)) * 78


def metadata(user_id=b"user", rp_id=RP_ID, user_name=b"", display=b""):
    return (bytes((1, 0, 3, len(rp_id) >> 8, len(rp_id) & 0xFF,
                   len(user_id), 0, len(user_name), len(display)))
            + rp_id.encode() + user_id + user_name + display)


class Vault:
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

    def __init__(self, state=OK, granted=0x02, token=b"t" * 32):
        self.state = state
        self.granted = granted
        self.token = token
        self.calls = []
        self.known = {}
        self.slots = {}
        self.bound = None
        self.oversized = False

    def resident_get(self, index):
        self.calls.append(("resident_get", index))
        record = self.slots.get(index)
        if record is None:
            return (self.UNPROVISIONED, b"", b"", -7, b"", b"")
        identifier, rp_hash = record
        # Under a token bound to one relying party the vault reports every other
        # party's slot as empty, which is what keeps the walk from learning how
        # many credentials anyone else stored.
        if self.bound is not None and rp_hash != self.bound:
            return (self.UNPROVISIONED, b"", b"", -7, b"", b"")
        return (self.OK,) + self.known[(identifier, rp_hash)]

    def resident_scan(self, rp_hash):
        self.calls.append(("resident_scan", rp_hash))
        occupancy = bytearray(100)
        for index, (_identifier, slot_hash) in self.slots.items():
            # The same scope the per-slot read applies above: under a token bound
            # to one relying party, every other party's slot reads as empty, so
            # occupancy cannot leak how many credentials anyone else stored.
            if self.bound is not None and slot_hash != self.bound:
                continue
            if rp_hash is not None and slot_hash != rp_hash:
                continue
            occupancy[index] = 1
        return (self.OK, bytes(occupancy))

    def resident_set(self, index, identifier, rp_hash):
        self.calls.append(("resident_set", index))
        if self.oversized:
            return self.LIMIT_EXCEEDED
        if index in self.slots:
            # The vault refuses to overwrite an occupied slot.
            return self.DENIED
        self.slots[index] = (identifier, rp_hash)
        return self.OK

    def resident_delete(self, index):
        self.calls.append(("resident_delete", index))
        return self.OK if self.slots.pop(index, None) else self.DENIED

    def hold(self, marker, user_id=b"user", rp_hash=RP_HASH, rp_id=RP_ID,
             user_name=b"", display=b""):
        identifier = credential_id(marker)
        self.known[(identifier, rp_hash)] = (
            identifier, rp_hash, -7,
            metadata(user_id, rp_id, user_name, display), COSE_ES256,
        )
        return identifier

    def status(self):
        # Recorded like every other call: a test that claims the vault was not
        # asked anything can only mean it if the double counts this one too.
        self.calls.append(("status",))
        return (self.state, 8, 0)

    def check_auth(self, protocol, message, param, permissions, rp):
        self.calls.append(("check_auth", permissions))
        if protocol not in (1, 2) or len(param) != (32 if protocol == 2 else 16):
            raise ValueError("invalid authenticator argument")
        if not 1 <= permissions <= 0x3F:
            raise ValueError("invalid authenticator argument")
        if permissions & ~self.granted:
            return self.DENIED
        expected = hashlib.sha256(self.token + message).digest()
        width = 32 if protocol == 2 else 16
        return self.OK if param == expected[:width] else self.DENIED

    def credential_open(self, identifier, rp_hash):
        self.calls.append(("credential_open", identifier[:1]))
        record = self.known.get((identifier, rp_hash))
        if record is None:
            return (self.DENIED, b"", b"", -7, b"", b"")
        return (self.OK,) + record

    def credential_sign(self, identifier, rp_hash, algorithm, message):
        self.calls.append(("credential_sign", identifier[:1], message))
        if not 1 <= len(message) <= 1024:
            raise ValueError("invalid authenticator argument")
        return (self.OK, hashlib.sha256(identifier + message).digest()[:64])


def mac(vault, protocol, message):
    digest = hashlib.sha256(vault.token + message).digest()
    return digest if protocol == 2 else digest[:16]


def assertion_request(vault, protocol=2, rp_id=RP_ID, allow=None, options=None,
                      param=None, client_data=CLIENT_DATA):
    items = [(b"\x01", cbor_text(rp_id)), (b"\x02", cbor_bytes(client_data))]
    if allow is not None:
        items.append((b"\x03", cbor_array(tuple(
            cbor_map(((cbor_text("id"), cbor_bytes(identifier)),
                      (cbor_text("type"), cbor_text("public-key"))))
            for identifier in allow
        ))))
    if options is not None:
        items.append((b"\x05", options))
    if param is None:
        param = mac(vault, protocol, client_data)
    if param is not False:
        items.append((b"\x06", cbor_bytes(param)))
        items.append((b"\x07", cbor_uint(protocol)))
    return cbor_map(items)


class Clock:
    def __init__(self):
        self.now = 0

    def ticks(self):
        return self.now

    async def checkpoint(self):
        self.now += 1
        await asyncio.sleep(0)


NONCE = bytes(32)
GENERATION = 3
CID = 7


class GetAssertionTests(unittest.TestCase):
    def setUp(self):
        self.clock = Clock()
        self.presence = TestPresenceProvider(self.clock.ticks, self.clock.checkpoint)
        self.vault = Vault()
        sys.modules["trezorauth"] = self.vault
        self.dispatcher = Dispatcher()
        self.dispatcher.policy = Policy(self.presence, self.clock.ticks)
        get_assertion.register(self.dispatcher, self.vault, lambda n: bytes(n))
        self.handler = self.dispatcher._handlers[2].__self__

    def tearDown(self):
        sys.modules.pop("trezorauth", None)

    def send(self, payload, edge=True, at=None, generation=GENERATION, cid=CID):
        event = TransportEvent(generation, cid, 0x90, b"\x02" + payload)
        key = TransactionKey(generation, cid, NONCE)

        async def run():
            task = asyncio.create_task(self.dispatcher.dispatch(event))
            await asyncio.sleep(0)
            if at is not None:
                self.clock.now = at
            if edge:
                self.presence.test_event(key, True)
            return await task

        response = asyncio.run(run())
        self.presence.test_event(key, False)
        return response

    def next(self, generation=GENERATION, cid=CID):
        event = TransportEvent(generation, cid, 0x90, b"\x08")
        return asyncio.run(self.dispatcher.dispatch(event))

    def signature(self, identifier, flags=0x05):
        data = RP_HASH + bytes((flags,)) + bytes(4)
        return hashlib.sha256(identifier + data + CLIENT_DATA).digest()[:64]

    def expected(self, identifier, user_id=b"user", count=None, flags=0x05,
                 name=None, display=None):
        data = RP_HASH + bytes((flags,)) + bytes(4)
        # Canonical order puts the shorter key first, so id, then name, then
        # displayName, which is the order the device's encoder produces.
        user = [(cbor_text("id"), cbor_bytes(user_id))]
        if name is not None:
            user.append((cbor_text("name"), cbor_text(name)))
        if display is not None:
            user.append((cbor_text("displayName"), cbor_text(display)))
        body = [
            (b"\x01", cbor_map(((cbor_text("id"), cbor_bytes(identifier)),
                                (cbor_text("type"), cbor_text("public-key"))))),
            (b"\x02", cbor_bytes(data)),
            (b"\x03", cbor_bytes(self.signature(identifier, flags))),
            (b"\x04", cbor_map(tuple(user))),
        ]
        if count is not None:
            body.append((b"\x05", cbor_uint(count)))
        return b"\x00" + cbor_map(body)

    # -- the assertion itself -------------------------------------------------
    def test_signs_over_authenticator_data_and_the_client_data_hash(self):
        for protocol in (2, 1):
            self.setUp()
            identifier = self.vault.hold(1)
            payload = assertion_request(self.vault, protocol, allow=[identifier])
            self.assertEqual(self.send(payload), self.expected(identifier))
            signed = [c for c in self.vault.calls if c[0] == "credential_sign"]
            self.assertEqual(len(signed), 1)
            # 37 bytes of authenticatorData then the 32-byte client data hash.
            self.assertEqual(signed[0][2],
                             RP_HASH + b"\x05" + bytes(4) + CLIENT_DATA)
            self.assertIsNone(self.dispatcher.policy.key)

    def test_the_flags_report_presence_and_verification_but_no_attestation(self):
        identifier = self.vault.hold(1)
        response = self.send(assertion_request(self.vault, allow=[identifier]))
        at = response.index(RP_HASH)
        self.assertEqual(response[at + 32], 0x01 | 0x04)
        self.assertEqual(response[at + 33:at + 37], bytes(4))

    def test_only_the_user_handle_is_returned(self):
        identifier = self.vault.hold(1, user_id=b"handle")
        response = self.send(assertion_request(self.vault, allow=[identifier]))
        self.assertEqual(response, self.expected(identifier, user_id=b"handle"))
        self.assertNotIn(b"displayName", response)
        self.assertNotIn(b"name", response)

    # -- several accounts on one relying party --------------------------------
    def two_accounts(self):
        first = self.vault.hold(1, user_id=b"one", user_name=b"ann",
                                display=b"Ann Smith")
        second = self.vault.hold(2, user_id=b"two", user_name=b"bob",
                                 display=b"Bob Jones")
        self.vault.slots[4] = (first, RP_HASH)
        self.vault.slots[9] = (second, RP_HASH)
        self.vault.bound = RP_HASH
        return first, second

    def test_several_discovered_accounts_are_named_for_the_picker(self):
        # With no display here, the platform's picker is the only way to choose,
        # and it has nothing to show unless the accounts are named. The names go
        # no further: the platform hands the relying party the handle alone.
        first, second = self.two_accounts()
        self.assertEqual(
            self.send(assertion_request(self.vault)),
            self.expected(first, b"one", count=2, name="ann",
                          display="Ann Smith"),
        )
        self.assertEqual(
            self.next(),
            self.expected(second, b"two", name="bob", display="Bob Jones"),
        )

    def test_one_discovered_account_is_the_handle_alone(self):
        # Nothing to choose between, so nothing to show, so nothing is said.
        identifier = self.vault.hold(1, user_name=b"ann", display=b"Ann Smith")
        self.vault.slots[4] = (identifier, RP_HASH)
        self.vault.bound = RP_HASH
        self.assertEqual(self.send(assertion_request(self.vault)),
                         self.expected(identifier))

    def test_an_allow_list_is_answered_without_names(self):
        # The platform sent the identifiers, so it already knows what it asked
        # for; a name would be personal data this answer has no reason to carry.
        first = self.vault.hold(1, user_id=b"one", user_name=b"ann",
                                display=b"Ann Smith")
        second = self.vault.hold(2, user_id=b"two", user_name=b"bob",
                                 display=b"Bob Jones")
        self.assertEqual(
            self.send(assertion_request(self.vault, allow=[first, second])),
            self.expected(first, b"one", count=2),
        )
        self.assertEqual(self.next(), self.expected(second, b"two"))

    # -- locating -------------------------------------------------------------
    def test_a_credential_for_another_party_is_not_found(self):
        foreign = self.vault.hold(2, rp_hash=OTHER_HASH, rp_id="other.com")
        payload = assertion_request(self.vault, allow=[foreign])
        self.assertEqual(self.send(payload), b"\x2e")

    def test_an_unknown_identifier_is_not_found(self):
        payload = assertion_request(self.vault, allow=[credential_id(9)])
        self.assertEqual(self.send(payload), b"\x2e")

    def test_discoverable_credentials_are_found_without_an_allow_list(self):
        first = self.vault.hold(1, user_id=b"one")
        second = self.vault.hold(2, user_id=b"two")
        self.vault.slots[5] = (first, RP_HASH)
        self.vault.slots[7] = (second, RP_HASH)
        self.vault.bound = RP_HASH
        self.assertEqual(self.send(assertion_request(self.vault)),
                         self.expected(first, b"one", count=2))
        self.assertEqual(self.next(), self.expected(second, b"two"))

    def test_another_partys_stored_credential_is_invisible(self):
        foreign = self.vault.hold(3, rp_hash=OTHER_HASH, rp_id="other.com")
        self.vault.slots[0] = (foreign, OTHER_HASH)
        self.vault.bound = RP_HASH
        self.assertEqual(self.send(assertion_request(self.vault)), b"\x2e")

    def test_a_non_discoverable_credential_is_not_discovered(self):
        # Held by the vault but never stored in a slot, so an assertion without
        # an allow list cannot reach it.
        self.vault.hold(1)
        self.vault.bound = RP_HASH
        self.assertEqual(self.send(assertion_request(self.vault)), b"\x2e")

    def test_unknown_entries_are_skipped_rather_than_failing_the_request(self):
        identifier = self.vault.hold(3)
        payload = assertion_request(
            self.vault, allow=[credential_id(9), identifier, credential_id(8)]
        )
        self.assertEqual(self.send(payload), self.expected(identifier))

    def test_nothing_is_signed_when_nothing_is_found(self):
        payload = assertion_request(self.vault, allow=[credential_id(9)])
        self.assertEqual(self.send(payload, edge=False), b"\x2e")
        self.assertNotIn("credential_sign", [c[0] for c in self.vault.calls])

    # -- the silent pre-flight ------------------------------------------------
    def silent(self, **kwargs):
        """A request carrying options {"up": false}."""
        return assertion_request(
            self.vault, options=cbor_map(((cbor_text("up"), b"\xf4"),)), **kwargs
        )

    def test_a_silent_probe_without_a_token_says_presence_is_required(self):
        # OpenSSH uses this exact shape -- allow list, up false, no token -- to work
        # out which attached device holds a non-discoverable credential, and accepts
        # only success or UP_REQUIRED as evidence that it does. NO_CREDENTIALS means
        # "not this device" to it, so answering that way loses the device entirely.
        identifier = self.vault.hold(1)
        self.vault.slots[0] = (identifier, RP_HASH)
        self.assertEqual(
            self.send(self.silent(allow=[identifier], param=False), edge=False),
            b"\x3b")
        self.assertEqual(self.vault.calls, [])

    def test_the_token_less_probe_answers_the_same_whatever_is_stored(self):
        # The refusal is a constant, which is the whole reason it is safe: it is the
        # same for a credential this device holds and for one it has never seen, so
        # an unverified probe learns neither whether a slot is used nor whether a
        # PIN is set.
        held = self.vault.hold(1)
        self.vault.slots[0] = (held, RP_HASH)
        stranger = credential_id(9)
        for allow in ([held], [stranger], None):
            self.assertEqual(
                self.send(self.silent(allow=allow, param=False), edge=False),
                b"\x3b")
        self.assertEqual(self.vault.calls, [])

    def test_a_silent_assertion_clears_the_presence_bit_and_waits_for_no_edge(self):
        waits = []
        provider = self.presence.wait_for_fresh_edge

        async def record(key, timeout_ms):
            waits.append(timeout_ms)
            return await provider(key, timeout_ms)

        self.presence.wait_for_fresh_edge = record
        identifier = self.vault.hold(1)
        response = self.send(self.silent(allow=[identifier]), edge=False)
        self.assertEqual(response, self.expected(identifier, flags=0x04))
        self.assertEqual(waits, [])
        self.assertIsNone(self.dispatcher.policy.key)

    def test_a_silent_assertion_still_needs_a_token_that_carries_ga(self):
        identifier = self.vault.hold(1)
        forged = self.silent(allow=[identifier], param=bytes(32))
        self.assertEqual(self.send(forged, edge=False), b"\x33")
        self.assertNotIn("credential_open", [c[0] for c in self.vault.calls])
        self.vault.granted = 0x01
        self.assertEqual(
            self.send(self.silent(allow=[identifier]), edge=False), b"\x33"
        )
        self.assertNotIn("credential_sign", [c[0] for c in self.vault.calls])

    def test_a_silent_assertion_finds_nothing_it_does_not_hold(self):
        self.assertEqual(
            self.send(self.silent(allow=[credential_id(9)]), edge=False), b"\x2e"
        )
        self.assertNotIn("credential_sign", [c[0] for c in self.vault.calls])

    def test_a_silent_assertion_discovers_this_partys_slots(self):
        identifier = self.vault.hold(1)
        self.vault.slots[3] = (identifier, RP_HASH)
        self.vault.bound = RP_HASH
        self.assertEqual(self.send(self.silent(), edge=False),
                         self.expected(identifier, flags=0x04))

    def test_a_silent_continuation_keeps_the_presence_bit_clear(self):
        first = self.vault.hold(1, user_id=b"one")
        second = self.vault.hold(2, user_id=b"two")
        self.assertEqual(self.send(self.silent(allow=[first, second]), edge=False),
                         self.expected(first, b"one", count=2, flags=0x04))
        self.assertEqual(self.next(), self.expected(second, b"two", flags=0x04))

    # -- refusals -------------------------------------------------------------
    def test_no_pin_auth_param_is_refused(self):
        self.vault.hold(1)
        self.assertEqual(self.send(assertion_request(self.vault, param=False)), b"\x36")
        self.vault.state = Vault.UNPROVISIONED
        self.assertEqual(self.send(assertion_request(self.vault, param=False)), b"\x35")

    def test_the_selection_probe_answers_whether_a_pin_exists(self):
        self.assertEqual(self.send(assertion_request(self.vault, param=b"")), b"\x31")
        self.vault.state = Vault.UNPROVISIONED
        self.assertEqual(self.send(assertion_request(self.vault, param=b"")), b"\x35")

    def test_a_forged_pin_auth_param_signs_nothing(self):
        identifier = self.vault.hold(1)
        payload = assertion_request(self.vault, allow=[identifier], param=bytes(32))
        self.assertEqual(self.send(payload, edge=False), b"\x33")
        self.assertNotIn("credential_open", [c[0] for c in self.vault.calls])

    def test_a_token_without_the_assertion_bit_is_refused(self):
        self.vault.granted = 0x01
        identifier = self.vault.hold(1)
        payload = assertion_request(self.vault, allow=[identifier])
        self.assertEqual(self.send(payload), b"\x33")

    def test_presence_is_required_for_the_first_assertion(self):
        identifier = self.vault.hold(1)
        payload = assertion_request(self.vault, allow=[identifier])
        self.assertEqual(self.send(payload, edge=False, at=30000), b"\x27")
        self.assertNotIn("credential_sign", [c[0] for c in self.vault.calls])

    # -- continuations --------------------------------------------------------
    def three(self):
        first = self.vault.hold(1, user_id=b"one")
        second = self.vault.hold(2, user_id=b"two")
        third = self.vault.hold(3, user_id=b"three")
        return first, second, third

    def test_a_continuation_reports_its_count_and_hands_back_the_rest(self):
        first, second, third = self.three()
        payload = assertion_request(self.vault, allow=[first, second, third])
        self.assertEqual(self.send(payload), self.expected(first, b"one", count=3))
        self.assertEqual(self.dispatcher.policy.remaining, 2)
        self.assertEqual(self.next(), self.expected(second, b"two"))
        self.assertEqual(self.next(), self.expected(third, b"three"))
        # The count ran out; the transaction and the held credentials are gone.
        self.assertIsNone(self.dispatcher.policy.key)
        self.assertEqual(self.next(), b"\x30")

    def test_a_continuation_collects_no_further_presence(self):
        first, second, _third = self.three()
        payload = assertion_request(self.vault, allow=[first, second])
        self.assertTrue(self.send(payload).startswith(b"\x00"))
        self.assertIsNone(self.presence.key)
        # No edge is fed here, and the follow-up still answers.
        self.assertEqual(self.next(), self.expected(second, b"two"))

    def test_a_single_credential_reports_no_count_and_leaves_nothing_pending(self):
        identifier = self.vault.hold(1)
        payload = assertion_request(self.vault, allow=[identifier])
        response = self.send(payload)
        self.assertEqual(response, self.expected(identifier))
        self.assertNotIn(b"\x05", response[-2:])
        self.assertEqual(self.next(), b"\x30")

    def test_a_continuation_belongs_to_one_channel(self):
        # Enforced by the dispatcher's continuation gate and by the policy, which
        # compares the whole transaction key; this asserts the outcome rather
        # than a particular layer.
        first, second, _third = self.three()
        payload = assertion_request(self.vault, allow=[first, second])
        self.assertTrue(self.send(payload).startswith(b"\x00"))
        self.assertEqual(self.next(cid=8), b"\x30")
        self.assertEqual(self.next(generation=4), b"\x30")

    def test_a_scan_that_ignores_the_filter_cannot_assert_for_another_party(self):
        # The filter the scan takes is the vault's answer, not this side's proof.
        # A vault that answered a filtered scan with someone else's slot would,
        # without the relying-party comparison after the read, produce a signature
        # for a party the request never named. This drives exactly that vault: the
        # scan ignores the filter, the read is honest, and the refusal has to come
        # from the comparison.
        foreign = self.vault.hold(3, rp_hash=OTHER_HASH, rp_id="other.com")
        self.vault.slots[0] = (foreign, OTHER_HASH)
        self.vault.bound = None
        honest = self.vault.resident_scan
        self.vault.resident_scan = lambda rp_hash: honest(None)
        self.assertEqual(self.send(assertion_request(self.vault)), b"\x2e")
        self.assertNotIn("credential_sign", [c[0] for c in self.vault.calls])

    def test_a_wrongly_scoped_token_still_cannot_assert_for_another_party(self):
        # The vault hides other parties' slots from a bound token, so this drives
        # the case where it did not: with the scoping removed, the discovery walk
        # must still refuse a credential that belongs to someone else.
        foreign = self.vault.hold(3, rp_hash=OTHER_HASH, rp_id="other.com")
        self.vault.slots[0] = (foreign, OTHER_HASH)
        self.vault.bound = None
        self.assertEqual(self.send(assertion_request(self.vault)), b"\x2e")
        self.assertNotIn("credential_sign", [c[0] for c in self.vault.calls])

    def test_a_new_assertion_discards_the_outstanding_continuation(self):
        first, second, _third = self.three()
        payload = assertion_request(self.vault, allow=[first, second])
        self.assertTrue(self.send(payload).startswith(b"\x00"))
        self.assertEqual(len(self.handler._pending), 1)
        single = assertion_request(self.vault, allow=[first])
        self.assertEqual(self.send(single), self.expected(first, b"one"))
        self.assertEqual(self.handler._pending, [])
        self.assertEqual(self.next(), b"\x30")

    def test_an_aborted_transaction_takes_its_continuation_with_it(self):
        first, second, _third = self.three()
        payload = assertion_request(self.vault, allow=[first, second])
        self.assertTrue(self.send(payload).startswith(b"\x00"))
        self.dispatcher.policy.abort("cancel")
        self.assertEqual(self.next(), b"\x30")
        self.assertEqual(self.handler._pending, [])

    def test_the_longest_allow_list_that_fits_runs_to_the_end(self):
        # Nine, not the decoder's ten: a credential identifier is at least 78
        # bytes, so ten descriptors plus the rest of the request exceed the
        # 1,024-byte message bound before the list cap is ever reached. The
        # transport is the binding limit here, not the schema.
        allow = [self.vault.hold(marker, user_id=bytes((marker,)))
                 for marker in range(1, 10)]
        response = self.send(assertion_request(self.vault, allow=allow))
        self.assertEqual(response, self.expected(allow[0], b"\x01", count=9))
        self.assertEqual(self.dispatcher.policy.remaining, 8)
        for index in range(1, 9):
            self.assertEqual(self.next(),
                             self.expected(allow[index], bytes((index + 1,))))
        self.assertEqual(self.next(), b"\x30")

    def test_a_list_longer_than_a_continuation_is_cut_to_what_it_can_serve(self):
        # Unreachable over the wire for the reason above, so the locator is
        # driven directly. The policy refuses to reserve more than nine
        # follow-ups, so finding more than ten would turn a reported count into
        # a promise that could not be kept.
        from apps.authenticator.command_types import (
            CredentialDescriptor, GetAssertionRequest,
        )

        allow = tuple(
            CredentialDescriptor(self.vault.hold(marker), ())
            for marker in range(1, 12)
        )
        request = GetAssertionRequest(
            RP_ID, CLIENT_DATA, allow, None, True, False, bytes(32), 2,
        )
        found = self.handler._locate(request, RP_HASH)
        self.assertEqual(len(found), 10)
        self.assertEqual([c.id for c in found], [d.id for d in allow[:10]])

    def test_a_vault_that_refuses_to_sign_is_not_reported_as_a_denial(self):
        identifier = self.vault.hold(1)
        self.vault.credential_sign = lambda *args: (Vault.ERROR, b"")
        payload = assertion_request(self.vault, allow=[identifier])
        self.assertEqual(self.send(payload), b"\x7f")

    # -- wiring ---------------------------------------------------------------
    def test_the_firmware_serves_both_assertion_commands(self):
        dispatcher = default_dispatcher()
        self.assertEqual(sorted(dispatcher._handlers),
                         [1, 2, 4, 6, 7, 8, 10, 11, 65])


if __name__ == "__main__":
    unittest.main()
