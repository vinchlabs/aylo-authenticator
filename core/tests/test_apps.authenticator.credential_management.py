"""Credential management: what it discloses, and what each disclosure costs.

This command exists to answer questions about what the device holds, so most of
these tests are about the price of an answer: a token carrying cm, unbound, plus a
fresh physical edge for every subcommand that begins something. The rest are about
the continuations -- a follow-up rides the first response's authorization, and the
tests say exactly when it stops being allowed.
"""

import asyncio
import hashlib
import importlib.util
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

# Same trap as the assertion suite: under CPython "storage" is the wallet package,
# so the real pass-through module is loaded on its own.
sys.modules["storage"] = types.ModuleType("storage")
_spec = importlib.util.spec_from_file_location(
    "storage.authenticator",
    os.path.join(os.path.dirname(os.path.abspath(__file__)),
                 "..", "src", "storage", "authenticator.py"),
)
_module = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_module)
sys.modules["storage.authenticator"] = _module


from apps.authenticator import credential_management
from apps.authenticator.dispatcher import Dispatcher, default_dispatcher
from apps.authenticator.policy import Policy, TransactionKey
from apps.authenticator.presence import PresenceProvider
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


def cbor_map(items):
    return bytes((0xA0 + len(items),)) + b"".join(k + v for k, v in items)


RP_ID = "example.com"
RP_HASH = hashlib.sha256(RP_ID.encode()).digest()
OTHER_ID = "other.com"
OTHER_HASH = hashlib.sha256(OTHER_ID.encode()).digest()
UNKNOWN_HASH = hashlib.sha256(b"nowhere.example").digest()
COSE_ES256 = bytes.fromhex("a5010203262001215820") + bytes(32) + \
    bytes.fromhex("225820") + bytes(32)

GET_CREDS_METADATA = 1
ENUMERATE_RPS_BEGIN = 2
ENUMERATE_RPS_NEXT = 3
ENUMERATE_CREDENTIALS_BEGIN = 4
ENUMERATE_CREDENTIALS_NEXT = 5
DELETE_CREDENTIAL = 6
UPDATE_USER_INFORMATION = 7

NEXT_RP_PAYLOAD = b"\x0a\xa1\x01\x03"
NEXT_CREDENTIAL_PAYLOAD = b"\x0a\xa1\x01\x05"

RESIDENT_SLOTS = 100


def credential_id(marker):
    return bytes((marker,)) * 78


def metadata(user_id=b"user", rp_id=RP_ID, rp_name="", user_name="", display=""):
    names = (rp_name.encode(), user_name.encode(), display.encode())
    header = bytes((1, 0, 3, len(rp_id) >> 8, len(rp_id) & 0xFF, len(user_id),
                    len(names[0]), len(names[1]), len(names[2])))
    return header + rp_id.encode() + user_id + b"".join(names)


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

    def __init__(self, state=OK, granted=0x04, token=b"t" * 32):
        self.state = state
        self.granted = granted
        self.token = token
        self.calls = []
        self.known = {}
        self.slots = {}
        # The relying party the live token is bound to, if any. The vault refuses
        # a check that names no party while the session is bound to one.
        self.bound = None
        self.deletes_fail = False

    def status(self):
        return (self.state, 8, 0)

    def check_auth(self, protocol, message, param, permissions, rp):
        self.calls.append(("check_auth", permissions, rp, bytes(message)))
        if protocol not in (1, 2) or len(param) != (32 if protocol == 2 else 16):
            raise ValueError("invalid authenticator argument")
        if not 1 <= permissions <= 0x3F:
            raise ValueError("invalid authenticator argument")
        if permissions & ~self.granted:
            return self.DENIED
        if self.bound is not None and rp != self.bound:
            return self.DENIED
        expected = hashlib.sha256(self.token + message).digest()
        width = 32 if protocol == 2 else 16
        return self.OK if param == expected[:width] else self.DENIED

    def resident_get(self, index):
        self.calls.append(("resident_get", index))
        record = self.slots.get(index)
        if record is None:
            return (self.UNPROVISIONED, b"", b"", -7, b"", b"")
        return (self.OK,) + self.known[record]

    def resident_scan(self, rp_hash):
        self.calls.append(("resident_scan", rp_hash))
        occupancy = bytearray(100)
        for index, record in self.slots.items():
            # The filter is the vault's to apply, so the double applies it here
            # rather than letting the caller narrow the answer afterwards.
            if rp_hash is not None and record[1] != rp_hash:
                continue
            occupancy[index] = 1
        return (self.OK, bytes(occupancy))

    def resident_delete(self, index):
        self.calls.append(("resident_delete", index))
        if self.deletes_fail:
            return self.ERROR
        return self.OK if self.slots.pop(index, None) else self.DENIED

    def hold(self, index, marker, user_id=b"user", rp_id=RP_ID, rp_hash=RP_HASH,
             rp_name="", user_name="", display=""):
        identifier = credential_id(marker)
        record = (identifier, rp_hash)
        self.known[record] = (
            identifier, rp_hash, -7,
            metadata(user_id, rp_id, rp_name, user_name, display), COSE_ES256,
        )
        self.slots[index] = record
        return identifier


def mac(vault, protocol, message):
    digest = hashlib.sha256(vault.token + message).digest()
    return digest if protocol == 2 else digest[:16]


def request(vault, subcommand, params=None, protocol=2, param=None):
    """A credential-management request, MAC'd the way CTAP specifies.

    Only the parameter-bearing subcommands put subCommandParams into the MAC
    input, so the message is assembled the same way the decoder assembles it.
    """
    items = [(b"\x01", cbor_uint(subcommand))]
    message = bytes((subcommand,))
    if params is not None:
        items.append((b"\x02", params))
        if subcommand in (4, 6, 7):
            message += params
    if param is None:
        param = mac(vault, protocol, message)
    items.append((b"\x03", cbor_uint(protocol)))
    items.append((b"\x04", cbor_bytes(param)))
    return cbor_map(items)


def rp_params(rp_hash):
    return cbor_map(((b"\x01", cbor_bytes(rp_hash)),))


def credential_params(identifier):
    descriptor = cbor_map(((cbor_text("id"), cbor_bytes(identifier)),
                           (cbor_text("type"), cbor_text("public-key"))))
    return cbor_map(((b"\x02", descriptor),))


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


class CredentialManagementTests(unittest.TestCase):
    def setUp(self):
        self.clock = Clock()
        self.presence = TestPresenceProvider(self.clock.ticks, self.clock.checkpoint)
        self.vault = Vault()
        sys.modules["trezorauth"] = self.vault
        self.dispatcher = Dispatcher()
        self.dispatcher.policy = Policy(self.presence, self.clock.ticks)
        credential_management.register(
            self.dispatcher, self.vault, lambda n: bytes(n)
        )
        self.handler = self.dispatcher._handlers[10].__self__

    def tearDown(self):
        sys.modules.pop("trezorauth", None)

    def send(self, payload, edge=True, generation=GENERATION, cid=CID):
        event = TransportEvent(generation, cid, 0x90, b"\x0a" + payload)
        key = TransactionKey(generation, cid, NONCE)

        async def run():
            task = asyncio.create_task(self.dispatcher.dispatch(event))
            await asyncio.sleep(0)
            if edge:
                self.presence.test_event(key, True)
            return await task

        response = asyncio.run(run())
        self.presence.test_event(key, False)
        return response

    def raw(self, payload, generation=GENERATION, cid=CID):
        """A continuation, which collects no edge and carries no parameters."""
        event = TransportEvent(generation, cid, 0x90, payload)
        return asyncio.run(self.dispatcher.dispatch(event))

    def refusing_dispatcher(self):
        """A device whose presence provider turns every request down."""
        dispatcher = Dispatcher()
        dispatcher.policy = Policy(PresenceProvider(), self.clock.ticks)
        credential_management.register(dispatcher, self.vault, lambda n: bytes(n))
        return dispatcher

    def rp_entry(self, rp_id, rp_hash, name=None, total=None):
        rp = [(cbor_text("id"), cbor_text(rp_id))]
        if name is not None:
            rp.append((cbor_text("name"), cbor_text(name)))
        body = [(b"\x03", cbor_map(rp)), (b"\x04", cbor_bytes(rp_hash))]
        if total is not None:
            body.append((b"\x05", cbor_uint(total)))
        return b"\x00" + cbor_map(body)

    def credential_entry(self, identifier, user_id=b"user", user_name=None,
                         display=None, total=None):
        user = [(cbor_text("id"), cbor_bytes(user_id))]
        if user_name is not None:
            user.append((cbor_text("name"), cbor_text(user_name)))
        if display is not None:
            user.append((cbor_text("displayName"), cbor_text(display)))
        body = [
            (b"\x06", cbor_map(user)),
            (b"\x07", cbor_map(((cbor_text("id"), cbor_bytes(identifier)),
                                (cbor_text("type"), cbor_text("public-key"))))),
            (b"\x08", COSE_ES256),
        ]
        if total is not None:
            body.append((b"\x09", cbor_uint(total)))
        body.append((b"\x0a", cbor_uint(3)))
        return b"\x00" + cbor_map(body)

    # -- what an answer costs -------------------------------------------------
    def test_a_request_with_no_pin_token_is_told_to_get_one(self):
        payload = cbor_map(((b"\x01", cbor_uint(ENUMERATE_RPS_BEGIN)),))
        # The decoder refuses this one before the handler sees it: every
        # subcommand that answers is required to carry a pinUvAuthParam.
        self.assertEqual(self.send(payload, edge=False), b"\x36")
        self.assertEqual(self.vault.calls, [])

    def test_an_unprovisioned_device_says_no_pin_is_set(self):
        self.vault.state = Vault.UNPROVISIONED
        # Reached by handing the handler a request the decoder cannot build, which
        # is the only way to exercise a branch the schema already guarantees.
        from apps.authenticator.cbor_codec import CtapError
        from apps.authenticator.command_types import (
            CommandContext, CredentialManagementRequest,
        )

        bare = CredentialManagementRequest(
            ENUMERATE_RPS_BEGIN, None, None, None, None, None, b"\x02",
        )
        context = CommandContext(GENERATION, CID, 10)
        with self.assertRaises(CtapError) as caught:
            asyncio.run(self.handler.handle(bare, context))
        self.assertEqual(caught.exception.code, 0x35)

    def test_a_request_with_a_protocol_missing_is_a_missing_parameter(self):
        from apps.authenticator.cbor_codec import CtapError
        from apps.authenticator.command_types import (
            CommandContext, CredentialManagementRequest,
        )

        bare = CredentialManagementRequest(
            ENUMERATE_RPS_BEGIN, None, None, None, None, b"p" * 32, b"\x02",
        )
        context = CommandContext(GENERATION, CID, 10)
        with self.assertRaises(CtapError) as caught:
            asyncio.run(self.handler.handle(bare, context))
        self.assertEqual(caught.exception.code, 0x14)

    def test_a_grant_that_does_not_verify_is_the_vault_s_answer(self):
        self.vault.hold(0, 0xA1)
        payload = request(self.vault, ENUMERATE_RPS_BEGIN, param=b"x" * 32)
        self.assertEqual(self.send(payload, edge=False), b"\x33")
        self.assertNotIn(("resident_get", 0), self.vault.calls)

    def test_a_token_without_cm_cannot_manage_anything(self):
        self.vault.granted = 0x02
        self.vault.hold(0, 0xA1)
        payload = request(self.vault, ENUMERATE_RPS_BEGIN)
        self.assertEqual(self.send(payload, edge=False), b"\x33")
        self.assertNotIn(("resident_get", 0), self.vault.calls)

    def test_the_grant_is_checked_for_cm_and_for_no_relying_party(self):
        self.vault.hold(0, 0xA1)
        self.send(request(self.vault, ENUMERATE_RPS_BEGIN))
        checks = [call for call in self.vault.calls if call[0] == "check_auth"]
        self.assertEqual(len(checks), 1)
        self.assertEqual(checks[0][1], 0x04)
        # No relying party, because enumerating them is the point.
        self.assertIsNone(checks[0][2])
        self.assertEqual(checks[0][3], bytes((ENUMERATE_RPS_BEGIN,)))

    def test_the_parameters_are_inside_what_the_grant_covers(self):
        self.vault.hold(0, 0xA1)
        params = rp_params(RP_HASH)
        self.send(request(self.vault, ENUMERATE_CREDENTIALS_BEGIN, params))
        checks = [call for call in self.vault.calls if call[0] == "check_auth"]
        self.assertEqual(
            checks[0][3], bytes((ENUMERATE_CREDENTIALS_BEGIN,)) + params
        )
        # The relying party in the parameters is also the one the grant is checked
        # against. This used to be asserted the other way round, on the grounds
        # that accepting a token bound to the named party would be a way in. It is
        # not: binding narrows a token, and honouring it is how CTAP says to treat
        # one. What would be a way in is accepting a token bound to some other
        # party, which the next test drives.
        self.assertEqual(checks[0][2], RP_HASH)

    def test_a_bound_token_cannot_ask_about_the_whole_device(self):
        # Under a bound token the vault hides every other party's slot, so an
        # answer about the device -- which parties exist, how many slots are in
        # use -- would describe one that is nearly empty. Those subcommands name no
        # party, so a bound token has nothing to be checked against and is refused.
        self.vault.bound = RP_HASH
        self.vault.hold(0, 0xA1)
        for subcommand in (GET_CREDS_METADATA, ENUMERATE_RPS_BEGIN):
            self.setUp()
            self.vault.bound = RP_HASH
            self.vault.hold(0, 0xA1)
            self.assertEqual(
                self.send(request(self.vault, subcommand), edge=False), b"\x33"
            )
            self.assertNotIn(("resident_get", 0), self.vault.calls)

    def test_a_token_bound_to_one_party_may_enumerate_that_party(self):
        # CTAP lets a platform bind a cm token, and libfido2 does: one token to
        # list the parties, then a bound one for each party's credentials. A
        # subcommand that names a party can be checked against the binding, so the
        # token is good for exactly what it was bound for.
        identifier = self.vault.hold(0, 0xA1, user_name="ann", display="Ann")
        self.vault.bound = RP_HASH
        self.assertEqual(
            self.send(request(self.vault, ENUMERATE_CREDENTIALS_BEGIN,
                              rp_params(RP_HASH))),
            self.credential_entry(identifier, user_name="ann", display="Ann",
                                  total=1),
        )

    def test_a_token_bound_to_another_party_is_still_refused(self):
        # The binding is the restriction it claims to be: naming one party in the
        # parameters does not make a token bound to a different one acceptable.
        self.vault.hold(0, 0xA1)
        self.vault.bound = OTHER_HASH
        self.assertEqual(
            self.send(request(self.vault, ENUMERATE_CREDENTIALS_BEGIN,
                              rp_params(RP_HASH)), edge=False),
            b"\x33",
        )
        self.assertNotIn(("resident_get", 0), self.vault.calls)

    def test_a_refused_gesture_discloses_nothing(self):
        self.vault.hold(0, 0xA1)
        dispatcher = self.refusing_dispatcher()
        event = TransportEvent(
            GENERATION, CID, 0x90,
            b"\x0a" + request(self.vault, ENUMERATE_RPS_BEGIN),
        )
        self.assertEqual(asyncio.run(dispatcher.dispatch(event)), b"\x27")
        self.assertNotIn(("resident_get", 0), self.vault.calls)
        self.assertIsNone(dispatcher.policy.key)

    def test_the_grant_is_consumed_before_the_vault_is_read(self):
        self.vault.hold(0, 0xA1)
        order = []
        original = self.dispatcher.policy.take_authorization

        def take(key):
            order.append("take")
            return original(key)

        self.dispatcher.policy.take_authorization = take
        # The vault read that metadata performs is the scan: one authenticated
        # pass, where this used to be a hundred per-slot reads.
        read = self.vault.resident_scan

        def watched(rp_hash):
            order.append("read")
            return read(rp_hash)

        self.vault.resident_scan = watched
        self.send(request(self.vault, GET_CREDS_METADATA))
        self.assertEqual(order[:2], ["take", "read"])

    def test_each_beginning_costs_its_own_gesture(self):
        self.vault.hold(0, 0xA1)
        for _ in range(2):
            self.assertTrue(
                self.send(request(self.vault, GET_CREDS_METADATA)).startswith(b"\x00")
            )
        # A second beginning without a second edge is refused.
        dispatcher = self.refusing_dispatcher()
        event = TransportEvent(
            GENERATION, CID, 0x90,
            b"\x0a" + request(self.vault, GET_CREDS_METADATA),
        )
        self.assertEqual(asyncio.run(dispatcher.dispatch(event)), b"\x27")

    # -- metadata -------------------------------------------------------------
    def test_metadata_counts_the_slots_in_use(self):
        self.vault.hold(0, 0xA1)
        self.vault.hold(7, 0xA2, user_id=b"second")
        self.vault.hold(42, 0xA3, rp_id=OTHER_ID, rp_hash=OTHER_HASH)
        response = self.send(request(self.vault, GET_CREDS_METADATA))
        self.assertEqual(
            response,
            b"\x00" + cbor_map(((b"\x01", cbor_uint(3)),
                                (b"\x02", cbor_uint(RESIDENT_SLOTS - 3)))),
        )

    def test_metadata_on_an_empty_device_offers_every_slot(self):
        response = self.send(request(self.vault, GET_CREDS_METADATA))
        self.assertEqual(
            response,
            b"\x00" + cbor_map(((b"\x01", cbor_uint(0)),
                                (b"\x02", cbor_uint(RESIDENT_SLOTS)))),
        )

    # -- enumerating relying parties -----------------------------------------
    def test_each_relying_party_is_reported_once_however_many_credentials(self):
        self.vault.hold(0, 0xA1)
        self.vault.hold(3, 0xA2, user_id=b"second")
        self.vault.hold(9, 0xA3, rp_id=OTHER_ID, rp_hash=OTHER_HASH)
        self.assertEqual(
            self.send(request(self.vault, ENUMERATE_RPS_BEGIN)),
            self.rp_entry(RP_ID, RP_HASH, total=2),
        )
        self.assertEqual(
            self.raw(NEXT_RP_PAYLOAD), self.rp_entry(OTHER_ID, OTHER_HASH)
        )

    def test_a_relying_party_name_is_reported_when_the_record_holds_one(self):
        self.vault.hold(0, 0xA1, rp_name="Example Inc")
        self.assertEqual(
            self.send(request(self.vault, ENUMERATE_RPS_BEGIN)),
            self.rp_entry(RP_ID, RP_HASH, name="Example Inc", total=1),
        )

    def test_enumerating_relying_parties_on_an_empty_device_has_no_answer(self):
        self.assertEqual(
            self.send(request(self.vault, ENUMERATE_RPS_BEGIN)), b"\x2e"
        )

    def test_a_single_relying_party_leaves_nothing_to_continue(self):
        self.vault.hold(5, 0xA1)
        self.assertEqual(
            self.send(request(self.vault, ENUMERATE_RPS_BEGIN)),
            self.rp_entry(RP_ID, RP_HASH, total=1),
        )
        self.assertEqual(self.raw(NEXT_RP_PAYLOAD), b"\x30")

    # -- enumerating credentials ---------------------------------------------
    def test_credentials_are_reported_only_for_the_party_asked_about(self):
        first = self.vault.hold(0, 0xA1, user_name="ann", display="Ann")
        self.vault.hold(2, 0xB1, rp_id=OTHER_ID, rp_hash=OTHER_HASH)
        second = self.vault.hold(4, 0xA2, user_id=b"second")
        response = self.send(
            request(self.vault, ENUMERATE_CREDENTIALS_BEGIN, rp_params(RP_HASH))
        )
        self.assertEqual(
            response,
            self.credential_entry(first, user_name="ann", display="Ann", total=2),
        )
        self.assertEqual(
            self.raw(NEXT_CREDENTIAL_PAYLOAD),
            self.credential_entry(second, user_id=b"second"),
        )

    def test_the_public_key_is_the_vault_s_own_bytes(self):
        # Spliced in rather than parsed and rebuilt, so nothing between the vault
        # and the platform can change what the key says.
        self.vault.hold(0, 0xA1)
        response = self.send(
            request(self.vault, ENUMERATE_CREDENTIALS_BEGIN, rp_params(RP_HASH))
        )
        # The key map follows its map key directly. Encoded as a byte string it
        # would be preceded by a length header, and a platform reading a COSE key
        # would find a blob instead.
        self.assertIn(b"\x08" + COSE_ES256, response)

    def test_a_party_with_no_credentials_has_no_answer(self):
        self.vault.hold(0, 0xA1)
        self.assertEqual(
            self.send(request(self.vault, ENUMERATE_CREDENTIALS_BEGIN,
                              rp_params(UNKNOWN_HASH))),
            b"\x2e",
        )

    # -- continuations --------------------------------------------------------
    def test_a_follow_up_collects_no_second_gesture(self):
        self.vault.hold(0, 0xA1)
        self.vault.hold(1, 0xA2, rp_id=OTHER_ID, rp_hash=OTHER_HASH)
        self.send(request(self.vault, ENUMERATE_RPS_BEGIN))
        # No edge is offered here at all, and the answer still arrives.
        self.assertEqual(
            self.raw(NEXT_RP_PAYLOAD), self.rp_entry(OTHER_ID, OTHER_HASH)
        )

    def test_a_follow_up_on_another_channel_is_refused_and_ends_it(self):
        self.vault.hold(0, 0xA1)
        self.vault.hold(1, 0xA2, rp_id=OTHER_ID, rp_hash=OTHER_HASH)
        self.send(request(self.vault, ENUMERATE_RPS_BEGIN))
        self.assertEqual(self.raw(NEXT_RP_PAYLOAD, cid=CID + 1), b"\x30")
        # The enumeration is gone, not merely unavailable on that channel.
        self.assertEqual(self.raw(NEXT_RP_PAYLOAD), b"\x30")

    def test_a_credential_follow_up_cannot_drain_a_party_enumeration(self):
        self.vault.hold(0, 0xA1)
        self.vault.hold(1, 0xA2, rp_id=OTHER_ID, rp_hash=OTHER_HASH)
        self.send(request(self.vault, ENUMERATE_RPS_BEGIN))
        self.assertEqual(self.raw(NEXT_CREDENTIAL_PAYLOAD), b"\x30")
        self.assertEqual(self.raw(NEXT_RP_PAYLOAD), b"\x30")

    def test_the_continuation_ends_when_its_count_runs_out(self):
        self.vault.hold(0, 0xA1)
        self.vault.hold(1, 0xA2, rp_id=OTHER_ID, rp_hash=OTHER_HASH)
        self.send(request(self.vault, ENUMERATE_RPS_BEGIN))
        self.assertEqual(
            self.raw(NEXT_RP_PAYLOAD), self.rp_entry(OTHER_ID, OTHER_HASH)
        )
        # It ends with the last answer rather than with the next request.
        # Reserving more follow-ups than are held would leave the transaction
        # alive, holding the channel, with nothing left to say.
        self.assertIsNone(self.dispatcher.policy.key)
        self.assertEqual(self.raw(NEXT_RP_PAYLOAD), b"\x30")

    def test_a_new_beginning_ends_the_outstanding_enumeration(self):
        self.vault.hold(0, 0xA1)
        self.vault.hold(1, 0xA2, rp_id=OTHER_ID, rp_hash=OTHER_HASH)
        self.send(request(self.vault, ENUMERATE_RPS_BEGIN))
        self.assertTrue(
            self.send(request(self.vault, GET_CREDS_METADATA)).startswith(b"\x00")
        )
        self.assertEqual(self.raw(NEXT_RP_PAYLOAD), b"\x30")

    def test_a_follow_up_with_nothing_outstanding_is_not_allowed(self):
        self.assertEqual(self.raw(NEXT_RP_PAYLOAD), b"\x30")
        self.assertEqual(self.raw(NEXT_CREDENTIAL_PAYLOAD), b"\x30")

    # -- deletion -------------------------------------------------------------
    def test_deleting_removes_the_slot_that_holds_the_identifier(self):
        self.vault.hold(0, 0xA1)
        target = self.vault.hold(11, 0xA2, user_id=b"second")
        response = self.send(
            request(self.vault, DELETE_CREDENTIAL, credential_params(target))
        )
        self.assertEqual(response, b"\x00")
        self.assertIn(("resident_delete", 11), self.vault.calls)
        self.assertEqual(sorted(self.vault.slots), [0])

    def test_deleting_something_absent_is_no_credentials(self):
        self.vault.hold(0, 0xA1)
        response = self.send(
            request(self.vault, DELETE_CREDENTIAL,
                    credential_params(credential_id(0xEE)))
        )
        self.assertEqual(response, b"\x2e")
        self.assertNotIn(
            "resident_delete", [call[0] for call in self.vault.calls]
        )

    def test_a_vault_that_will_not_delete_is_not_reported_as_success(self):
        target = self.vault.hold(3, 0xA1)
        self.vault.deletes_fail = True
        response = self.send(
            request(self.vault, DELETE_CREDENTIAL, credential_params(target))
        )
        self.assertEqual(response, b"\x7f")

    # -- what is not implemented ---------------------------------------------
    def test_updating_user_information_is_refused_without_asking_for_anything(self):
        # The metadata is authenticated inside the credential, so the only way to
        # change it is a new credential -- a new key the relying party has never
        # seen. Nobody is asked for a gesture for something that cannot work.
        self.vault.hold(0, 0xA1)
        user = cbor_map(((cbor_text("id"), cbor_bytes(b"user")),))
        params = cbor_map((
            (b"\x02", cbor_map(((cbor_text("id"), cbor_bytes(credential_id(0xA1))),
                                (cbor_text("type"), cbor_text("public-key"))))),
            (b"\x03", user),
        ))
        response = self.send(
            request(self.vault, UPDATE_USER_INFORMATION, params), edge=False
        )
        self.assertEqual(response, b"\x3e")
        self.assertEqual(self.vault.calls, [])
        self.assertIsNone(self.presence.key)

    def test_an_unknown_subcommand_is_refused_by_the_schema(self):
        payload = cbor_map(((b"\x01", cbor_uint(8)),))
        self.assertEqual(self.send(payload, edge=False), b"\x3e")

    # -- wiring ---------------------------------------------------------------
    def test_the_firmware_serves_credential_management(self):
        dispatcher = default_dispatcher()
        self.assertEqual(sorted(dispatcher._handlers),
                         [1, 2, 4, 6, 7, 8, 10, 11, 65])

    def test_the_native_module_is_imported_only_when_a_request_arrives(self):
        handler = credential_management.CredentialManagement(
            Policy(self.presence, self.clock.ticks)
        )
        self.assertIsNone(handler._auth)


if __name__ == "__main__":
    unittest.main()
