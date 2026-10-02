"""makeCredential: authorization order, refusals, and the exact attestation bytes.

The vault is stood in for. What that buys is the ability to check the order in
which authorization happens -- which is the whole security content of this
handler -- and to assert the attestation object byte for byte. The real vault's
credential creation is exercised against the real thing in
core/tests/test_trezorauth_credentials.py.
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
# credential.py reaches for trezor.crypto, which on the device is the flat shim
# in core/src/authenticator_frozen/trezor/crypto.py. Under CPython the name
# resolves to the wallet package instead, which pulls in trezorconfig, so the
# shim is reproduced here rather than imported.
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


from apps.authenticator import make_credential
from apps.authenticator.dispatcher import Dispatcher, default_dispatcher
from apps.authenticator.policy import Policy, TransactionKey
from apps.authenticator import protocol
from apps.authenticator.protocol import AAGUID
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
    if len(value) < 256:
        return b"\x78" + bytes((len(value),)) + value
    return b"\x79" + len(value).to_bytes(2, "big") + value


def cbor_array(items):
    return bytes((0x80 + len(items),)) + b"".join(items)


def cbor_map(items):
    return bytes((0xA0 + len(items),)) + b"".join(k + v for k, v in items)


RP_ID = "example.com"
RP_HASH = hashlib.sha256(RP_ID.encode()).digest()
CLIENT_DATA = bytes(range(32))
USER_ID = b"user-handle"
COSE_ES256 = bytes.fromhex("a5010203262001215820") + bytes(32) + \
    bytes.fromhex("225820") + bytes(32)
CRED_ID = bytes(range(78))
OTHER_HASH = hashlib.sha256(b"other.test").digest()
OLD_ID = b"old" + bytes(75)


def metadata(user_id=USER_ID, rp_id=RP_ID):
    """An authenticated resident record's public metadata, version 1."""
    return (bytes((1, 0, 3, len(rp_id) >> 8, len(rp_id) & 0xFF,
                   len(user_id), 0, 0, 0))
            + rp_id.encode() + user_id)


class Vault:
    """The calls makeCredential makes, and nothing else."""

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
    STORE_FULL = 11
    MIN_PIN_CODE_POINTS = 8
    # One past the last slot: store this wherever there is room.
    ANY_SLOT = 100

    def __init__(self, state=OK, granted=0x03, token=b"t" * 32):
        self.state = state
        self.granted = granted
        self.token = token
        self.calls = []
        self.created = []
        self.known = {}
        self.slots = {}
        self.bound = None
        self.oversized = False
        # The real vault invalidates its session on any result that is not OK, so
        # a second request is refused for that reason whatever it asks for. Off by
        # default, because most tests here are about one request.
        self.invalidate_on_refusal = False
        self.refused = False

    def status(self):
        return (self.state, 8, 0)

    def check_auth(self, protocol, message, param, permissions, rp):
        self.calls.append(("check_auth", protocol, message, param, permissions, rp))
        if protocol not in (1, 2):
            raise ValueError("invalid authenticator argument")
        if len(param) != (32 if protocol == 2 else 16):
            raise ValueError("invalid authenticator argument")
        if not 1 <= permissions <= 0x3F:
            raise ValueError("invalid authenticator argument")
        if rp is not None and len(rp) != 32:
            raise ValueError("invalid authenticator argument")
        if permissions & ~self.granted:
            return self.DENIED
        expected = hashlib.sha256(self.token + message).digest()
        width = 32 if protocol == 2 else 16
        return self.OK if param == expected[:width] else self.DENIED

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
        held = self.known.get((identifier, rp_hash))
        if held is None:
            # A record this vault cannot authenticate is a record it does not
            # have, which is how the real one answers too.
            return (self.UNPROVISIONED, b"", b"", -7, b"", b"")
        return (self.OK,) + held

    def account(self, metadata):
        """The user handle inside a record's metadata: CTAP's account ID."""
        rp_len = (metadata[3] << 8) | metadata[4]
        return metadata[9 + rp_len:9 + rp_len + metadata[5]]

    def hold(self, index, identifier=OLD_ID, user_id=USER_ID, rp_hash=RP_HASH,
             rp_id=RP_ID):
        """Seed one occupied slot with a record that can actually be read."""
        self.known[(identifier, rp_hash)] = (
            identifier, rp_hash, -7, metadata(user_id, rp_id), COSE_ES256,
        )
        self.slots[index] = (identifier, rp_hash)
        return identifier

    def resident_set(self, index, identifier, rp_hash):
        self.calls.append(("resident_set", index))
        if self.invalidate_on_refusal and self.refused:
            # Nothing is authorized any more; the slot named does not matter.
            return self.DENIED
        answer = self._resident_set(index, identifier, rp_hash)
        if answer != self.OK:
            self.refused = True
        return answer

    def _resident_set(self, index, identifier, rp_hash):
        if self.oversized:
            return self.LIMIT_EXCEEDED
        if index == self.ANY_SLOT:
            # The vault chooses, which is the whole point of the sentinel: it is
            # the only party that can see every slot. Choosing includes replacing
            # this party's record for this account, which costs no free slot.
            record = self.known.get((identifier, rp_hash))
            account = self.account(record[3]) if record else None
            for candidate in sorted(self.slots):
                held_id, held_rp = self.slots[candidate]
                held = self.known.get((held_id, held_rp))
                if (
                    held_rp == rp_hash and held is not None
                    and account is not None and self.account(held[3]) == account
                ):
                    self.slots[candidate] = (identifier, rp_hash)
                    return self.OK
            for candidate in range(100):
                if candidate not in self.slots:
                    self.slots[candidate] = (identifier, rp_hash)
                    return self.OK
            return self.STORE_FULL
        if index in self.slots:
            # The vault refuses to overwrite an occupied slot.
            return self.DENIED
        self.slots[index] = (identifier, rp_hash)
        return self.OK

    def resident_delete(self, index):
        self.calls.append(("resident_delete", index))
        return self.OK if self.slots.pop(index, None) else self.DENIED

    def credential_create(self, rp_hash, algorithm, metadata):
        self.calls.append(("credential_create", rp_hash, algorithm, metadata))
        self.created.append((rp_hash, algorithm, metadata))
        cose = COSE_ES256 if algorithm == -7 else bytes.fromhex(
            "a4010103272006215820"
        ) + bytes(32)
        # An envelope carries its own metadata, so a record written from this
        # identifier reads back with it. The double has to remember that much to
        # answer which account a slot holds.
        self.known[(CRED_ID, rp_hash)] = (
            CRED_ID, rp_hash, algorithm, metadata, cose,
        )
        return (self.OK, CRED_ID, rp_hash, algorithm, metadata, cose)

    def credential_attest(self, identifier, rp_hash, algorithm, message):
        self.calls.append(("credential_attest", algorithm, message))
        if not 1 <= len(message) <= 1024:
            raise ValueError("invalid authenticator argument")
        return (self.OK, hashlib.sha256(identifier + message).digest()[:64])

    def credential_open(self, identifier, rp_hash):
        self.calls.append(("credential_open", identifier, rp_hash))
        record = self.known.get((identifier, rp_hash))
        if record is None:
            return (self.DENIED, b"", b"", -7, b"", b"")
        return (self.OK,) + record


def mac(vault, protocol, message):
    digest = hashlib.sha256(vault.token + message).digest()
    return digest if protocol == 2 else digest[:16]


def make_request(vault, protocol=2, rp_id=RP_ID, rp_name=None, user_id=USER_ID,
                 user_name=None, display_name=None, algorithm=-7,
                 exclude=None, extensions=None, options=None, param=None,
                 client_data=CLIENT_DATA):
    # Canonical CBOR sorts map keys by their encoded bytes, so "id" precedes
    # "name" precedes "displayName"; the decoder rejects any other order.
    user_fields = [(cbor_text("id"), cbor_bytes(user_id))]
    if user_name is not None:
        user_fields.append((cbor_text("name"), cbor_text(user_name)))
    if display_name is not None:
        user_fields.append((cbor_text("displayName"), cbor_text(display_name)))
    rp_fields = [(cbor_text("id"), cbor_text(rp_id))]
    if rp_name is not None:
        rp_fields.append((cbor_text("name"), cbor_text(rp_name)))
    algorithms = cbor_array((cbor_map((
        (cbor_text("alg"), b"\x26" if algorithm == -7 else b"\x27"),
        (cbor_text("type"), cbor_text("public-key")),
    )),))
    items = [
        (b"\x01", cbor_bytes(client_data)),
        (b"\x02", cbor_map(rp_fields)),
        (b"\x03", cbor_map(user_fields)),
        (b"\x04", algorithms),
    ]
    if exclude is not None:
        items.append((b"\x05", cbor_array(tuple(
            cbor_map(((cbor_text("id"), cbor_bytes(identifier)),
                      (cbor_text("type"), cbor_text("public-key"))))
            for identifier in exclude
        ))))
    if extensions is not None:
        items.append((b"\x06", extensions))
    if options is not None:
        items.append((b"\x07", options))
    if param is None:
        param = mac(vault, protocol, client_data)
    if param is not False:
        items.append((b"\x08", cbor_bytes(param)))
        items.append((b"\x09", cbor_uint(protocol)))
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


class MakeCredentialTests(unittest.TestCase):
    def setUp(self):
        self.clock = Clock()
        self.presence = TestPresenceProvider(self.clock.ticks, self.clock.checkpoint)
        self.vault = Vault()
        # credential.py imports the native module by name rather than taking one,
        # so the double has to stand in as that module and not only be handed to
        # the handler. Both references are the same object, which is the point:
        # the handler and the credential layer must talk to one vault.
        sys.modules["trezorauth"] = self.vault
        self.dispatcher = Dispatcher()
        self.dispatcher.policy = Policy(self.presence, self.clock.ticks)
        make_credential.register(self.dispatcher, self.vault, lambda n: bytes(n))

    def tearDown(self):
        sys.modules.pop("trezorauth", None)

    def send(self, payload, edge=True, at=None):
        event = TransportEvent(GENERATION, CID, 0x90, b"\x01" + payload)
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
        self.presence.test_event(key, False)
        return response

    # -- the attestation object ----------------------------------------------
    def expected(self, cose=COSE_ES256, extensions=b"", flags=0x45, alg=-7):
        attested = AAGUID + len(CRED_ID).to_bytes(2, "big") + CRED_ID + cose
        data = RP_HASH + bytes((flags,)) + bytes(4) + attested + extensions
        # Self attestation: the credential signs authenticatorData and the client
        # data hash, which is the same thing an assertion signs. Canonical CBOR
        # sorts the statement's keys, so "alg" precedes "sig".
        statement = (b"\xa2" + cbor_text("alg")
                     + (b"\x26" if alg == -7 else b"\x27")
                     + cbor_text("sig")
                     + cbor_bytes(hashlib.sha256(
                         CRED_ID + data + CLIENT_DATA).digest()[:64]))
        return (b"\x00\xa3\x01" + cbor_text("packed") + b"\x02"
                + cbor_bytes(data) + b"\x03" + statement)

    def test_the_attestation_is_the_credential_signing_for_itself(self):
        # A platform that cannot verify an enrollment has no reason to trust it,
        # and one of them refuses outright: OpenSSH calls fido_cred_verify_self.
        # So the statement is "packed" with a signature by the credential's own
        # key, over authenticatorData and the client data hash -- the same bytes
        # an assertion covers.
        response = self.send(make_request(self.vault))
        self.assertEqual(response, self.expected())
        attested = [c for c in self.vault.calls if c[0] == "credential_attest"]
        self.assertEqual(len(attested), 1)
        self.assertEqual(attested[0][1], -7)
        at = response.index(RP_HASH)
        signed = attested[0][2]
        self.assertTrue(signed.startswith(RP_HASH))
        self.assertTrue(signed.endswith(CLIENT_DATA))
        self.assertNotIn("credential_sign", [c[0] for c in self.vault.calls])

    def test_a_vault_that_refuses_to_attest_is_not_reported_as_a_denial(self):
        self.vault.credential_attest = lambda *args: (Vault.ERROR, b"")
        self.assertEqual(self.send(make_request(self.vault)), b"\x7f")

    def test_creates_a_credential_and_attests_to_it(self):
        for protocol in (2, 1):
            self.setUp()
            payload = make_request(self.vault, protocol)
            self.assertEqual(self.send(payload), self.expected())
            rp_hash, algorithm, metadata = self.vault.created[0]
            self.assertEqual(rp_hash, RP_HASH)
            self.assertEqual(algorithm, -7)
            self.assertEqual(metadata[:3], b"\x01\x00\x03")
            self.assertEqual(metadata[9:9 + len(RP_ID)], RP_ID.encode())
            self.assertIsNone(self.dispatcher.policy.key)

    def test_the_signature_counter_is_zero_and_says_so(self):
        response = self.send(make_request(self.vault))
        # Located by the RP hash that opens authenticatorData rather than by a
        # computed offset, so the assertion does not restate the encoding.
        at = response.index(RP_HASH)
        self.assertEqual(response[at + 32], 0x01 | 0x04 | 0x40)
        self.assertEqual(response[at + 33:at + 37], bytes(4))

    def test_ed25519_is_created_when_the_party_asks_for_it(self):
        payload = make_request(self.vault, algorithm=-8)
        cose = bytes.fromhex("a4010103272006215820") + bytes(32)
        # The statement names the credential's algorithm, not the device's
        # preference, so an Ed25519 credential attests with Ed25519.
        self.assertEqual(self.send(payload),
                         self.expected(cose=cose, alg=-8))
        self.assertEqual(self.vault.created[0][1], -8)

    def test_only_an_advertised_extension_is_echoed(self):
        # credProtect is offered in GetInfo and is echoed. hmac-secret is not
        # offered, because the salts arrive encrypted under the shared secret and
        # nothing outside the vault can open them -- so it must not be echoed
        # either. Authenticator data is the one place CTAP gives for saying "this
        # credential has an hmac-secret", and saying it would be a promise that
        # every later assertion breaks, silently, by producing no output.
        extensions = cbor_map((
            (cbor_text("credProtect"), b"\x03"),
            (cbor_text("hmac-secret"), b"\xf5"),
        ))
        payload = make_request(self.vault, extensions=extensions)
        echoed = cbor_map(((cbor_text("credProtect"), b"\x03"),))
        self.assertEqual(self.send(payload),
                         self.expected(extensions=echoed, flags=0xC5))
        # The record still reserves the bit. Nothing reads it, and keeping it means
        # the extension can be implemented later without a record-format change.
        self.assertEqual(self.vault.created[0][2][1], 1)

    def test_a_request_for_only_hmac_secret_gets_no_extension_data(self):
        # Asking for an unsupported extension is not an error -- CTAP says an
        # authenticator ignores what it does not support. Ignoring it means no
        # extension map and no extension-data flag, not an empty map.
        extensions = cbor_map(((cbor_text("hmac-secret"), b"\xf5"),))
        payload = make_request(self.vault, extensions=extensions)
        self.assertEqual(self.send(payload), self.expected(flags=0x45))

    def test_every_echoed_extension_name_is_one_get_info_offers(self):
        from apps.authenticator import get_info

        extensions = cbor_map((
            (cbor_text("credProtect"), b"\x03"),
            (cbor_text("hmac-secret"), b"\xf5"),
        ))
        response = self.send(make_request(self.vault, extensions=extensions))
        offered = get_info.response(self.vault)[get_info.EXTENSIONS]
        for name in (b"credProtect", b"hmac-secret"):
            if name in response:
                self.assertIn(name.decode(), offered)

    # -- authorization order --------------------------------------------------
    def test_no_pin_auth_param_is_refused_without_creating_anything(self):
        self.assertEqual(self.send(make_request(self.vault, param=False)), b"\x36")
        self.vault.state = Vault.UNPROVISIONED
        self.assertEqual(self.send(make_request(self.vault, param=False)), b"\x35")
        self.assertEqual(self.vault.created, [])

    def test_the_selection_probe_answers_whether_a_pin_exists(self):
        self.assertEqual(self.send(make_request(self.vault, param=b"")), b"\x31")
        self.vault.state = Vault.UNPROVISIONED
        self.assertEqual(self.send(make_request(self.vault, param=b"")), b"\x35")
        self.assertEqual(self.vault.calls, [])

    def test_a_forged_pin_auth_param_never_reaches_presence(self):
        payload = make_request(self.vault, param=bytes(32))
        self.assertEqual(self.send(payload, edge=False), b"\x33")
        self.assertIsNone(self.presence.key)
        self.assertEqual(self.vault.created, [])

    def test_a_token_without_the_make_credential_bit_is_refused(self):
        self.vault.granted = 0x02
        self.assertEqual(self.send(make_request(self.vault)), b"\x33")
        self.assertEqual(self.vault.created, [])

    def test_presence_is_required_and_its_absence_creates_nothing(self):
        payload = make_request(self.vault)
        self.assertEqual(self.send(payload, edge=False, at=30000), b"\x27")
        self.assertEqual(self.vault.created, [])
        self.assertIsNone(self.dispatcher.policy.key)

    def test_the_grant_is_consumed_before_the_credential_is_made(self):
        order = []
        original = self.dispatcher.policy.take_authorization

        def take(key):
            order.append("take")
            return original(key)

        self.dispatcher.policy.take_authorization = take
        create = self.vault.credential_create

        def created(*args):
            order.append("create")
            return create(*args)

        self.vault.credential_create = created
        self.assertTrue(self.send(make_request(self.vault)).startswith(b"\x00"))
        self.assertEqual(order, ["take", "create"])

    # -- the exclude list -----------------------------------------------------
    def test_a_credential_this_device_holds_is_excluded(self):
        metadata = bytes((1, 0, 3, 0, len(RP_ID), 0, 0, 0, 0)) + RP_ID.encode()
        self.vault.known[(CRED_ID, RP_HASH)] = (
            CRED_ID, RP_HASH, -7, metadata, COSE_ES256,
        )
        payload = make_request(self.vault, exclude=[CRED_ID])
        self.assertEqual(self.send(payload), b"\x19")
        self.assertEqual(self.vault.created, [])

    def test_an_unknown_exclude_entry_does_not_stop_creation(self):
        payload = make_request(self.vault, exclude=[bytes(80), bytes(90)])
        self.assertEqual(self.send(payload), self.expected())

    def test_an_exclude_list_needs_a_token_that_can_read_credentials(self):
        # Without the ga bit every exclusion would look like "not mine", so the
        # request is refused rather than answered from a blind spot.
        self.vault.granted = 0x01
        payload = make_request(self.vault, exclude=[CRED_ID])
        self.assertEqual(self.send(payload), b"\x36")
        self.assertEqual(self.vault.created, [])
        # With no exclude list the same token is enough.
        self.assertEqual(self.send(make_request(self.vault)), self.expected())

    def test_the_exclude_list_is_read_only_after_presence(self):
        metadata = bytes((1, 0, 3, 0, len(RP_ID), 0, 0, 0, 0)) + RP_ID.encode()
        self.vault.known[(CRED_ID, RP_HASH)] = (
            CRED_ID, RP_HASH, -7, metadata, COSE_ES256,
        )
        payload = make_request(self.vault, exclude=[CRED_ID])
        self.assertEqual(self.send(payload, edge=False, at=30000), b"\x27")
        self.assertNotIn("credential_open", [call[0] for call in self.vault.calls])

    # -- what the record cannot hold -----------------------------------------
    def test_oversized_names_are_cut_on_a_code_point_boundary(self):
        # Three-byte characters do not divide the 100-byte limit, so the cut
        # lands inside one and has to back off; two-byte characters would align
        # and prove nothing.
        payload = make_request(self.vault, rp_name="r" * 300,
                               user_name="\u20ac" * 80, display_name="d" * 150)
        self.assertTrue(self.send(payload).startswith(b"\x00"))
        metadata = self.vault.created[0][2]
        rp_len = (metadata[3] << 8) | metadata[4]
        self.assertEqual(metadata[6], 100)
        self.assertEqual(metadata[7], 99)
        at = 9 + rp_len + metadata[5] + metadata[6]
        self.assertEqual(metadata[at:at + 99].decode(), "\u20ac" * 33)
        self.assertEqual(metadata[8], 100)

    def test_a_relying_party_id_the_record_cannot_hold_is_refused(self):
        payload = make_request(self.vault, rp_id="x" * 254)
        self.assertEqual(self.send(payload), b"\x39")
        self.assertEqual(self.vault.created, [])

    def discoverable(self):
        return make_request(self.vault,
                            options=cbor_map(((cbor_text("rk"), b"\xf5"),)))

    def test_a_discoverable_credential_goes_wherever_the_vault_has_room(self):
        """The vault chooses the slot, and is asked exactly once.

        This used to assert a search -- slot zero, then one, then two -- and that
        contract was impossible on the device. The vault invalidates its session on
        any refusal, so the second attempt of a search is refused for that reason
        rather than for the slot. A browser found it; this suite could not, because
        the double answered every attempt as though the first had not happened.
        """
        self.vault.slots[0] = (b"someone else", bytes(32))
        self.vault.slots[1] = (b"someone else", bytes(32))
        self.assertEqual(self.send(self.discoverable()), self.expected())
        self.assertEqual([c for c in self.vault.calls if c[0] == "resident_set"],
                         [("resident_set", 100)])
        self.assertEqual(self.vault.slots[2], (CRED_ID, RP_HASH))

    def test_another_partys_credential_does_not_make_the_store_look_full(self):
        """The defect itself, with the invalidation the device really performs.

        One credential belonging to somebody else used to be enough to make every
        further registration fail as KEY_STORE_FULL, on a device with ninety-nine
        free slots. Asking once is what fixes it, so asking once is what is
        asserted.
        """
        self.vault.invalidate_on_refusal = True
        self.vault.slots[0] = (b"someone else", bytes(32))
        self.assertEqual(self.send(self.discoverable()), self.expected())
        self.assertEqual([c for c in self.vault.calls if c[0] == "resident_set"],
                         [("resident_set", 100)])
        self.assertEqual(self.vault.slots[1], (CRED_ID, RP_HASH))

    # -- registering an account that is already here --------------------------
    def test_re_registering_an_account_replaces_its_record_in_place(self):
        # CTAP: a credential for an rp and account that both already exist
        # replaces the old one. Two records for one account would be two entries
        # in a platform's picker that nothing could tell apart. The slot does not
        # move, and nothing is deleted: one commit puts the new record where the
        # old one was, so the account is never for a moment without one.
        self.vault.hold(4)
        self.assertEqual(self.send(self.discoverable()), self.expected())
        self.assertEqual(self.vault.slots, {4: (CRED_ID, RP_HASH)})
        self.assertEqual([c for c in self.vault.calls if c[0] == "resident_set"],
                         [("resident_set", 100)])
        self.assertNotIn("resident_delete", [c[0] for c in self.vault.calls])

    def test_a_replacement_needs_no_free_slot(self):
        # Every slot occupied, one of them this account's. A replacement asks for
        # no room, so it must not be refused for want of any.
        for index in range(100):
            self.vault.slots[index] = (b"someone else", bytes(32))
        self.vault.hold(7)
        self.assertEqual(self.send(self.discoverable()), self.expected())
        self.assertEqual(self.vault.slots[7], (CRED_ID, RP_HASH))
        self.assertEqual(len(self.vault.slots), 100)

    def test_another_account_on_the_same_party_is_added_not_replaced(self):
        self.vault.hold(4, user_id=b"somebody else")
        self.assertEqual(self.send(self.discoverable()), self.expected())
        self.assertEqual(self.vault.slots[4], (OLD_ID, RP_HASH))
        self.assertEqual(self.vault.slots[0], (CRED_ID, RP_HASH))

    def test_the_same_account_on_another_party_is_left_alone(self):
        self.vault.hold(4, rp_hash=OTHER_HASH, rp_id="other.test")
        self.assertEqual(self.send(self.discoverable()), self.expected())
        self.assertEqual(self.vault.slots[4], (OLD_ID, OTHER_HASH))
        self.assertEqual(self.vault.slots[0], (CRED_ID, RP_HASH))

    def test_a_credential_is_stored_only_when_it_was_asked_for(self):
        self.assertEqual(self.send(make_request(self.vault)), self.expected())
        self.assertNotIn("resident_set", [c[0] for c in self.vault.calls])

    def test_a_full_store_is_reported_as_full(self):
        """Full is its own answer, told apart from a record that will not fit.

        A platform can act on REQUEST_TOO_LARGE by sending less metadata and can do
        nothing about KEY_STORE_FULL, so the vault reports them separately rather
        than letting a hundred denials add up to one of them.
        """
        for index in range(100):
            self.vault.slots[index] = (b"someone else", bytes(32))
        self.assertEqual(self.send(self.discoverable()), b"\x28")
        self.assertEqual(
            len([c for c in self.vault.calls if c[0] == "resident_set"]), 1
        )

    def test_a_refusal_that_is_not_about_room_is_not_reported_as_room(self):
        # A duplicate identifier, or an authorization that no longer holds. Neither
        # is something a platform can fix by asking for less, so neither may look
        # like a full store.
        self.vault.resident_set = lambda index, identifier, rp_hash: Vault.DENIED
        self.assertEqual(self.send(self.discoverable()), b"\x7f")

    def test_a_record_the_resident_format_cannot_hold_is_not_retried(self):
        self.vault.oversized = True
        self.assertEqual(self.send(self.discoverable()), b"\x39")
        # One attempt: every other slot would answer the same way.
        self.assertEqual(
            len([c for c in self.vault.calls if c[0] == "resident_set"]), 1
        )

    def test_a_vault_that_refuses_to_create_is_not_reported_as_a_denial(self):
        self.vault.credential_create = lambda *args: (
            Vault.ERROR, b"", b"", -7, b"", b"",
        )
        self.assertEqual(self.send(make_request(self.vault)), b"\x7f")

    # -- wiring ---------------------------------------------------------------
    def test_the_firmware_serves_make_credential(self):
        dispatcher = default_dispatcher()
        self.assertEqual(sorted(dispatcher._handlers),
                         [1, 2, 4, 6, 7, 8, 10, 11, 65])


class AuthenticatorDataTests(unittest.TestCase):
    """The shared assembler, tested directly.

    getAssertion will call the same function without attested credential data,
    so the rule that the flags and the payload agree is what stops a response
    that says "a credential follows" when none does. Nothing else can catch
    that: both halves would still be well-formed CBOR.
    """

    def test_composes_at_the_documented_offsets(self):
        data = protocol.authenticator_data(RP_HASH, 0x01)
        self.assertEqual(len(data), 37)
        self.assertEqual(data[:32], RP_HASH)
        self.assertEqual(data[32], 0x01)
        self.assertEqual(data[33:37], bytes(4))

    def test_rejects_a_hash_that_is_not_a_hash(self):
        for bad in (bytes(31), bytes(33), b"", bytearray(32)):
            with self.assertRaises(ValueError):
                protocol.authenticator_data(bad, 0x01)

    def test_flags_and_payload_must_agree(self):
        attested = protocol.AAGUID + b"\x00\x01" + b"x" + COSE_ES256
        with self.assertRaises(ValueError):
            protocol.authenticator_data(RP_HASH, 0x41)
        with self.assertRaises(ValueError):
            protocol.authenticator_data(RP_HASH, 0x01, attested)
        with self.assertRaises(ValueError):
            protocol.authenticator_data(RP_HASH, 0x81)
        with self.assertRaises(ValueError):
            protocol.authenticator_data(RP_HASH, 0x01, b"", b"\xa0")
        # Both declared and both present is the only accepted combination.
        self.assertTrue(
            protocol.authenticator_data(RP_HASH, 0xC1, attested, b"\xa0")
        )

    def test_the_credential_id_is_length_prefixed_and_the_key_is_verbatim(self):
        class Fake:
            id = CRED_ID

            def public_key(self):
                return COSE_ES256

        data = protocol.attested_credential_data(Fake())
        self.assertEqual(data[:16], protocol.AAGUID)
        self.assertEqual(data[16:18], len(CRED_ID).to_bytes(2, "big"))
        self.assertEqual(data[18:18 + len(CRED_ID)], CRED_ID)
        self.assertEqual(data[18 + len(CRED_ID):], COSE_ES256)

    def test_an_unusable_credential_id_is_refused(self):
        for bad in (b"", bytearray(78), "identifier", bytes(0x10000)):
            class Fake:
                id = bad

                def public_key(self):
                    return COSE_ES256

            with self.assertRaises(ValueError):
                protocol.attested_credential_data(Fake())


if __name__ == "__main__":
    unittest.main()
