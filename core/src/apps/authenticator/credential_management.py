"""CTAP authenticatorCredentialManagement.

This is the one command whose whole purpose is to answer questions about what the
device holds, so every subcommand that answers costs a PIN token carrying cm and a
fresh physical edge. The enumeration is not a secret from the person holding the
device; it is a secret from software that happens to be talking to it.

A cm permission may name a relying party, and the vault honours that by hiding
every other party's slot. That makes the binding useful for a subcommand that asks
about one party and wrong for a subcommand that asks about the device: bound,
enumerateRPs would report one party and a device that looks nearly empty.

So the grant is checked against whichever party the subcommand itself names, and
against none when it names none. enumerateCredentials names one, and libfido2 binds
its token to exactly that one -- which is how a resident key came to be unreadable
from OpenSSH on Linux, refused as PIN_AUTH_INVALID by a check that passed nothing.
getCredsMetadata and enumerateRPs name none, pass none, and so still refuse a bound
token. Either way the comparison is the vault's, against a hash the MAC covers, so
a token bound to some other party is refused wherever it is presented.

Continuations work the way GetNextAssertion's does: the first response is paid for
with an edge and reserves the follow-ups, and each follow-up rides that same
authorization. What is held between responses is a list of slot numbers rather
than the records themselves -- a hundred unwrapped credentials would be tens of
kilobytes of heap, and nothing else can run on the channel while a continuation is
outstanding, so re-reading one slot per follow-up costs a vault call and keeps the
answer current.

updateUserInformation is refused, and it is not a gap that can be closed later at
this layer. A credential's name and display name are authenticated inside the
credential itself, and the only way to produce a record with different metadata is
to create a new credential -- which means a new key, which the relying party has
never seen. Rewriting the metadata in place is not something the vault offers,
because the vault is what guarantees the metadata was not rewritten.
"""

from .cbor_codec import CtapError, RawCbor
from .client_pin import CREDENTIAL_MANAGEMENT, translate
from .credential import CredentialUnavailable
from .policy import PolicyError, TransactionKey
from .resident_store import ResidentStore

COMMAND = 10
# The number CTAP 2.1-PRE gave this command, which libfido2 1.10 is the reason to
# answer: it sends this one and never 0x0A.
PREVIEW_COMMAND = 0x41

GET_CREDS_METADATA = 0x01
ENUMERATE_RPS_BEGIN = 0x02
ENUMERATE_RPS_NEXT = 0x03
ENUMERATE_CREDENTIALS_BEGIN = 0x04
ENUMERATE_CREDENTIALS_NEXT = 0x05
DELETE_CREDENTIAL = 0x06
UPDATE_USER_INFORMATION = 0x07

# Response map keys.
EXISTING_COUNT = 0x01
REMAINING_COUNT = 0x02
RP = 0x03
RP_ID_HASH = 0x04
TOTAL_RPS = 0x05
USER = 0x06
CREDENTIAL_ID = 0x07
PUBLIC_KEY = 0x08
TOTAL_CREDENTIALS = 0x09
CRED_PROTECT = 0x0A

MISSING_PARAMETER = 0x14
OPERATION_DENIED = 0x27
NO_CREDENTIALS = 0x2E
NOT_ALLOWED = 0x30
PIN_NOT_SET = 0x35
PUAT_REQUIRED = 0x36
INVALID_SUBCOMMAND = 0x3E
OTHER = 0x7F

# The vault has a hundred numbered slots for discoverable credentials.
RESIDENT_SLOTS = 100

PRESENCE_TIMEOUT_MS = 30000


class CredentialManagement:
    """Owns the slots an outstanding enumeration still has to report."""

    def __init__(self, policy, auth=None, random_bytes=None) -> None:
        self.policy = policy
        self._auth = auth
        self._random_bytes = random_bytes
        self._forget()

    def _forget(self) -> None:
        self._key = None
        self._pending = []
        self._continues = None

    def _vault(self):
        auth = self._auth
        if auth is None:
            import trezorauth

            auth = self._auth = trezorauth
        return auth

    def _nonce(self) -> bytes:
        if self._random_bytes is not None:
            return self._random_bytes(32)
        from trezorcrypto import random

        return random.bytes(32)

    async def handle(self, request, context):
        subcommand = request.subcommand
        if subcommand in (ENUMERATE_RPS_NEXT, ENUMERATE_CREDENTIALS_NEXT):
            return self._next(subcommand)
        # Anything else ends whatever enumeration was outstanding. The dispatcher
        # has already aborted the policy; this drops the slot numbers that went
        # with it so a later follow-up cannot find them lying around.
        self._forget()
        if subcommand == UPDATE_USER_INFORMATION:
            # Refused before a gesture is asked for: there is no edge a person
            # could give that would make this work, so charging one would be a
            # request for nothing. CTAP2_ERR_INVALID_SUBCOMMAND is the code the
            # specification gives for a subcommand that is not implemented.
            raise CtapError(INVALID_SUBCOMMAND)
        key = await self._authorize(request, context)
        if subcommand == GET_CREDS_METADATA:
            return self._metadata()
        if subcommand == ENUMERATE_RPS_BEGIN:
            return self._begin_rps(key)
        if subcommand == ENUMERATE_CREDENTIALS_BEGIN:
            return self._begin_credentials(key, request.rp_id_hash)
        return self._delete(request.credential)

    async def _authorize(self, request, context):
        """One PIN grant carrying cm, and one fresh edge, for this subcommand."""
        auth = self._vault()
        param = request.pin_uv_auth_param
        protocol = request.pin_uv_auth_protocol
        if param is None:
            state, _retries, _consecutive = auth.status()
            raise CtapError(PUAT_REQUIRED if state == auth.OK else PIN_NOT_SET)
        if protocol is None:
            raise CtapError(MISSING_PARAMETER)

        key = TransactionKey(
            context.connection_generation, context.cid, self._nonce()
        )
        # The transaction is not scoped to a relying party: credential management
        # is a question about the device, and one enumeration may walk several
        # parties. The token is a different matter.
        #
        # CTAP lets a platform bind a cm token to one party, and libfido2 does it:
        # one token to enumerate the parties, then a bound one for each party's
        # credentials. The vault then requires every grant check to name that
        # party, so passing nothing refused a perfectly good token as
        # PIN_AUTH_INVALID -- which is what made a resident key unreadable from
        # OpenSSH on Linux.
        #
        # So the check names whichever party this subcommand itself names, and
        # nothing when it names none. That narrows rather than widens: a token
        # bound to another party still fails, because the vault compares its
        # binding against the hash passed here, and the hash is inside what the MAC
        # covers so it cannot be substituted. The subcommands that answer about the
        # whole device -- how many slots are in use, which parties exist -- still
        # pass nothing and still refuse a bound token, because under one the vault
        # hides every other party's slot and the answer would describe a device
        # that is nearly empty.
        self.policy.begin(key, context.command, None)

        result = auth.check_auth(
            protocol, request.auth_material, param, CREDENTIAL_MANAGEMENT,
            request.rp_id_hash,
        )
        if result != auth.OK:
            raise CtapError(translate(auth, result))
        self.policy.authorize_pin(
            key, CREDENTIAL_MANAGEMENT, None, bytearray(param)
        )

        try:
            await self.policy.consume_presence(key, PRESENCE_TIMEOUT_MS)
        except PolicyError:
            # consume_presence has already aborted the transaction. Refusal and
            # timeout arrive here alike.
            raise CtapError(OPERATION_DENIED)
        self.policy.take_authorization(key)
        return key

    def _occupied(self, rp_id_hash=None):
        """The slots holding a credential, in slot order.

        One scan for the whole answer, so the vault authenticates its stored
        snapshot once rather than once per slot. A refusal here is a damaged vault
        rather than an answer about scope, and there is no CTAP code for that: a
        bound token has already been checked against the party this subcommand
        named, and an unbound one sees every slot.
        """
        try:
            return ResidentStore.occupied(rp_id_hash)
        except CredentialUnavailable:
            raise CtapError(OTHER)

    def _record(self, index):
        """Re-read one slot that the enumeration already counted as occupied."""
        try:
            credential = ResidentStore.get(index)
        except CredentialUnavailable:
            raise CtapError(OTHER)
        if credential is None:
            # Nothing else can run on this channel while a continuation is
            # outstanding, so a slot that has emptied since it was counted means
            # the vault changed underneath us.
            raise CtapError(OTHER)
        return credential

    def _metadata(self):
        existing = len(self._occupied())
        # The remaining count is what the specification calls an estimate: a slot
        # is free, but a record large enough to need more than a slot holds will
        # still be turned down.
        return {
            EXISTING_COUNT: existing,
            REMAINING_COUNT: RESIDENT_SLOTS - existing,
        }

    def _begin_rps(self, key):
        slots = []
        seen = []
        for index in self._occupied():
            # Which parties are stored is not something occupancy can answer, so
            # this is the one enumeration that still reads each occupied slot.
            credential = self._record(index)
            if credential.rp_id_hash in seen:
                continue
            seen.append(credential.rp_id_hash)
            slots.append(index)
        if not slots:
            raise CtapError(NO_CREDENTIALS)
        total = len(slots)
        first = slots.pop(0)
        self._arm(key, ENUMERATE_RPS_NEXT, slots)
        response = self._rp_entry(first)
        response[TOTAL_RPS] = total
        return response

    def _begin_credentials(self, key, rp_id_hash):
        # The vault filters by relying party itself, so this asks about one
        # party's slots and is told nothing about anyone else's.
        slots = self._occupied(rp_id_hash)
        if not slots:
            raise CtapError(NO_CREDENTIALS)
        total = len(slots)
        first = slots.pop(0)
        self._arm(key, ENUMERATE_CREDENTIALS_NEXT, slots)
        response = self._credential_entry(first)
        response[TOTAL_CREDENTIALS] = total
        return response

    def _arm(self, key, subcommand, slots) -> None:
        """Reserve the follow-ups before answering, so the count reported and the
        count the policy will allow are decided together."""
        if not slots:
            return
        self.policy.continue_responses(key, None, len(slots))
        self._key = key
        self._continues = subcommand
        self._pending = slots

    def _next(self, subcommand):
        """Continue the enumeration the first response already authorized."""
        if not self._pending or self._key is None or self._continues != subcommand:
            # Either nothing is outstanding, or the platform asked to continue an
            # enumeration it never began. CTAP calls an out-of-order stateful
            # command not allowed, which is exactly what this is.
            self._forget()
            raise CtapError(NOT_ALLOWED)
        key = self._key
        try:
            # The policy is the authority on whether the transaction is alive. If
            # it disagrees, the slots held here are stale and go.
            self.policy.next_response(key, None)
        except PolicyError:
            self._forget()
            raise CtapError(NOT_ALLOWED)
        index = self._pending.pop(0)
        if not self._pending:
            self._forget()
        if subcommand == ENUMERATE_RPS_NEXT:
            return self._rp_entry(index)
        return self._credential_entry(index)

    def _rp_entry(self, index):
        credential = self._record(index)
        # The relying party id, and its name when the record carries one. This
        # answer goes to the settings screen of the person holding the device, at
        # their request, so a list of opaque hashes would defeat the point.
        rp = {"id": credential.rp_id}
        if credential.rp_name:
            rp["name"] = credential.rp_name
        return {RP: rp, RP_ID_HASH: credential.rp_id_hash}

    def _credential_entry(self, index):
        credential = self._record(index)
        user = {"id": credential.user_id}
        if credential.user_name:
            user["name"] = credential.user_name
        if credential.user_display_name:
            user["displayName"] = credential.user_display_name
        return {
            USER: user,
            CREDENTIAL_ID: {"id": credential.id, "type": "public-key"},
            # The vault's COSE key is already canonical CBOR. It is spliced in
            # rather than parsed and rebuilt, so nothing between the vault and
            # the platform can change what the key says.
            PUBLIC_KEY: RawCbor(credential.public_key()),
            CRED_PROTECT: credential.cred_protect,
        }

    def _delete(self, descriptor):
        for index in self._occupied():
            # Matching an identifier means reading the record that holds it;
            # occupancy alone cannot say which slot this descriptor names.
            if self._record(index).id != descriptor.id:
                continue
            try:
                ResidentStore.delete(index)
            except CredentialUnavailable:
                raise CtapError(OTHER)
            # Deletion has no response data.
            return None
        # Nothing here matches, which is the same answer as "this device holds no
        # such credential" and tells a caller with a valid grant nothing more.
        raise CtapError(NO_CREDENTIALS)


def register(dispatcher, auth=None, random_bytes=None) -> None:
    handler = CredentialManagement(dispatcher.policy, auth, random_bytes)
    dispatcher.register(COMMAND, handler.handle)
    # One handler, two command numbers: see dispatcher.COMMANDS.
    dispatcher.register(PREVIEW_COMMAND, handler.handle)
