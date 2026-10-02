"""CTAP authenticatorGetAssertion and authenticatorGetNextAssertion.

A request carrying options {"up": false} is the pre-flight probe a platform sends
to find out what a device holds before it prompts for anything. Two different
platforms send two different versions of it, and they need two different answers.
What decides is what the request proved:

  * With a token verified for this relying party the answer is a real assertion
    signed with the presence bit clear. Nobody touched anything and the
    authenticator data says so, which is what makes it safe to give: WebAuthn
    requires a relying party to reject an assertion whose presence bit is not
    set, so this answer reports existence and cannot be spent as a login. This is
    the shape Windows WebAuthn sends, and refusing it produced a key that could
    register and never assert.
  * Without a pinUvAuthParam the answer is CTAP2_ERR_UP_REQUIRED, reached without
    asking the vault anything at all. This is the shape OpenSSH sends to work out
    which of the attached devices holds a non-discoverable credential, and
    sk-usbhid.c accepts exactly two answers to it: success, or this one. Any other
    error means "not this device", so answering NO_CREDENTIALS here told ssh the
    credential was absent and it reported "device not found" for a key this device
    was holding.

UP_REQUIRED is the right answer rather than merely the accepted one. It is a
constant: the same whether or not this device holds the credential, so it discloses
nothing, where a truthful silent assertion would disclose existence to anyone with
access to the port. It needs no vault call, so the rule that no signature happens
without a verified PIN is untouched. And it is true -- the device really does
require presence, or a token, before it will sign.

An earlier version of this module refused *every* presence-less request with
UP_REQUIRED, which broke the browser. The replacement answered every one of them
from nothing with NO_CREDENTIALS, which broke OpenSSH. Both were the same mistake:
treating one request shape where there are two.

GetNextAssertion also collects no fresh edge, because it is not a new
authorization -- it continues the one the first assertion already paid for. The
policy holds that continuation and counts it down; this module holds the
credentials still to be returned and refuses to use them the moment the policy
stops agreeing that the transaction is alive.

What a response says about the account is decided the same way: by whether the
answer is any use without it. A device with no display cannot offer a choice, so
when discovery finds more than one account for a relying party the platform's own
picker is the only way to choose, and a picker needs names. One account, or an
allow list the platform composed itself, needs none -- so none are sent. The
specification permits user identifiable information only where user verification
was done, which every assertion here has: a token was verified before any of this.
Nothing reaches the relying party either way; the platform keeps the handle and
discards the rest.
"""

from .cbor_codec import CtapError
from .client_pin import GET_ASSERTION, translate
from .credential import Credential, CredentialUnavailable
from .policy import PolicyError, TransactionKey
from .resident_store import ResidentStore
from .protocol import (
    FLAG_USER_PRESENT, FLAG_USER_VERIFIED, authenticator_data,
)

COMMAND = 2
NEXT_COMMAND = 8

# Response map keys.
CREDENTIAL = 1
AUTH_DATA = 2
SIGNATURE = 3
USER = 4
NUMBER_OF_CREDENTIALS = 5

MISSING_PARAMETER = 0x14
OPERATION_DENIED = 0x27
NO_CREDENTIALS = 0x2E
UP_REQUIRED = 0x3B
PIN_INVALID = 0x31
PIN_NOT_SET = 0x35
PUAT_REQUIRED = 0x36
NOT_ALLOWED = 0x30
OTHER = 0x7F

# The policy bounds a continuation to nine follow-ups, which is also the decoder's
# ceiling on an allow list, so ten assertions is the whole of it.
MAX_FOLLOW_UPS = 9

PRESENCE_TIMEOUT_MS = 30000


class GetAssertion:
    """Owns the credentials a continuation still has to return."""

    def __init__(self, policy, auth=None, random_bytes=None) -> None:
        self.policy = policy
        self._auth = auth
        self._random_bytes = random_bytes
        self._forget()

    def _forget(self) -> None:
        self._key = None
        self._rp_id_hash = None
        self._client_data_hash = None
        self._flags = 0
        self._named = False
        self._pending = []

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
        # Any new assertion ends whatever continuation was outstanding. The
        # dispatcher has already aborted the policy for us; this drops the
        # credentials that went with it so a later GetNextAssertion cannot find
        # them lying around.
        self._forget()
        auth = self._vault()
        param = request.pin_uv_auth_param
        protocol = request.pin_uv_auth_protocol

        if param == b"":
            # The authenticator-selection probe, answered the same way
            # makeCredential answers it and for the same reasons.
            state, _retries, _consecutive = auth.status()
            raise CtapError(
                PIN_INVALID
                if state == auth.OK or state == auth.PIN_AUTH_BLOCKED
                else PIN_NOT_SET
            )
        if param is None:
            if not request.up:
                # The unverified pre-flight probe. Answered from nothing, and with
                # the one refusal that does not claim the credential is absent:
                # OpenSSH reads NO_CREDENTIALS as "not this device" and gives up,
                # while UP_REQUIRED keeps the device a candidate and still tells
                # the truth, since presence or a token really is required. The
                # answer does not depend on what is stored, so it reveals nothing.
                raise CtapError(UP_REQUIRED)
            state, _retries, _consecutive = auth.status()
            raise CtapError(PUAT_REQUIRED if state == auth.OK else PIN_NOT_SET)
        if protocol is None:
            raise CtapError(MISSING_PARAMETER)

        from trezorcrypto import sha256

        rp_id_hash = sha256(request.rp_id.encode()).digest()

        key = TransactionKey(
            context.connection_generation, context.cid, self._nonce()
        )
        self.policy.begin(key, context.command, rp_id_hash)

        result = auth.check_auth(
            protocol, request.client_data_hash, param, GET_ASSERTION, rp_id_hash,
        )
        if result != auth.OK:
            raise CtapError(translate(auth, result))
        self.policy.authorize_pin(
            key, GET_ASSERTION, rp_id_hash, bytearray(param)
        )

        found = self._locate(request, rp_id_hash)
        if not found:
            raise CtapError(NO_CREDENTIALS)
        # Only a discovery that found a choice needs the choice described.
        named = request.allow_list is None and len(found) > 1

        if request.up:
            try:
                await self.policy.consume_presence(key, PRESENCE_TIMEOUT_MS)
            except PolicyError:
                raise CtapError(OPERATION_DENIED)
            self.policy.take_authorization(key)
            flags = FLAG_USER_PRESENT | FLAG_USER_VERIFIED
        else:
            self.policy.take_authorization_without_presence(key)
            flags = FLAG_USER_VERIFIED

        remaining = found[1:]
        if remaining:
            # Reserve the follow-ups before answering, so the count the platform
            # is told and the count the policy will allow are decided together.
            self.policy.continue_responses(key, rp_id_hash, len(remaining))
            self._key = key
            self._rp_id_hash = rp_id_hash
            self._client_data_hash = request.client_data_hash
            self._flags = flags
            self._named = named
            self._pending = remaining

        response = self._assert(
            found[0], rp_id_hash, request.client_data_hash, flags, named
        )
        if remaining:
            response[NUMBER_OF_CREDENTIALS] = len(found)
        return response

    async def handle_next(self, request, context):
        """Continue the assertion the first response already authorized."""
        if not self._pending or self._key is None:
            # Nothing is outstanding. CTAP calls an out-of-order stateful command
            # not allowed, which is the truth here: there is no state to continue.
            raise CtapError(NOT_ALLOWED)
        # The channel is not re-checked here. The dispatcher only lets command 8
        # through while the policy is in a continuation on the same generation
        # and channel, and next_response below compares the whole transaction
        # key anyway, so a third copy of that rule would be a claim nothing can
        # break.
        key = self._key
        rp_id_hash = self._rp_id_hash
        client_data_hash = self._client_data_hash
        # Whatever the first response said about presence, every response in the
        # series says, because they are all the one authorization it paid for.
        flags = self._flags
        # Likewise the naming: the series is one picker being filled in.
        named = self._named
        try:
            # The policy is the authority on whether the transaction is still
            # alive. If it disagrees, the credentials held here are stale and go.
            self.policy.next_response(key, rp_id_hash)
        except PolicyError:
            self._forget()
            raise CtapError(NOT_ALLOWED)
        credential = self._pending.pop(0)
        if not self._pending:
            self._forget()
        return self._assert(credential, rp_id_hash, client_data_hash, flags, named)

    def _locate(self, request, rp_id_hash):
        """The credentials this device can assert for this relying party."""
        if request.allow_list is None:
            return self._discover(rp_id_hash)
        found = []
        for descriptor in request.allow_list:
            try:
                found.append(Credential.open(descriptor.id, rp_id_hash))
            except (CredentialUnavailable, ValueError):
                # Not ours, not this relying party's, or not a well-formed
                # identifier. The token carries ga, so a refusal is an answer.
                continue
            if len(found) > MAX_FOLLOW_UPS:
                # One more than the continuation can ever hand back. Stopping
                # here keeps the count reported to the platform equal to the
                # count the policy will allow.
                break
        return found

    def _discover(self, rp_id_hash):
        """The discoverable credentials stored for this relying party.

        One scan names this party's slots, and only those slots are read. The
        vault answers for the party the token is bound to and reports every other
        party's slot as empty, so this sees only what it is entitled to see. The
        hash is compared again after reading: a token that was somehow scoped
        wrongly must not turn into an assertion for the wrong party, and the
        filter asking for one party is not by itself proof the answer honoured it.
        """
        found = []
        for index in ResidentStore.occupied(rp_id_hash):
            credential = ResidentStore.get(index)
            if credential is None or credential.rp_id_hash != rp_id_hash:
                continue
            found.append(credential)
            if len(found) > MAX_FOLLOW_UPS:
                break
        return found

    def _assert(self, credential, rp_id_hash, client_data_hash, flags, named):
        data = authenticator_data(rp_id_hash, flags)
        try:
            signature = credential.sign(data + client_data_hash)
        except CredentialUnavailable:
            raise CtapError(OTHER)
        user = {"id": credential.user_id}
        if named:
            # Whatever the site itself supplied, and nothing the site left out: an
            # empty name is not a name, and sending one would fill a picker with
            # blanks rather than describe anything.
            if credential.user_name:
                user["name"] = credential.user_name
            if credential.user_display_name:
                user["displayName"] = credential.user_display_name
        return {
            CREDENTIAL: {"id": credential.id, "type": "public-key"},
            AUTH_DATA: data,
            SIGNATURE: signature,
            USER: user,
        }


def register(dispatcher, auth=None, random_bytes=None) -> None:
    handler = GetAssertion(dispatcher.policy, auth, random_bytes)
    dispatcher.register(COMMAND, handler.handle)
    dispatcher.register(NEXT_COMMAND, handler.handle_next)
