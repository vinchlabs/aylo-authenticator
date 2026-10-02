"""CTAP authenticatorMakeCredential.

This device has no path that creates a credential without a PIN. The policy's
permission table puts command 1 in WAIT_PIN unconditionally, so a request that
carries no pinUvAuthParam has nothing to fall back to and is refused rather than
served with a weaker guarantee. That is the same property CTAP calls alwaysUv,
arrived at from the authorization layer rather than from an option flag.

Attestation is `none`: an empty statement over authenticatorData that already
carries the credential's own public key. Nothing here signs anything. A
self-attestation statement would be a signature by the very key being attested,
which tells a relying party nothing it cannot read from the key itself, and basic
attestation would need a shared certificate this project deliberately does not
have.

A discoverable credential goes into a numbered slot, and which slots are free is
not something this side is allowed to know. The vault reports another relying
party's slot as empty and refuses to let one party overwrite another's, so
allocation is a walk of attempts: the vault turns down the ones that are taken.
That is a privacy property rather than a workaround -- the application never
learns how many credentials other parties have put on the device.
"""

from .cbor_codec import CtapError, encode_response
from .client_pin import GET_ASSERTION, MAKE_CREDENTIAL, translate
from .credential import (
    Credential, CredentialLimitExceeded, CredentialStoreFull,
    CredentialUnavailable,
)
from .policy import PolicyError, TransactionKey
from .resident_store import ResidentStore
from .protocol import (
    FLAG_ATTESTED, FLAG_EXTENSION_DATA, FLAG_USER_PRESENT, FLAG_USER_VERIFIED,
    attested_credential_data, authenticator_data,
)

COMMAND = 1

# Response map keys.
FMT = 1
AUTH_DATA = 2
ATT_STMT = 3

# WebAuthn's packed format, which is what a self attestation has to be: the
# "none" format carries no signature, and a platform that verifies an
# enrollment has nothing to verify.
PACKED_ATTESTATION = "packed"

MISSING_PARAMETER = 0x14
CREDENTIAL_EXCLUDED = 0x19
OPERATION_DENIED = 0x27
KEY_STORE_FULL = 0x28
PIN_INVALID = 0x31
PIN_NOT_SET = 0x35
PUAT_REQUIRED = 0x36
REQUEST_TOO_LARGE = 0x39
OTHER = 0x7F

# The credential record carries the relying party id so the vault can re-derive
# its hash and refuse metadata that does not match; it cannot be truncated, and
# 253 bytes is what the record has for it.
MAX_RP_ID = 253
# Each display name has 100 bytes in the record. The request decoder allows far
# more, because the protocol does not limit them, so they are cut here.
MAX_LABEL = 100

# The vault has a hundred numbered slots for discoverable credentials.
RESIDENT_SLOTS = 100

PRESENCE_TIMEOUT_MS = 30000


def _label(value) -> str:
    """Fit a display name into the record without producing invalid UTF-8."""
    if value is None:
        return ""
    encoded = value.encode()
    if len(encoded) <= MAX_LABEL:
        return value
    end = MAX_LABEL
    # Back off a byte at a time while the cut would land inside a code point.
    while end and encoded[end] & 0xC0 == 0x80:
        end -= 1
    return encoded[:end].decode()


class MakeCredential:
    """Holds no state; the vault owns the session and the policy the grant."""

    def __init__(self, policy, auth=None, random_bytes=None) -> None:
        self.policy = policy
        self._auth = auth
        self._random_bytes = random_bytes

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
        auth = self._vault()
        param = request.pin_uv_auth_param
        protocol = request.pin_uv_auth_protocol

        if param == b"":
            # CTAP's authenticator-selection probe. The specification has the
            # authenticator collect a gesture first, so that a user with several
            # keys attached picks one; with no indicator to light and no policy
            # state that allows a wait without a grant, there is nothing to
            # collect and nothing the gesture would disambiguate. The answer
            # itself discloses only whether a PIN is set, which GetInfo already
            # says out loud.
            state, _retries, _consecutive = auth.status()
            raise CtapError(
                PIN_INVALID
                if state == auth.OK or state == auth.PIN_AUTH_BLOCKED
                else PIN_NOT_SET
            )
        if param is None:
            state, _retries, _consecutive = auth.status()
            raise CtapError(PUAT_REQUIRED if state == auth.OK else PIN_NOT_SET)
        if protocol is None:
            raise CtapError(MISSING_PARAMETER)
        # The "uv" option is not consulted. CTAP says a present pinUvAuthParam
        # makes it false whatever the platform sent, and a platform is forbidden
        # from sending both; since this handler refuses every request without a
        # pinUvAuthParam above, that branch is the only one reachable.

        rp_id = request.rp.id
        if len(rp_id.encode()) > MAX_RP_ID:
            # The stored record has to hold the id itself, because the vault
            # re-hashes it to check the metadata binds to this relying party.
            raise CtapError(REQUEST_TOO_LARGE)
        from trezorcrypto import sha256

        rp_id_hash = sha256(rp_id.encode()).digest()

        key = TransactionKey(
            context.connection_generation, context.cid, self._nonce()
        )
        self.policy.begin(key, context.command, rp_id_hash)

        result = auth.check_auth(
            protocol, request.client_data_hash, param, MAKE_CREDENTIAL,
            rp_id_hash,
        )
        if result != auth.OK:
            raise CtapError(translate(auth, result))
        # The plaintext token never crosses into Python, so what the policy
        # retains is a marker that this verification happened, held in a mutable
        # buffer it erases when the transaction ends.
        self.policy.authorize_pin(
            key, MAKE_CREDENTIAL, rp_id_hash, bytearray(param)
        )

        try:
            await self.policy.consume_presence(key, PRESENCE_TIMEOUT_MS)
        except PolicyError:
            # consume_presence has already aborted the transaction. Refusal and
            # timeout arrive here alike.
            raise CtapError(OPERATION_DENIED)

        if request.exclude_list:
            self._refuse_excluded(auth, request, protocol, param, rp_id_hash)

        self.policy.take_authorization(key)
        credential = self._create(request, rp_id)
        if request.rk:
            self._store(credential)
        return self._attestation(request, credential, rp_id_hash)

    def _store(self, credential):
        """Hand a discoverable credential to the vault, which chooses its slot.

        Occupancy is the vault's to know, which is why this does not look for a
        free slot itself. It used to: it tried slot zero, and on a refusal slot
        one, and so on. That could never have worked, and a browser found it. A
        refusal leaves the vault through its fail-closed exit, which invalidates
        the session, so the second attempt had no authorization left and neither
        did the ninety-eight after it -- a device holding one credential for
        somebody else reported itself full.

        Replacing is the vault's to do as well, and for the same reason. CTAP
        says a credential for a relying party and an account that both already
        exist replaces the record that is there; only the vault can see which
        slot that is, and only the vault can put the new record in its place as
        one authenticated commit, so the account is never for a moment without
        one. It needs no free slot either: a device with every slot occupied can
        still replace.

        This was tried here first, as a scan for the account followed by a store
        and a delete, and it could not work. Deletion requires the
        credential-management permission and a registration carries the creation
        one, so the removal was refused, the refusal was swallowed, and the device
        kept both records. The device was the only thing that could have said so.
        """
        try:
            ResidentStore.store(credential)
        except CredentialLimitExceeded:
            # This record does not fit a slot at all. A different slot would say
            # the same, and a platform can act on it by sending less metadata.
            raise CtapError(REQUEST_TOO_LARGE)
        except CredentialStoreFull:
            raise CtapError(KEY_STORE_FULL)
        except CredentialUnavailable:
            # The vault refused for a reason that is not about room: a duplicate
            # identifier, or an authorization that no longer holds. Neither is
            # something a platform can fix by asking differently.
            raise CtapError(OTHER)

    def _refuse_excluded(self, auth, request, protocol, param, rp_id_hash):
        """Refuse a credential this authenticator already holds for this party.

        Checked after presence, which is the order CTAP asks for: an exclusion is
        an answer about what the device holds, and the specification does not let
        that be read without a gesture even by a caller holding a valid token.

        Deciding whether an identifier is one of ours means opening it, and
        opening needs the ga permission, which a token issued for mc alone does
        not carry. So the permission is probed first. Without the probe a token
        without ga would make every exclusion look like "not mine" and the
        credential would be created anyway -- the one outcome the relying party
        asked to prevent.
        """
        if auth.check_auth(
            protocol, request.client_data_hash, param,
            MAKE_CREDENTIAL | GET_ASSERTION, rp_id_hash,
        ) != auth.OK:
            raise CtapError(PUAT_REQUIRED)
        for descriptor in request.exclude_list:
            try:
                Credential.open(descriptor.id, rp_id_hash)
            except (CredentialUnavailable, ValueError):
                # Not ours, not for this relying party, or not even a
                # well-formed identifier. The probe above established that a
                # refusal here is an answer and not a missing permission.
                continue
            raise CtapError(CREDENTIAL_EXCLUDED)

    def _create(self, request, rp_id):
        try:
            return Credential.create(
                rp_id,
                request.user.id,
                rp_name=_label(request.rp.name),
                user_name=_label(request.user.name),
                user_display_name=_label(request.user.display_name),
                algorithm=request.algorithm,
                hmac_secret=request.hmac_secret,
            )
        except CredentialUnavailable:
            # The vault refused. It has already been told the grant is valid, so
            # this is a damaged or locked vault rather than an authorization
            # answer, and no CTAP code describes it.
            raise CtapError(OTHER)

    def _attestation(self, request, credential, rp_id_hash):
        flags = FLAG_USER_PRESENT | FLAG_USER_VERIFIED | FLAG_ATTESTED
        extensions = {}
        if request.cred_protect is not None:
            # The decoder accepts only UV_REQUIRED, and the record stores only
            # that, so the echo is the value the credential actually has.
            extensions["credProtect"] = credential.cred_protect
        # hmac-secret is deliberately not echoed. GetInfo does not offer it, and
        # authenticator data is where CTAP says a credential *has* one -- claiming
        # it here would promise an output no assertion can produce, because the
        # salts arrive encrypted under the shared secret and only the vault could
        # open them. The request is accepted and ignored, which is what CTAP asks
        # of an authenticator for an extension it does not support. The vault still
        # records the bit, as a reservation rather than a capability.
        encoded = b""
        if extensions:
            flags |= FLAG_EXTENSION_DATA
            encoded = encode_response(extensions)
        data = authenticator_data(
            rp_id_hash, flags, attested_credential_data(credential), encoded
        )
        # Self attestation, over exactly the bytes a relying party verifies. This
        # used to be the "none" format with an empty statement, which is legal and
        # turned out to be useless: a platform that checks an enrollment has
        # nothing to check, and OpenSSH refuses the key outright -- it calls
        # fido_cred_verify_self and finds no signature. The credential signs for
        # itself instead, which proves it came from whatever made it and says
        # nothing about this device.
        try:
            signature = credential.attest(data + request.client_data_hash)
        except CredentialUnavailable:
            raise CtapError(OTHER)
        return {
            FMT: PACKED_ATTESTATION,
            AUTH_DATA: data,
            ATT_STMT: {"alg": credential.algorithm, "sig": signature},
        }


def register(dispatcher, auth=None, random_bytes=None) -> None:
    handler = MakeCredential(dispatcher.policy, auth, random_bytes)
    dispatcher.register(COMMAND, handler.handle)
