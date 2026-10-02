"""CTAP ClientPIN, routed to the vault.

This handler decides what a subcommand is allowed to do and what error the
platform gets back. It never sees a PIN, a PIN hash, a shared secret or a token:
the platform's ciphertext is passed through to the vault untouched, and the vault
returns only its own ciphertext and a result code.

Everything that can be judged from the request's shape alone -- subcommand
number, protocol, which parameters are mandatory, every ciphertext length, a
zero permissions set, a missing rpId for an RP-scoped permission -- is already
rejected by the CBOR schema before a typed request reaches here. So the codes
below are only the ones that depend on the vault's answer or on what this
particular device can do.

Four of the eight defined subcommands are refused rather than implemented, and
each refusal is a property of this device rather than an omission:

  * changePIN (0x04). The root is wrapped under a PIN-derived key and there is
    no power-safe re-wrap path, so a change that appeared to succeed could
    strand every credential. The vault denies it unconditionally; answering here
    keeps that true without a call that could only be a no-op.
  * getPINToken (0x05). It is defined to hand out a token carrying the default
    mc and ga permissions with no relying party associated, and the vault has no
    way to represent an unbound mc/ga grant -- issuing one would mean dropping
    the RP binding that makes a captured token useless against another site.
    CTAP 2.1 keeps this subcommand for backwards compatibility only; a platform
    that sees pinUvAuthToken in GetInfo uses 0x09 instead.
  * getPinUvAuthTokenUsingUvWithPermissions (0x06) and getUVRetries (0x07).
    There is no built-in user verification to perform or to count retries for.
    This authenticator has no display and no biometric; a PIN plus a physical
    edge is the whole of it.

All four answer CTAP2_ERR_INVALID_SUBCOMMAND, which the specification defines as
covering subcommands that are invalid *or* not implemented.

All of this is reachable by a conforming platform: GetInfo advertises
pinUvAuthToken and both pinUvAuth protocols, and reports clientPin according to
whether a PIN is set.
"""

from .cbor_codec import CtapError
from .pin_protocol import (
    KEY_AGREEMENT, PIN_RETRIES, PIN_UV_AUTH_TOKEN, POWER_CYCLE_STATE,
    decode_key_agreement, encode_key_agreement,
)
from .policy import PolicyError, TransactionKey

COMMAND = 6

GET_PIN_RETRIES = 1
GET_KEY_AGREEMENT = 2
SET_PIN = 3
CHANGE_PIN = 4
GET_PIN_TOKEN = 5
GET_TOKEN_USING_UV = 6
GET_UV_RETRIES = 7
GET_TOKEN_USING_PIN = 9

# Answered "not implemented" for the reasons in the module docstring.
REFUSED = (CHANGE_PIN, GET_PIN_TOKEN, GET_TOKEN_USING_UV, GET_UV_RETRIES)

INVALID_PARAMETER = 0x02
OPERATION_DENIED = 0x27
PIN_INVALID = 0x31
PIN_BLOCKED = 0x32
PIN_AUTH_INVALID = 0x33
PIN_AUTH_BLOCKED = 0x34
PIN_NOT_SET = 0x35
PIN_POLICY_VIOLATION = 0x37
INVALID_SUBCOMMAND = 0x3E
UNAUTHORIZED_PERMISSION = 0x40
OTHER = 0x7F

# What a token may carry. The specification ties each permission to a GetInfo
# option and requires CTAP2_ERR_UNAUTHORIZED_PERMISSION when the option is not
# advertised, so this mask and what GetInfo advertises have to say the same
# thing; get_info.py derives the credMgmt option from this constant rather than
# repeating the judgement.
#
# mc and ga are conditioned only on noMcGaPermissionsWithClientPin, which this
# device does not set, so they are grantable. cm is conditioned on credMgmt,
# which this firmware now implements and advertises, so it is grantable too.
# The remaining defined bits -- be, lbw, acfg -- name bio enrollment, large blobs
# and authenticator configuration, none of which this device has.
MAKE_CREDENTIAL = 0x01
GET_ASSERTION = 0x02
CREDENTIAL_MANAGEMENT = 0x04
GRANTABLE = MAKE_CREDENTIAL | GET_ASSERTION | CREDENTIAL_MANAGEMENT

# setPIN is the only subcommand that writes persistent state on a device nobody
# has unlocked yet, so it is the only one that needs a physical edge.
PRESENCE_TIMEOUT_MS = 30000


def translate(auth, result: int) -> int:
    """Map a vault result onto the CTAP code that describes it to the platform."""
    if result == auth.UNPROVISIONED:
        return PIN_NOT_SET
    if result == auth.PIN_INVALID:
        return PIN_INVALID
    if result == auth.PIN_AUTH_BLOCKED:
        return PIN_AUTH_BLOCKED
    if result == auth.PIN_BLOCKED:
        return PIN_BLOCKED
    if result == auth.PIN_POLICY:
        return PIN_POLICY_VIOLATION
    if result == auth.INVALID_ARGUMENT:
        # A peer key that is not on the curve, which is what CTAP calls a failed
        # decapsulate, and a new PIN whose padding or UTF-8 does not hold up.
        return INVALID_PARAMETER
    if result == auth.DENIED:
        # No key agreement is in flight, the pinUvAuthParam did not verify, or a
        # PIN already exists. CTAP answers all three with PIN_AUTH_INVALID, so
        # collapsing them loses nothing the platform was entitled to know.
        return PIN_AUTH_INVALID
    # ERROR and MIGRATION_REQUIRED both mean the vault will not act and no CTAP
    # code says why; LIMIT_EXCEEDED cannot come back from these calls.
    return OTHER


class ClientPin:
    """Holds no state: the vault owns the session, the policy owns the grant."""

    def __init__(self, policy, auth=None, random_bytes=None) -> None:
        self.policy = policy
        self._auth = auth
        self._random_bytes = random_bytes

    def _vault(self):
        # Imported on first use, not at construction, so that building the
        # dispatcher does not require the native module to exist.
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
        subcommand = request.subcommand

        if subcommand == GET_PIN_RETRIES:
            state, retries, _consecutive = auth.status()
            if state == auth.PIN_AUTH_BLOCKED:
                # The count is still true; what is missing is a power cycle.
                # getRetries is the one response powerCycleState is defined for,
                # and reporting it is not a substitute for PIN_AUTH_BLOCKED on
                # the subcommands that must return it, which still do.
                return {PIN_RETRIES: retries, POWER_CYCLE_STATE: True}
            if state != auth.OK:
                raise CtapError(translate(auth, state))
            return {PIN_RETRIES: retries, POWER_CYCLE_STATE: False}

        if subcommand in REFUSED:
            raise CtapError(INVALID_SUBCOMMAND)

        if subcommand == GET_KEY_AGREEMENT:
            result, public_key = auth.key_agreement()
            if result != auth.OK:
                raise CtapError(translate(auth, result))
            return {KEY_AGREEMENT: encode_key_agreement(public_key)}

        # Only setPIN and getPinUvAuthTokenUsingPinWithPermissions are left, and
        # the schema has required a key agreement and a protocol for both.
        peer = decode_key_agreement(request.key_agreement)
        protocol = request.pin_uv_auth_protocol
        if subcommand == SET_PIN:
            return await self._set_pin(auth, request, context, protocol, peer)
        return self._issue(auth, request, protocol, peer)

    async def _set_pin(self, auth, request, context, protocol, peer):
        state, _retries, _consecutive = auth.status()
        if state != auth.UNPROVISIONED:
            # CTAP answers a setPIN on a device that already has a PIN with
            # PIN_AUTH_INVALID, and so would the vault, by refusing to provision
            # over one. Checked first anyway so a request that cannot succeed
            # never makes somebody walk over and insert a card for it.
            raise CtapError(
                PIN_AUTH_INVALID if state == auth.OK else translate(auth, state)
            )

        key = TransactionKey(
            context.connection_generation, context.cid, self._nonce()
        )
        self.policy.begin(key, context.command, None)
        try:
            await self.policy.consume_presence(key, PRESENCE_TIMEOUT_MS)
            self.policy.take_authorization(key)
        except PolicyError:
            # consume_presence has already aborted the transaction and cleared
            # the provider. A refusal and a timeout arrive here the same way, and
            # the platform is told the same thing either way.
            raise CtapError(OPERATION_DENIED)

        result = auth.set_pin(
            protocol, request.new_pin_enc, request.pin_uv_auth_param, peer
        )
        if result != auth.OK:
            raise CtapError(translate(auth, result))
        # setPIN has no response data. Returning None makes the dispatcher emit a
        # bare success status rather than an empty CBOR map.
        return None

    def _issue(self, auth, request, protocol, peer):
        permissions = request.permissions
        if permissions & ~GRANTABLE:
            # Refused rather than quietly narrowed: a platform that believed it
            # held a large-blob grant would go on to use it.
            raise CtapError(UNAUTHORIZED_PERMISSION)
        rp_id_hash = None
        if request.rp_id is not None:
            from trezorcrypto import sha256

            rp_id_hash = sha256(request.rp_id.encode()).digest()
        # None, not b"", for an unscoped token: the binding rejects a short
        # buffer, and only an absent one means "no relying party".
        result, token = auth.issue_token(
            request.pin_hash_enc, protocol, permissions, rp_id_hash, peer
        )
        if result != auth.OK:
            raise CtapError(translate(auth, result))
        return {PIN_UV_AUTH_TOKEN: token}


def register(dispatcher, auth=None, random_bytes=None) -> None:
    """Attach ClientPIN to a dispatcher, sharing the dispatcher's policy."""
    handler = ClientPin(dispatcher.policy, auth, random_bytes)
    dispatcher.register(COMMAND, handler.handle)
