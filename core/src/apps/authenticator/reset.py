"""CTAP authenticatorReset and authenticatorSelection.

The two commands live together because they are the same shape: no PIN, no
parameters, no response body, authorized by a physical edge and nothing else.
Splitting forty lines into a second module would add an entry to the image's
frozen manifest for no gain.

Reset is the one command that destroys everything, and the specification gives an
authenticator without a display exactly one defence against a remote one: the
request has to arrive within ten seconds of power-up. This device has no display,
so that clause is not optional here. The window is checked before presence is
collected -- the command must be early, the gesture only has to be within the
ordinary wait -- and it is measured from when the transport started serving,
which on this applet is the moment the device powered up. A USB unplug powers the
device down, so replugging is what reopens the window, which is also how a person
would expect to be told to do it.
"""

from .cbor_codec import CtapError
from .policy import PolicyError, TransactionKey

RESET_COMMAND = 7
SELECTION_COMMAND = 11

OPERATION_DENIED = 0x27
NOT_ALLOWED = 0x30
USER_ACTION_TIMEOUT = 0x3A
OTHER = 0x7F

# The specification's figure, and the whole of the protection for a device that
# cannot ask a person to confirm on a screen.
#
# Widening this is tempting and was done once, for an hour, to re-provision the PIN
# from a host whose USB bridge takes longer to attach than the window lasts. Worth
# recording why it went back: on a device with assumed presence there is no gesture
# to stand in the way, so this window is the entire reason a stranger holding the
# key cannot wipe it. Two minutes is a different product from ten seconds.
RESET_WINDOW_MS = 10000

PRESENCE_TIMEOUT_MS = 30000

# utime.ticks_ms() is free to wrap. The policy masks its own arithmetic the same
# way, so a wrap cannot make an elapsed interval look negative or enormous.
_TICKS_MASK = (1 << 30) - 1


class PresenceOnly:
    """A command authorized by a fresh physical edge and nothing else."""

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

    async def _edge(self, context, ticks_ms=None):
        """Take one fresh edge for this command, or say why there was none."""
        key = TransactionKey(
            context.connection_generation, context.cid, self._nonce()
        )
        self.policy.begin(key, context.command, None)
        began = None if ticks_ms is None else ticks_ms()
        try:
            await self.policy.consume_presence(key, PRESENCE_TIMEOUT_MS)
        except PolicyError:
            # consume_presence has already aborted the transaction. It reports a
            # refusal and a timeout alike, so the clock is what separates them,
            # and Reset is a command the specification wants told apart.
            if began is not None and ticks_ms is not None:
                elapsed = (ticks_ms() - began) & _TICKS_MASK
                if elapsed >= PRESENCE_TIMEOUT_MS:
                    raise CtapError(USER_ACTION_TIMEOUT)
            raise CtapError(OPERATION_DENIED)
        self.policy.take_authorization(key)
        return key


class Reset(PresenceOnly):
    def __init__(self, policy, auth=None, random_bytes=None, ticks_ms=None,
                 started_ms=None) -> None:
        super().__init__(policy, auth, random_bytes)
        self._ticks_ms = ticks_ms
        self._started_ms = started_ms

    def _now(self):
        if self._ticks_ms is not None:
            return self._ticks_ms()
        from utime import ticks_ms

        return ticks_ms()

    async def handle(self, request, context):
        if self._started_ms is None:
            # Nobody said when this device powered up, so the window cannot be
            # shown to be open. Refusing is the only answer that cannot be wrong;
            # the transport supplies the reference on the path that matters.
            raise CtapError(NOT_ALLOWED)
        if (self._now() - self._started_ms) & _TICKS_MASK >= RESET_WINDOW_MS:
            raise CtapError(NOT_ALLOWED)

        auth = self._vault()
        await self._edge(context, self._now)
        if auth.wipe() != auth.OK:
            # The vault refused to destroy itself. Saying OK here would leave a
            # person believing their credentials were gone when they are not.
            raise CtapError(OTHER)
        # Reset has no response data.
        return None


class Selection(PresenceOnly):
    async def handle(self, request, context):
        """Answer "this one" to a person choosing among attached keys."""
        await self._edge(context)
        return None


def register(dispatcher, auth=None, random_bytes=None, ticks_ms=None,
             started_ms=None) -> None:
    dispatcher.register(
        RESET_COMMAND,
        Reset(dispatcher.policy, auth, random_bytes, ticks_ms, started_ms).handle,
    )
    dispatcher.register(
        SELECTION_COMMAND,
        Selection(dispatcher.policy, auth, random_bytes).handle,
    )
