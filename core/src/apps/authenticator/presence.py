"""Physical confirmation: one fresh, debounced insertion and nothing else.

This board has no button. The only inputs a person can reach are the touchscreen,
which this firmware leaves out entirely, and the microSD card-detect line, which
is what a confirmation is here: put a card in, and the operation that was waiting
goes through. Once.

The rules below are what make that a confirmation rather than a level check.

A card already in the slot is not a confirmation. The wait arms itself from a
level it has seen go empty, so a card left in place authorizes nothing -- the
person has to take it out and put it back. That is also what makes one insertion
pay for exactly one operation: after it is spent the level is PRESENT, and the
next operation needs another removal first.

A reading counts only once it has held. A mechanical contact chatters as it
closes, and an undebounced line would report several insertions for one gesture,
which is one gesture paying for several operations.

A reading that cannot be trusted is refused rather than waited through. The
native sampler reports a fault for a line it never configured, and a fault is not
an absence: waiting through it would sit out the full timeout for a card that can
never register.
"""

# One reading of the line, mirroring the native enum. Compared by value, so these
# have to stay in step with io/auth_presence.h.
ABSENT = 0
PRESENT = 1
FAULT = 2

# How long a level has to hold before it counts. Long enough to outlast the
# chatter of a card seating in its slot, short enough that a person does not
# notice it. A gesture is held for something closer to a second.
DEBOUNCE_MS = 40

# utime.ticks_ms() is free to wrap. Masking the difference the way the policy does
# keeps a wrap from making an interval look negative or enormous.
_TICKS_MASK = (1 << 30) - 1

_NOTHING = 0
_EDGE = 1
_FAULTED = -1


class PresenceProvider:
    """Fail-closed. Denies every confirmation, and is the default everywhere."""

    async def wait_for_fresh_edge(self, key, timeout_ms: int) -> bool:
        return False

    def clear(self) -> None:
        pass


class AssumedPresenceProvider(PresenceProvider):
    """Confirms everything, because this build has no way to ask.

    This board's only gesture is the microSD line, and until that is wired up and
    observed on silicon a device that insists on a gesture cannot be used at all.
    So a build may declare that presence is assumed, and this provider grants it.

    What is given up is exactly one thing, and it is worth naming: an operation is
    no longer proof that a person was there. The PIN is still required for every
    credential operation, so software cannot act without the PIN -- but software
    that has the PIN can act without anybody present, which is what a gesture
    exists to prevent.

    What stops this from becoming the shipped behaviour is not a comment. The
    production build refuses to compile it, the image audit refuses to certify an
    image carrying it, and GetInfo reports a different device identity so a
    platform can tell the difference before it enrolls anything.
    """

    async def wait_for_fresh_edge(self, key, timeout_ms: int) -> bool:
        return True

    def clear(self) -> None:
        pass


class HardwarePresenceProvider(PresenceProvider):
    """The card-detect line, debounced, one confirmation per insertion."""

    def __init__(self, sample=None, ticks_ms=None, checkpoint=None) -> None:
        self._sample = sample
        self._ticks_ms = ticks_ms
        self._checkpoint = checkpoint
        self.key = None
        self._ticket = None
        # None means "not established yet". The first level a reading settles on
        # is therefore never a transition, which is what keeps a pre-inserted card
        # from counting.
        self._level = None
        self._candidate = None
        self._candidate_since = 0

    def _read(self) -> int:
        if self._sample is not None:
            return self._sample()
        import trezorauth

        return trezorauth.presence_sample()

    def _now(self) -> int:
        if self._ticks_ms is not None:
            return self._ticks_ms()
        from utime import ticks_ms

        return ticks_ms()

    async def _wait(self) -> None:
        if self._checkpoint is not None:
            return await self._checkpoint()
        from trezor.loop import checkpoint

        return await checkpoint()

    def _advance(self, now: int) -> int:
        """Fold one reading into the debounced level.

        Returns `_EDGE` for a fresh insertion, `_FAULTED` for a reading that
        cannot be trusted, `_NOTHING` otherwise.
        """
        sample = self._read()
        if sample != ABSENT and sample != PRESENT:
            # Anything that is not one of the two levels is a fault, including a
            # value this code does not recognise. Forgetting the level means
            # recovery needs a confirmed empty slot again rather than resuming
            # from whatever was believed before the line broke.
            self._level = None
            self._candidate = None
            return _FAULTED
        if sample != self._candidate:
            self._candidate = sample
            self._candidate_since = now
            return _NOTHING
        if (now - self._candidate_since) & _TICKS_MASK < DEBOUNCE_MS:
            return _NOTHING
        if sample == self._level:
            return _NOTHING
        previous = self._level
        self._level = sample
        # A confirmation is a transition out of a level that was seen to be empty.
        # PRESENT arrived at from an unknown level is a card that was already
        # there when the wait began.
        return _EDGE if sample == PRESENT and previous == ABSENT else _NOTHING

    async def wait_for_fresh_edge(self, key, timeout_ms: int) -> bool:
        if self.key is not None:
            # One wait at a time. A second transaction asking to share the line
            # would let one insertion authorize two operations.
            return False
        ticket = object()
        self.key = key
        self._ticket = ticket
        self._candidate = None
        self._candidate_since = 0
        start = self._now()
        try:
            while self._ticket is ticket:
                now = self._now()
                if (now - start) & _TICKS_MASK >= timeout_ms:
                    return False
                state = self._advance(now)
                if state:
                    return state == _EDGE
                await self._wait()
            # The transaction this wait belonged to was cleared under it.
            return False
        finally:
            if self._ticket is ticket:
                self.clear()

    def clear(self) -> None:
        self.key = None
        self._ticket = None
        self._candidate = None
        self._candidate_since = 0
        # The debounced level deliberately survives. A card still in the slot
        # cannot become a confirmation for whatever runs next.


def presence_is_assumed(auth) -> bool:
    """Whether this build confirms operations without asking anybody.

    Read from the module the image actually contains, so the answer is a property
    of the artifact rather than of a flag somebody remembered to pass.
    """
    return bool(getattr(auth, "ASSUMED_PRESENCE", False))


def default_provider() -> PresenceProvider:
    """The provider this image actually has.

    Decided by what the image contains rather than by a flag: a build that declares
    presence assumed confirms without asking, a build with the native sampler reads
    the line, and anything else -- the host test environment, or a build where the
    driver was left out -- gets the fail-closed base. A build without a line to read
    cannot be talked into believing it has one.
    """
    try:
        import trezorauth
    except ImportError:
        return PresenceProvider()
    if presence_is_assumed(trezorauth):
        # Checked before the sampler, so a build in this mode does not depend on
        # the line at all and a broken line cannot make it refuse.
        return AssumedPresenceProvider()
    if not hasattr(trezorauth, "presence_sample"):
        return PresenceProvider()
    return HardwarePresenceProvider(trezorauth.presence_sample)
