"""Explicit emulator events only; excluded from normal frozen module sets."""

from trezorio import AUTH_TEST_PRESENCE

from .presence import PresenceProvider

if not AUTH_TEST_PRESENCE:
    raise ImportError("test presence is emulator-only")


class TestPresenceProvider(PresenceProvider):
    def __init__(self, ticks_ms=None, checkpoint=None) -> None:
        if ticks_ms is None:
            from utime import ticks_ms
        if checkpoint is None:
            from trezor.loop import checkpoint
        self._ticks_ms = ticks_ms
        self._checkpoint = checkpoint
        self.key = None
        self._ticket = None
        self._edge = None
        self._inserted = False

    def test_event(self, key, inserted: bool) -> bool:
        # Pre-inserted cards/early events establish a level, never a queued edge.
        # Wrong-transaction events cannot change the active provider's level.
        if self.key is not None and key != self.key:
            return False
        rising = inserted and not self._inserted
        self._inserted = bool(inserted)
        if self.key is None or not rising or self._edge is not None:
            return False
        self._edge = self._ticket
        return True

    async def wait_for_fresh_edge(self, key, timeout_ms: int) -> bool:
        if self.key is not None:
            return False
        ticket = object()
        self.key = key
        self._ticket = ticket
        self._edge = None
        start = self._ticks_ms()
        try:
            while self._ticket is ticket:
                elapsed = (self._ticks_ms() - start) & ((1 << 30) - 1)
                if elapsed >= timeout_ms:
                    return False
                if self._edge is ticket:
                    return True
                await self._checkpoint()
            return False
        finally:
            if self._ticket is ticket:
                self.clear()

    def clear(self) -> None:
        self.key = None
        self._ticket = None
        self._edge = None
        # Keep physical level: a held/pre-inserted event cannot become a new edge.
