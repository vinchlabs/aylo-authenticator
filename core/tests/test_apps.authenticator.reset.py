"""Reset's ten-second window, and Selection.

Reset is the one command that destroys everything, and on a device with no
display the ten-second window is the whole of its protection against a remote
one. So the assertions here are mostly about when it refuses: too late, no
reference at all, no gesture, a gesture that never came, and a vault that would
not do it.
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

from apps.authenticator import reset
from apps.authenticator.dispatcher import Dispatcher, default_dispatcher
from apps.authenticator.policy import Policy, TransactionKey
from apps.authenticator.presence import PresenceProvider
from apps.authenticator.transport_types import TransportEvent

sys.modules["trezorio"] = types.SimpleNamespace(AUTH_TEST_PRESENCE=True)
from apps.authenticator.test_presence import TestPresenceProvider
del sys.modules["trezorio"]


class Vault:
    OK = 0
    UNPROVISIONED = 1
    ERROR = 7

    def __init__(self, wipes=OK):
        self.calls = []
        self._wipes = wipes

    def wipe(self):
        self.calls.append("wipe")
        return self._wipes


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


class ResetTests(unittest.TestCase):
    def setUp(self):
        self.clock = Clock()
        self.presence = TestPresenceProvider(self.clock.ticks, self.clock.checkpoint)
        self.vault = Vault()
        self.dispatcher = Dispatcher()
        self.dispatcher.policy = Policy(self.presence, self.clock.ticks)
        reset.register(self.dispatcher, self.vault, lambda n: bytes(n),
                       ticks_ms=self.clock.ticks, started_ms=0)

    def send(self, command, edge=True, at=None):
        event = TransportEvent(GENERATION, CID, 0x90, bytes((command,)))
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

    def wrapped_dispatcher(self):
        """A dispatcher whose power-up reference sits five ticks before the wrap."""
        dispatcher = Dispatcher()
        dispatcher.policy = Policy(self.presence, self.clock.ticks)
        reset.register(dispatcher, self.vault, lambda n: bytes(n),
                       ticks_ms=self.clock.ticks, started_ms=(1 << 30) - 5)
        return dispatcher

    # -- the window -----------------------------------------------------------
    def test_a_reset_inside_the_window_wipes_everything(self):
        self.clock.now = 9999
        self.assertEqual(self.send(7), b"\x00")
        self.assertEqual(self.vault.calls, ["wipe"])

    def test_a_reset_at_the_deadline_is_too_late(self):
        self.clock.now = 10000
        self.assertEqual(self.send(7), b"\x30")
        self.assertEqual(self.vault.calls, [])

    def test_a_reset_long_after_power_up_is_too_late(self):
        self.clock.now = 60000
        self.assertEqual(self.send(7, edge=False), b"\x30")
        self.assertEqual(self.vault.calls, [])
        # Refused before anyone was asked for a gesture.
        self.assertIsNone(self.presence.key)

    def test_without_a_power_up_reference_a_reset_is_refused(self):
        # A window that cannot be shown to be open must not be treated as open.
        dispatcher = Dispatcher()
        dispatcher.policy = Policy(self.presence, self.clock.ticks)
        reset.register(dispatcher, self.vault, lambda n: bytes(n),
                       ticks_ms=self.clock.ticks, started_ms=None)
        event = TransportEvent(GENERATION, CID, 0x90, b"\x07")
        self.assertEqual(asyncio.run(dispatcher.dispatch(event)), b"\x30")
        self.assertEqual(self.vault.calls, [])

    def test_the_window_stays_open_across_a_tick_counter_wrap(self):
        self.dispatcher = self.wrapped_dispatcher()
        self.clock.now = 5          # five milliseconds later, past the wrap
        self.assertEqual(self.send(7), b"\x00")
        self.assertEqual(self.vault.calls, ["wipe"])

    def test_the_window_still_closes_across_a_tick_counter_wrap(self):
        # The masked subtraction is the whole of this. Unmasked, an interval that
        # spans the wrap reads as a large negative number, nothing is ever ten
        # seconds old again, and the window stays open for as long as the device
        # stays plugged in -- which is exactly the remote reset it exists to stop.
        self.dispatcher = self.wrapped_dispatcher()
        self.clock.now = 10000      # 10005 ms after power-up, across the wrap
        self.assertEqual(self.send(7, edge=False), b"\x30")
        self.assertEqual(self.vault.calls, [])

    # -- the gesture ----------------------------------------------------------
    def test_a_refused_gesture_destroys_nothing(self):
        dispatcher = Dispatcher()
        dispatcher.policy = Policy(PresenceProvider(), self.clock.ticks)
        reset.register(dispatcher, self.vault, lambda n: bytes(n),
                       ticks_ms=self.clock.ticks, started_ms=0)
        event = TransportEvent(GENERATION, CID, 0x90, b"\x07")
        self.assertEqual(asyncio.run(dispatcher.dispatch(event)), b"\x27")
        self.assertEqual(self.vault.calls, [])
        self.assertIsNone(dispatcher.policy.key)

    def test_a_gesture_that_never_came_is_a_timeout_not_a_refusal(self):
        # The specification asks for these to be told apart, and the only signal
        # at this layer is the clock: the waiter that ran to the deadline reports
        # a timeout, the one turned down at once reports a refusal.
        self.assertEqual(self.send(7, edge=False), b"\x3a")
        self.assertEqual(self.vault.calls, [])

    def test_the_grant_is_consumed_before_the_wipe(self):
        order = []
        original = self.dispatcher.policy.take_authorization

        def take(key):
            order.append("take")
            return original(key)

        self.dispatcher.policy.take_authorization = take
        wipe = self.vault.wipe

        def wiped():
            order.append("wipe")
            return wipe()

        self.vault.wipe = wiped
        self.assertEqual(self.send(7), b"\x00")
        self.assertEqual(order, ["take", "wipe"])

    def test_a_vault_that_will_not_wipe_is_not_reported_as_success(self):
        # Answering OK would leave a person believing their credentials are gone.
        self.vault = Vault(wipes=Vault.ERROR)
        self.dispatcher = Dispatcher()
        self.dispatcher.policy = Policy(self.presence, self.clock.ticks)
        reset.register(self.dispatcher, self.vault, lambda n: bytes(n),
                       ticks_ms=self.clock.ticks, started_ms=0)
        self.assertEqual(self.send(7), b"\x7f")
        self.assertEqual(self.vault.calls, ["wipe"])

    # -- selection ------------------------------------------------------------
    def test_selection_answers_to_a_gesture_and_touches_nothing(self):
        self.assertEqual(self.send(11), b"\x00")
        self.assertEqual(self.vault.calls, [])
        self.assertIsNone(self.dispatcher.policy.key)

    def test_selection_without_a_gesture_is_denied(self):
        dispatcher = Dispatcher()
        dispatcher.policy = Policy(PresenceProvider(), self.clock.ticks)
        reset.register(dispatcher, self.vault, lambda n: bytes(n),
                       ticks_ms=self.clock.ticks, started_ms=0)
        event = TransportEvent(GENERATION, CID, 0x90, b"\x0b")
        self.assertEqual(asyncio.run(dispatcher.dispatch(event)), b"\x27")

    def test_selection_ignores_the_reset_window(self):
        # It destroys nothing, so being late is not a reason to refuse it.
        self.clock.now = 60000
        self.assertEqual(self.send(11), b"\x00")

    def test_a_body_on_either_command_is_rejected(self):
        for command in (b"\x07", b"\x0b"):
            event = TransportEvent(GENERATION, CID, 0x90, command + b"\xa0")
            self.assertEqual(asyncio.run(self.dispatcher.dispatch(event)), b"\x02")
        self.assertEqual(self.vault.calls, [])

    # -- wiring ---------------------------------------------------------------
    def test_the_firmware_serves_the_whole_surface_it_implements(self):
        dispatcher = default_dispatcher(started_ms=0)
        self.assertEqual(sorted(dispatcher._handlers),
                         [1, 2, 4, 6, 7, 8, 10, 11, 65])
        # Every CTAP command the decoder accepts now has a handler, so the only
        # command left without one is a command the dispatcher refuses outright.
        event = TransportEvent(GENERATION, CID, 0x90, b"\x09")
        self.assertEqual(asyncio.run(dispatcher.dispatch(event)), b"\x01")

    def test_a_dispatcher_given_no_reference_still_serves_the_rest(self):
        dispatcher = default_dispatcher()
        self.assertEqual(sorted(dispatcher._handlers),
                         [1, 2, 4, 6, 7, 8, 10, 11, 65])


if __name__ == "__main__":
    unittest.main()
