"""The confirmation line, fed timestamped readings.

Everything here is about what does not count as a confirmation: a card already in
the slot, the chatter of one seating in it, a second insertion for an operation
that already got one, a reading that cannot be trusted, and a second transaction
hoping to share the gesture. The one thing that does count is a card going in
after the line was seen to be empty, and it counts exactly once.
"""

import asyncio
import os
import sys
import types

sys.path.remove(os.path.dirname(__file__))
import unittest

# The fallback clock is a device module. It is stubbed rather than avoided,
# because the provider a firmware gets when nobody injects anything is exactly
# what the last tests here are about.
sys.modules["utime"] = types.SimpleNamespace(ticks_ms=lambda: 0)

from apps.authenticator.presence import (
    ABSENT, DEBOUNCE_MS, FAULT, PRESENT, AssumedPresenceProvider,
    HardwarePresenceProvider, PresenceProvider, default_provider,
)
from apps.authenticator.policy import Policy, TransactionKey

GENERATION = 3
CID = 7
NONCE = bytes(32)
TIMEOUT_MS = 30000

# The debounce window, as this suite assumes it. Written out rather than
# imported: every script and every deadline below is built from it, so taking
# it from the module would let a change to the window quietly rescale the
# tests that are supposed to notice.
WINDOW = 40


def key(generation=GENERATION, cid=CID, nonce=NONCE):
    return TransactionKey(generation, cid, nonce)


class Line:
    """A card-detect line whose level and clock the test drives by hand.

    Each poll advances the clock by one millisecond, so a level has to be held
    across `WINDOW` polls to be believed -- which is what makes the bounce
    cases below real rather than notional.
    """

    def __init__(self, level=ABSENT, step=1):
        self.level = level
        self.now = 0
        self.step = step
        self.reads = 0
        self.script = []

    def sample(self):
        self.reads += 1
        if self.script:
            self.level = self.script.pop(0)
        return self.level

    def ticks(self):
        return self.now

    async def checkpoint(self):
        self.now += self.step
        await asyncio.sleep(0)


class PresenceTests(unittest.TestCase):
    def provider(self, line):
        return HardwarePresenceProvider(line.sample, line.ticks, line.checkpoint)

    def wait(self, provider, timeout_ms=TIMEOUT_MS, transaction=None):
        return asyncio.run(
            provider.wait_for_fresh_edge(
                transaction if transaction is not None else key(), timeout_ms
            )
        )

    def settle(self, line, provider, level, transaction=None):
        """Hold a level long enough for it to be believed, without a wait."""
        line.level = level
        # A short wait that cannot reach the timeout, used only to feed readings.
        self.wait(provider, WINDOW * 4, transaction)

    # -- the window itself ----------------------------------------------------
    def test_the_debounce_window_is_the_one_the_tests_assume(self):
        # Part of the contract rather than a tuning knob: shorter and a seating
        # card's chatter starts counting as several insertions, longer and a person
        # notices the lag.
        self.assertEqual(DEBOUNCE_MS, WINDOW)

    # -- what counts ----------------------------------------------------------
    def test_a_card_going_in_after_an_empty_line_is_a_confirmation(self):
        line = Line(ABSENT)
        provider = self.provider(line)
        # Empty for long enough to be believed, then inserted.
        line.script = [ABSENT] * (WINDOW + 2) + [PRESENT] * 200
        self.assertTrue(self.wait(provider))

    def test_the_confirmation_needs_the_level_to_hold(self):
        line = Line(ABSENT)
        provider = self.provider(line)
        # Settles empty, then a burst of three readings that agree with each other
        # and still fall well short of the debounce window. Three rather than one
        # on purpose: a single stray reading never repeats, so a provider with no
        # debounce at all would refuse it for the wrong reason and look correct.
        line.script = ([ABSENT] * (WINDOW + 2) + [PRESENT] * 3
                       + [ABSENT] * 400)
        self.assertFalse(self.wait(provider, WINDOW * 6))

    def test_a_burst_too_short_to_count_does_not_spend_the_gesture(self):
        # The other half of the same rule: a burst that was rightly ignored must
        # not have consumed anything either, so the insertion that follows still
        # counts.
        line = Line(ABSENT)
        provider = self.provider(line)
        line.script = ([ABSENT] * (WINDOW + 2) + [PRESENT] * 3
                       + [ABSENT] * (WINDOW + 2) + [PRESENT] * 200)
        self.assertTrue(self.wait(provider))

    def test_chatter_while_a_card_seats_is_one_confirmation_not_several(self):
        line = Line(ABSENT)
        provider = self.provider(line)
        bounce = [PRESENT, ABSENT, PRESENT, ABSENT, PRESENT, ABSENT] * 3
        line.script = ([ABSENT] * (WINDOW + 2) + bounce
                       + [PRESENT] * 200)
        self.assertTrue(self.wait(provider))
        # The gesture is spent. Holding the same card in gives nothing more.
        line.script = [PRESENT] * 400
        self.assertFalse(self.wait(provider, WINDOW * 6))

    # -- what does not count --------------------------------------------------
    def test_a_card_already_in_the_slot_is_not_a_confirmation(self):
        line = Line(PRESENT)
        provider = self.provider(line)
        line.script = [PRESENT] * 400
        self.assertFalse(self.wait(provider, WINDOW * 6))

    def test_a_card_left_in_has_to_come_out_before_it_counts_again(self):
        line = Line(ABSENT)
        provider = self.provider(line)
        line.script = [ABSENT] * (WINDOW + 2) + [PRESENT] * 200
        self.assertTrue(self.wait(provider))
        # Still in: nothing.
        line.script = [PRESENT] * 400
        self.assertFalse(self.wait(provider, WINDOW * 6))
        # Out, then in again: a confirmation.
        line.script = ([ABSENT] * (WINDOW + 2) + [PRESENT] * 200)
        self.assertTrue(self.wait(provider))

    def test_a_removal_is_not_a_confirmation(self):
        line = Line(PRESENT)
        provider = self.provider(line)
        line.script = [PRESENT] * (WINDOW + 2) + [ABSENT] * 400
        self.assertFalse(self.wait(provider, WINDOW * 8))

    def test_rapid_cycles_produce_one_confirmation_per_wait(self):
        line = Line(ABSENT)
        provider = self.provider(line)
        cycle = [ABSENT] * (WINDOW + 2) + [PRESENT] * (WINDOW + 2)
        line.script = cycle * 4 + [PRESENT] * 100
        self.assertTrue(self.wait(provider))
        # The rest of the cycles are still in the script, but they belong to no
        # wait: only a wait can turn a transition into a confirmation.
        self.assertFalse(self.wait(provider, WINDOW))

    def test_a_reading_that_cannot_be_trusted_is_refused_at_once(self):
        line = Line(FAULT)
        provider = self.provider(line)
        line.script = [FAULT] * 400
        self.assertFalse(self.wait(provider))
        # Refused immediately rather than waited through: one reading was enough.
        self.assertEqual(line.reads, 1)

    def test_an_unknown_reading_is_a_fault_rather_than_an_absence(self):
        line = Line(99)
        provider = self.provider(line)
        self.assertFalse(self.wait(provider))
        self.assertEqual(line.reads, 1)

    def test_a_fault_forgets_the_level_so_recovery_needs_an_empty_line(self):
        line = Line(ABSENT)
        provider = self.provider(line)
        # An empty line, believed, then the line breaks.
        line.script = [ABSENT] * (WINDOW + 2) + [FAULT]
        self.assertFalse(self.wait(provider, WINDOW * 6))
        # A card appearing now is a level arrived at from nothing known, so it is
        # not a confirmation even though the line was empty a moment ago.
        line.script = [PRESENT] * 400
        self.assertFalse(self.wait(provider, WINDOW * 6))
        # Emptiness has to be established again first.
        line.script = [ABSENT] * (WINDOW + 2) + [PRESENT] * 200
        self.assertTrue(self.wait(provider))

    def test_a_wait_that_runs_out_reports_no_confirmation(self):
        line = Line(ABSENT)
        provider = self.provider(line)
        line.script = [ABSENT] * 400
        self.assertFalse(self.wait(provider, 50))
        # And it stopped at the deadline rather than reading forever.
        self.assertLessEqual(line.reads, 51)

    def test_a_zero_length_wait_reads_nothing(self):
        line = Line(ABSENT)
        provider = self.provider(line)
        self.assertFalse(self.wait(provider, 0))
        self.assertEqual(line.reads, 0)

    def test_the_line_is_not_shared_by_two_transactions(self):
        line = Line(ABSENT)
        provider = self.provider(line)
        first = key()
        second = key(cid=CID + 1)

        async def race():
            line.script = [ABSENT] * (WINDOW + 2) + [PRESENT] * 200
            task = asyncio.create_task(
                provider.wait_for_fresh_edge(first, TIMEOUT_MS)
            )
            await asyncio.sleep(0)
            # One insertion must not pay for two operations.
            self.assertFalse(
                await provider.wait_for_fresh_edge(second, TIMEOUT_MS)
            )
            return await task

        self.assertTrue(asyncio.run(race()))

    def test_clearing_a_wait_ends_it_without_a_confirmation(self):
        line = Line(ABSENT)
        provider = self.provider(line)

        async def interrupted():
            line.script = [ABSENT] * (WINDOW + 2) + [PRESENT] * 200
            task = asyncio.create_task(
                provider.wait_for_fresh_edge(key(), TIMEOUT_MS)
            )
            await asyncio.sleep(0)
            provider.clear()
            return await task

        self.assertFalse(asyncio.run(interrupted()))
        self.assertIsNone(provider.key)

    def test_a_cleared_wait_leaves_the_level_behind(self):
        # Which is what keeps a card that was inserted during an abandoned wait
        # from authorizing whatever runs next.
        line = Line(ABSENT)
        provider = self.provider(line)
        line.script = [ABSENT] * (WINDOW + 2) + [PRESENT] * 200
        self.assertTrue(self.wait(provider))
        provider.clear()
        line.script = [PRESENT] * 400
        self.assertFalse(self.wait(provider, WINDOW * 6))

    def test_a_slot_already_known_to_be_empty_takes_the_first_insertion(self):
        # The debounced level outlives a wait, so a person who has already taken
        # the card out does not have to take it out again. Forgetting the level
        # between waits would demand a second removal nobody asked for.
        line = Line(ABSENT)
        provider = self.provider(line)
        line.script = [ABSENT] * (WINDOW + 2) + [PRESENT] * 200
        self.assertTrue(self.wait(provider))
        # A wait that sees the card come out, and runs out before anything else.
        line.script = [ABSENT] * 400
        self.assertFalse(self.wait(provider, WINDOW + 4))
        # Emptiness is established, so this insertion counts straight away.
        line.script = [PRESENT] * 200
        self.assertTrue(self.wait(provider))

    def test_the_wait_survives_a_tick_counter_wrap(self):
        line = Line(ABSENT)
        line.now = (1 << 30) - WINDOW
        provider = self.provider(line)
        line.script = [ABSENT] * (WINDOW + 2) + [PRESENT] * 200

        original = line.ticks

        def wrapping():
            return original() & ((1 << 30) - 1)

        line.ticks = wrapping
        provider = HardwarePresenceProvider(line.sample, wrapping,
                                            line.checkpoint)
        self.assertTrue(self.wait(provider))

    def test_the_deadline_still_expires_across_a_tick_counter_wrap(self):
        # The masked subtraction is the whole of this. Unmasked, an interval that
        # spans the wrap reads as a large negative number, the wait never reaches
        # its deadline, and a transaction nobody confirmed holds the channel for as
        # long as the device stays plugged in.
        line = Line(ABSENT)
        line.now = (1 << 30) - 10

        def wrapping():
            return line.now & ((1 << 30) - 1)

        provider = HardwarePresenceProvider(line.sample, wrapping,
                                            line.checkpoint)
        line.script = [ABSENT] * 400
        self.assertFalse(asyncio.run(provider.wait_for_fresh_edge(key(), 50)))
        self.assertLessEqual(line.reads, 51)

    # -- a build that has nothing to ask --------------------------------------
    def test_a_build_that_assumes_presence_confirms_without_asking(self):
        # The gesture this board has is not wired up yet, and a device that insists
        # on one cannot be used at all. A build may say so, and then it confirms.
        sys.modules["trezorauth"] = types.SimpleNamespace(ASSUMED_PRESENCE=True)
        try:
            provider = default_provider()
            self.assertIs(type(provider), AssumedPresenceProvider)
            self.assertTrue(
                asyncio.run(provider.wait_for_fresh_edge(key(), 1000))
            )
            # And again: there is no one-shot rule to spend, because there was
            # never a gesture to spend.
            self.assertTrue(
                asyncio.run(provider.wait_for_fresh_edge(key(), 1000))
            )
        finally:
            sys.modules.pop("trezorauth", None)

    def test_assuming_presence_does_not_read_the_line_at_all(self):
        # Checked before the sampler, so a broken or absent line cannot make this
        # build refuse. That is the point of it.
        reads = []

        def sample():
            reads.append(1)
            return FAULT

        sys.modules["trezorauth"] = types.SimpleNamespace(
            ASSUMED_PRESENCE=True, presence_sample=sample
        )
        try:
            self.assertTrue(
                asyncio.run(default_provider().wait_for_fresh_edge(key(), 1000))
            )
            self.assertEqual(reads, [])
        finally:
            sys.modules.pop("trezorauth", None)

    def test_a_build_that_does_not_declare_it_still_reads_the_line(self):
        # Absence of the flag, and anything falsy in its place, means ask.
        for flag in (False, 0, None):
            sys.modules["trezorauth"] = types.SimpleNamespace(
                ASSUMED_PRESENCE=flag, presence_sample=lambda: FAULT
            )
            try:
                with self.subTest(flag=flag):
                    self.assertIs(
                        type(default_provider()), HardwarePresenceProvider
                    )
            finally:
                sys.modules.pop("trezorauth", None)

    def test_a_policy_in_that_build_gets_the_assuming_provider(self):
        sys.modules["trezorauth"] = types.SimpleNamespace(ASSUMED_PRESENCE=True)
        try:
            self.assertIs(type(Policy().presence), AssumedPresenceProvider)
        finally:
            sys.modules.pop("trezorauth", None)

    # -- which provider a firmware gets --------------------------------------
    def test_a_build_without_the_native_sampler_denies_everything(self):
        sys.modules.pop("trezorauth", None)
        provider = default_provider()
        self.assertIs(type(provider), PresenceProvider)
        self.assertFalse(asyncio.run(provider.wait_for_fresh_edge(key(), 1000)))

    def test_a_vault_without_a_sampler_is_not_mistaken_for_a_line(self):
        sys.modules["trezorauth"] = types.SimpleNamespace(OK=0)
        try:
            self.assertIs(type(default_provider()), PresenceProvider)
        finally:
            sys.modules.pop("trezorauth", None)

    def test_a_build_with_the_native_sampler_reads_the_line(self):
        readings = []

        def sample():
            readings.append(1)
            return FAULT

        sys.modules["trezorauth"] = types.SimpleNamespace(
            presence_sample=sample
        )
        try:
            provider = default_provider()
            self.assertIs(type(provider), HardwarePresenceProvider)
            self.assertFalse(
                asyncio.run(provider.wait_for_fresh_edge(key(), 1000))
            )
            self.assertEqual(len(readings), 1)
        finally:
            sys.modules.pop("trezorauth", None)

    def test_a_policy_with_no_provider_falls_back_to_the_fail_closed_one(self):
        sys.modules.pop("trezorauth", None)
        policy = Policy()
        self.assertIs(type(policy.presence), PresenceProvider)

    def test_a_policy_on_a_device_reads_the_line(self):
        # The other half of the same rule. A policy that fell back to the base
        # class on a device would refuse every operation on hardware while every
        # test that injects a provider stayed green.
        sys.modules["trezorauth"] = types.SimpleNamespace(
            presence_sample=lambda: FAULT
        )
        try:
            self.assertIs(type(Policy().presence), HardwarePresenceProvider)
        finally:
            sys.modules.pop("trezorauth", None)


if __name__ == "__main__":
    unittest.main()
