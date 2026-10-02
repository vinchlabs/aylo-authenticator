"""Policy ownership, fresh edges, and cleanup regressions (no hardware)."""

import asyncio
import os
import sys
import types

sys.path.remove(os.path.dirname(__file__))
import unittest

from apps.authenticator.policy import USED, Policy, PolicyError, TransactionKey
from apps.authenticator.presence import PresenceProvider

# Only the emulator's explicit compile-time switch makes this module usable.
sys.modules["trezorio"] = types.SimpleNamespace(AUTH_TEST_PRESENCE=True)
from apps.authenticator.test_presence import TestPresenceProvider
del sys.modules["trezorio"]

from apps.authenticator.dispatcher import Dispatcher
from apps.authenticator.transport import HidAssembler, handle_reports
from apps.authenticator.transport_types import TransportEvent


def key(generation=3, cid=7, nonce=b"a" * 32):
    return TransactionKey(generation, cid, nonce)


class Clock:
    def __init__(self):
        self.now = 0

    def ticks(self):
        return self.now

    async def checkpoint(self):
        self.now += 1
        await asyncio.sleep(0)


class PolicyTests(unittest.TestCase):
    def setUp(self):
        self.clock = Clock()
        self.presence = TestPresenceProvider(self.clock.ticks, self.clock.checkpoint)
        self.policy = Policy(self.presence, self.clock.ticks)
        self.key = key()
        self.rp = b"r" * 32

    def begin(self):
        self.policy.begin(self.key, 2, self.rp)

    def pin(self):
        token = bytearray(b"pin token")
        self.policy.authorize_pin(self.key, 2, self.rp, token)
        return token

    async def edge(self):
        task = asyncio.create_task(self.policy.consume_presence(self.key, 20))
        await asyncio.sleep(0)
        self.assertTrue(self.presence.test_event(self.key, True))
        await task

    def test_pin_precedes_presence_and_edge_authorizes_one_operation(self):
        self.begin()
        with self.assertRaises(PolicyError):
            asyncio.run(self.policy.consume_presence(self.key, 20))
        token = self.pin()
        asyncio.run(self.edge())
        self.policy.take_authorization(self.key)
        with self.assertRaises(PolicyError):
            self.policy.take_authorization(self.key)
        self.policy.finish(self.key)
        self.assertEqual(token, bytearray(9))
        self.assertIsNone(self.policy.key)

    def test_pin_grants_reject_wrong_permission_rp_generation_channel_nonce(self):
        for bad_key, permission, rp in ((key(4), 2, self.rp), (key(cid=8), 2, self.rp),
                                        (key(nonce=b"b" * 32), 2, self.rp),
                                        (self.key, 1, self.rp), (self.key, 2, b"x" * 32)):
            self.begin()
            token = bytearray(b"secret")
            with self.assertRaises(PolicyError):
                self.policy.authorize_pin(bad_key, permission, rp, token)
            self.assertEqual(token, bytearray(6))
            self.policy.abort("test")

    def test_busy_begin_cannot_steal_transaction_or_edge(self):
        self.begin()
        self.pin()
        with self.assertRaises(PolicyError):
            self.policy.begin(key(cid=8), 2, self.rp)
        async def race():
            first = asyncio.create_task(self.policy.consume_presence(self.key, 20))
            await asyncio.sleep(0)
            with self.assertRaises(PolicyError):
                await self.policy.consume_presence(self.key, 20)
            self.assertFalse(self.presence.test_event(key(cid=8), True))
            self.assertTrue(self.presence.test_event(self.key, True))
            await first
        asyncio.run(race())
        self.policy.take_authorization(self.key)

    def test_preinserted_and_early_events_are_not_fresh(self):
        self.assertFalse(self.presence.test_event(self.key, True))
        self.begin()
        token = self.pin()
        async def check():
            task = asyncio.create_task(self.policy.consume_presence(self.key, 20))
            await asyncio.sleep(0)
            self.assertFalse(self.presence.test_event(self.key, True))
            self.assertFalse(self.presence.test_event(self.key, False))
            self.assertTrue(self.presence.test_event(self.key, True))
            await task
        asyncio.run(check())
        self.policy.finish(self.key)
        self.assertEqual(token, bytearray(9))

    def test_timeout_and_all_abort_reasons_erase_buffers_and_references(self):
        for reason in ("cancel", "timeout", "usb-reset", "disconnect", "reboot", "exception", "channel-change"):
            self.begin()
            token = self.pin()
            secret = bytearray(b"derived key")
            self.policy.retain(self.key, secret)
            self.policy.abort(reason)
            self.assertEqual(token, bytearray(9))
            self.assertEqual(secret, bytearray(11))
            self.assertIsNone(self.policy.key)
            self.assertIsNone(self.policy.rp_id_hash)
            self.assertEqual(self.policy.buffers, [])
            self.assertIsNone(self.presence.key)
        self.begin()
        token = self.pin()
        with self.assertRaises(PolicyError):
            asyncio.run(self.policy.consume_presence(self.key, 2))
        self.assertIsNone(self.policy.key)
        self.assertEqual(token, bytearray(9))

    def test_abort_pending_wait_cannot_authorize_replacement(self):
        self.begin()
        old_token = self.pin()
        async def cancel():
            task = asyncio.create_task(self.policy.consume_presence(self.key, 20))
            await asyncio.sleep(0)
            self.policy.abort("cancel")
            replacement = key(nonce=b"b" * 32)
            self.policy.begin(replacement, 2, self.rp)
            new_token = bytearray(b"new")
            self.policy.authorize_pin(replacement, 2, self.rp, new_token)
            with self.assertRaises(PolicyError):
                await task
            self.assertEqual(self.policy.key, replacement)
            self.assertEqual(new_token, bytearray(b"new"))
            self.assertFalse(self.presence.test_event(self.key, True))
        asyncio.run(cancel())
        self.assertEqual(old_token, bytearray(9))

    def authorized(self, command, rp):
        """A fresh transaction for one command, carried all the way to USED."""
        self.policy.abort("test-reset")
        self.presence.test_event(self.key, False)
        self.policy = Policy(self.presence, self.clock.ticks)
        self.policy.begin(self.key, command, rp)
        if self.policy.required_permissions:
            self.policy.authorize_pin(
                self.key, 0x3F, rp, bytearray(b"pin token")
            )
        asyncio.run(self.edge())
        self.policy.take_authorization(self.key)
        self.presence.test_event(self.key, False)

    def test_the_follow_up_count_is_bounded_per_command(self):
        # An assertion series cannot outrun the decoder's allow list; credential
        # management walks a hundred numbered slots, so it may owe ninety-nine.
        for command, rp, limit in ((2, self.rp, 9), (10, None, 99)):
            self.authorized(command, rp)
            with self.assertRaises(PolicyError):
                self.policy.continue_responses(self.key, rp, limit + 1)
            self.authorized(command, rp)
            with self.assertRaises(PolicyError):
                self.policy.continue_responses(self.key, rp, 0)
            self.authorized(command, rp)
            self.policy.continue_responses(self.key, rp, limit)
            self.assertEqual(self.policy.remaining, limit)

    def test_a_command_with_no_follow_ups_cannot_reserve_any(self):
        # A continuation is a second use of one authorization. Naming the commands
        # that have them keeps a future handler from acquiring one by accident.
        for command in (1, 6, 7, 11):
            rp = self.rp if command == 1 else None
            self.authorized(command, rp)
            with self.assertRaises(PolicyError):
                self.policy.continue_responses(self.key, rp, 1)

    def test_only_an_assertion_may_be_authorized_without_presence(self):
        # CTAP 2.1 has exactly one presence-less operation: a getAssertion
        # carrying options {"up": false}, which answers what the device holds and
        # signs with the presence bit clear. Nothing else may reach USED without
        # an edge, and that assertion may only do so from a verified PIN.
        for command, rp in ((1, self.rp), (6, None), (7, None), (10, None),
                            (11, None)):
            self.policy.abort("test-reset")
            self.policy.begin(self.key, command, rp)
            if self.policy.required_permissions:
                self.policy.authorize_pin(
                    self.key, 0x3F, rp, bytearray(b"pin token")
                )
            with self.assertRaises(PolicyError):
                self.policy.take_authorization_without_presence(self.key)
        self.policy.abort("test-reset")
        self.policy.begin(self.key, 2, self.rp)
        with self.assertRaises(PolicyError):
            # Not from WAIT_PIN: a silent assertion still carries a token.
            self.policy.take_authorization_without_presence(self.key)
        token = self.pin()
        with self.assertRaises(PolicyError):
            self.policy.take_authorization_without_presence(key(cid=8))
        self.policy.take_authorization_without_presence(self.key)
        self.assertEqual(self.policy.state, USED)
        with self.assertRaises(PolicyError):
            self.policy.take_authorization_without_presence(self.key)
        self.policy.finish(self.key)
        self.assertEqual(token, bytearray(9))
        self.assertIsNone(self.policy.key)

    def test_continuation_stays_with_original_transaction_and_rp(self):
        self.begin()
        token = self.pin()
        asyncio.run(self.edge())
        self.policy.take_authorization(self.key)
        self.policy.continue_responses(self.key, self.rp, 2)
        self.assertEqual(token, bytearray(9))
        for other, rp in ((key(cid=8), self.rp), (key(4), self.rp),
                          (key(nonce=b"b" * 32), self.rp), (self.key, b"x" * 32)):
            with self.assertRaises(PolicyError):
                self.policy.next_response(other, rp)
        self.policy.next_response(self.key, self.rp)
        self.policy.next_response(self.key, self.rp)
        self.assertIsNone(self.policy.key)
        with self.assertRaises(PolicyError):
            self.policy.next_response(self.key, self.rp)

    def test_missing_hardware_provider_denies_and_cleans_up(self):
        self.policy = Policy(PresenceProvider(), self.clock.ticks)
        self.begin()
        token = self.pin()
        with self.assertRaises(PolicyError):
            asyncio.run(self.policy.consume_presence(self.key, 20))
        self.assertEqual(token, bytearray(9))
        self.assertIsNone(self.policy.key)

    def test_presence_only_reset_selection_and_client_pin(self):
        # ClientPIN joins reset and selection: its one presence-taking
        # subcommand is setPIN, which runs before any PIN exists, so there is no
        # grant it could carry and a fresh edge alone authorizes it.
        for command in (6, 7, 11):
            self.policy.begin(self.key, command, None)
            self.assertEqual(self.policy.required_permissions, 0)
            asyncio.run(self.edge())
            self.policy.take_authorization(self.key)
            self.policy.finish(self.key)
            self.presence.test_event(self.key, False)
        # GetNextAssertion continues an authorized transaction and can never
        # open one, so it still has no entry of its own.
        with self.assertRaises(PolicyError):
            self.policy.begin(self.key, 8, None)

    def test_edge_at_deadline_is_expired_and_wiped(self):
        self.begin()
        token = self.pin()
        async def expire():
            task = asyncio.create_task(self.policy.consume_presence(self.key, 20))
            await asyncio.sleep(0)
            self.clock.now = 20
            self.presence.test_event(self.key, True)
            with self.assertRaises(PolicyError):
                await task
        asyncio.run(expire())
        self.assertEqual(token, bytearray(9))
        self.assertIsNone(self.policy.key)

    def test_default_dispatcher_owns_policy_and_cleans_before_error_hook(self):
        dispatcher = Dispatcher(cleanup=lambda context, reason: self.assertEqual(token, bytearray(9)))
        self.policy = dispatcher.policy
        self.begin()
        token = self.pin()
        event = TransportEvent(3, 7, 0x90, b"\x01\xa0")
        self.assertEqual(asyncio.run(dispatcher.dispatch(event)), b"\x27")
        self.assertIsNone(self.policy.key)

    def test_dispatcher_exception_and_context_change_erase_secrets(self):
        dispatcher = Dispatcher()
        self.policy = dispatcher.policy
        self.begin()
        token = self.pin()
        event = TransportEvent(4, 8, 0x90, b"\x04")
        self.assertTrue(asyncio.run(dispatcher.dispatch(event)).startswith(b"\x00"))
        self.assertEqual(token, bytearray(9))
        async def fail(request, context):
            self.begin()
            self.pin()
            self.policy.retain(self.key, secret)
            raise RuntimeError("failure")
        dispatcher.register(4, fail)
        secret = bytearray(b"secret")
        self.assertEqual(asyncio.run(dispatcher.dispatch(event)), b"\x7f")
        self.assertEqual(secret, bytearray(6))
        self.assertIsNone(self.policy.key)

    def test_successful_handler_cannot_leave_transient_secret_references(self):
        dispatcher = Dispatcher()
        token = bytearray(b"secret")
        async def handler(request, context):
            dispatcher.policy.begin(self.key, 2, self.rp)
            dispatcher.policy.authorize_pin(self.key, 2, self.rp, token)
            return {1: True}
        dispatcher.register(4, handler)
        self.assertEqual(asyncio.run(dispatcher.dispatch(TransportEvent(3, 7, 0x90, b"\x04"))),
                         b"\x00\xa1\x01\xf5")
        self.assertEqual(token, bytearray(6))
        self.assertIsNone(dispatcher.policy.key)

    def test_new_request_cleanup_observer_failure_returns_generic_error(self):
        def fail(context, reason):
            raise RuntimeError("observer failed")
        dispatcher = Dispatcher(cleanup=fail)
        dispatcher.policy.begin(self.key, 2, self.rp)
        token = bytearray(b"secret")
        dispatcher.policy.authorize_pin(self.key, 2, self.rp, token)
        self.assertEqual(asyncio.run(dispatcher.dispatch(TransportEvent(4, 8, 0x90, b"\x04"))), b"\x7f")
        self.assertEqual(token, bytearray(6))
        self.assertIsNone(dispatcher.policy.key)

    def test_old_waiter_cannot_clear_restarted_equal_key(self):
        self.begin()
        self.pin()
        async def restart():
            task = asyncio.create_task(self.policy.consume_presence(self.key, 20))
            await asyncio.sleep(0)
            self.policy.abort("cancel")
            self.begin()
            token = self.pin()
            with self.assertRaises(PolicyError):
                await task
            self.assertEqual(token, bytearray(b"pin token"))
            self.assertEqual(self.policy.key, self.key)
        asyncio.run(restart())

    def test_assembler_abort_overwrites_existing_buffer(self):
        assembler = HidAssembler(lambda: 7)
        assembler.channels.append(7)
        frame = (7).to_bytes(4, "big") + b"\x90\x00\x64" + b"s" * 57
        for action in (lambda: assembler.cancel(7), lambda: assembler.tick(501), assembler.disconnect):
            assembler.feed(frame, 0)
            retained = assembler.payload
            action()
            self.assertEqual(retained, bytearray(57))

    def test_transport_lifecycle_erases_before_reply_and_on_exit(self):
        for scenario in ("cancel", "timeout", "usb-reset", "disconnect", "exception", "init", "reboot", "ping",
                         "pending-cancel", "pending-usb", "pending-foreign-cancel", "pending-busy"):
            self._transport_scenario(scenario)

    def test_fresh_edge_cannot_overtake_queued_reset(self):
        self._transport_scenario("pending-race-usb")

    def test_fresh_edge_cannot_overtake_queued_active_cancel(self):
        self._transport_scenario("pending-race-cancel")

    def test_fresh_edge_cannot_overtake_queued_disconnect(self):
        self._transport_scenario("pending-race-disconnect")

    def test_queued_busy_request_cannot_hide_active_cancel_from_fresh_edge(self):
        self._transport_scenario("pending-race-busy-cancel")

    def test_expired_fresh_edge_is_cleaned_before_operation(self):
        self._transport_scenario("pending-race-timeout")

    def test_fresh_edge_succeeds_once_when_input_queue_is_empty(self):
        self._transport_scenario("pending-race-success")

    def test_sustained_foreign_cancel_cannot_extend_presence_deadline(self):
        self._sustained_traffic_timeout(0x91)

    def test_sustained_busy_traffic_cannot_extend_presence_deadline(self):
        self._sustained_traffic_timeout(0x81)

    def test_presence_deadline_under_traffic_survives_tick_wrap(self):
        self._sustained_traffic_timeout(0x91, (1 << 30) - 10)

    def _sustained_traffic_timeout(self, command, started=0):
        class StopPoll(Exception):
            pass

        clock = Clock()
        clock.now = started
        provider = TestPresenceProvider(clock.ticks, clock.checkpoint)
        dispatcher = Dispatcher()
        dispatcher.policy = Policy(provider)
        token = bytearray(b"pin secret")
        derived = bytearray(b"derived secret")
        operations = []
        frames = []
        stage = [0]
        first_key = key(0)
        rp = self.rp

        async def waiting(request, context):
            dispatcher.policy.begin(first_key, 2, rp)
            dispatcher.policy.authorize_pin(first_key, 2, rp, token)
            dispatcher.policy.retain(first_key, derived)
            await dispatcher.policy.consume_presence(first_key, 20)
            dispatcher.policy.take_authorization(first_key)
            operations.append("secret operation")

        async def clean(request, context):
            return {1: True}

        dispatcher.register(4, waiting)
        dispatcher.register(7, clean)

        def frame(cid, marker, payload=b""):
            return (cid.to_bytes(4, "big") + bytes((marker, 0, len(payload))) + payload).ljust(64, b"\0")

        class Interface:
            current = b""
            def iface_num(self):
                return 16
            def read(self, target, offset):
                target[:] = self.current
            def write(self, data):
                frames.append((stage[0], bytes(data)))
                if ((clock.now - started) & ((1 << 30) - 1)) >= 20:
                    self_test.assertEqual(token, bytearray(10))
                    self_test.assertEqual(derived, bytearray(14))
                return 64

        self_test = self
        iface = Interface()
        def poll(events, ready, timeout):
            stage[0] += 1
            step = stage[0]
            if step == 1:
                iface.current = frame(0xFFFFFFFF, 0x86, b"abcdefgh")
            elif step == 2:
                iface.current = frame(7, 0x90, b"\x04")
            elif 3 <= step <= 6:
                # Every poll has input. A valid edge is already available, but
                # the coroutine must not resume under this queued traffic.
                if step == 6:
                    self.assertEqual(timeout, 5, "poll must be capped by remaining wait time")
                clock.now = (started + (step - 2) * 5) & ((1 << 30) - 1)
                if step == 3:
                    self.assertTrue(provider.test_event(first_key, True))
                self.assertEqual(token, bytearray(b"pin secret"))
                self.assertEqual(operations, [])
                iface.current = frame(8, command)
            elif step in (7, 8):
                self.assertIsNone(dispatcher.policy.key, "timeout must run without stepping handler")
                self.assertEqual(token, bytearray(10))
                self.assertEqual(derived, bytearray(14))
                self.assertIsNone(provider.key)
                self.assertIsNone(dispatcher.policy.presence_remaining_ms())
                self.assertEqual(operations, [])
                clock.now += 5
                iface.current = frame(8, command)
            elif step == 9:
                # Same active channel can immediately accept a clean request.
                iface.current = frame(7, 0x90, b"\x07")
            else:
                raise StopPoll()
            ready[:] = [16, 64]
            return True

        async def checkpoint():
            await asyncio.sleep(0)

        saved = {n: sys.modules.get(n) for n in ("trezorio", "utime", "trezor", "trezorcrypto")}
        sys.modules["trezorio"] = types.SimpleNamespace(POLL_READ=1, POLL_WRITE=2, USB_EVENT=8, poll=poll)
        sys.modules["utime"] = types.SimpleNamespace(ticks_ms=clock.ticks)
        sys.modules["trezor"] = types.SimpleNamespace(loop=types.SimpleNamespace(checkpoint=checkpoint))
        sys.modules["trezorcrypto"] = types.SimpleNamespace(random=types.SimpleNamespace(bytes=lambda n: (7).to_bytes(n, "big")))
        try:
            with self.assertRaises(StopPoll):
                asyncio.run(handle_reports(iface, dispatcher))
            self.assertEqual(operations, [])
            self.assertFalse(any(step < 9 and data[4] == 0x90 and data[7] == 0 for step, data in frames))
            self.assertTrue(any(step == 9 and data[4] == 0x90 and data[7:12] == b"\x00\xa1\x01\xf5\x00" for step, data in frames))
            if command == 0x91:
                self.assertFalse(any(data[:4] == (8).to_bytes(4, "big") for _, data in frames))
        finally:
            for name, original in saved.items():
                if original is None:
                    sys.modules.pop(name, None)
                else:
                    sys.modules[name] = original

    def test_each_assertion_response_erases_buffers_and_preserves_only_continuation(self):
        dispatcher = Dispatcher()
        dispatcher.policy = self.policy
        self.begin()
        token = self.pin()
        asyncio.run(self.edge())
        self.policy.take_authorization(self.key)
        self.policy.continue_responses(self.key, self.rp, 3)
        self.assertEqual(token, bytearray(9))
        retained = []

        async def next_response(request, context):
            before = bytearray(b"derived before")
            self.policy.retain(self.key, before)
            retained.append(before)
            self.policy.next_response(self.key, self.rp)
            if self.policy.key is not None:
                after = bytearray(b"derived after")
                self.policy.retain(self.key, after)
                retained.append(after)
            return {1: True}

        dispatcher.register(8, next_response)
        for remaining in (2, 1, 0):
            response = asyncio.run(dispatcher.dispatch(TransportEvent(3, 7, 0x90, b"\x08")))
            self.assertEqual(response, b"\x00\xa1\x01\xf5")
            for buffer in retained:
                self.assertEqual(buffer, bytearray(len(buffer)))
            self.assertEqual(self.policy.buffers, [])
            self.assertEqual(self.policy.remaining, remaining)
            if remaining:
                self.assertEqual(self.policy.key, self.key)
                self.assertEqual(self.policy.rp_id_hash, self.rp)
            else:
                self.assertIsNone(self.policy.key)
                self.assertIsNone(self.policy.rp_id_hash)

    def _transport_scenario(self, scenario):
        class StopPoll(Exception):
            pass

        dispatcher = Dispatcher()
        token = bytearray(b"secret")
        seen = []
        operations = []
        responses = []
        race = scenario.startswith("pending-race-")
        stage = [0]
        now = [0]
        init = (0xFFFFFFFF).to_bytes(4, "big") + b"\x86\x00\x08abcdefgh" + bytes(49)
        fragment = (7).to_bytes(4, "big") + b"\x90\x00\x64" + b"s" * 57
        cancel = (7).to_bytes(4, "big") + b"\x91\x00\x00" + bytes(57)
        sync = (7).to_bytes(4, "big") + b"\x86\x00\x08abcdefgh" + bytes(49)

        class Interface:
            current = b""
            def iface_num(self):
                return 16
            def read(self, target, offset):
                target[:] = self.current
            def write(self, frame):
                responses.append(bytes(frame))
                if stage[0] >= 3 or (scenario == "ping" and stage[0] == 2):
                    seen.append(bytes(token))
                return 64

        iface = Interface()
        pending = scenario.startswith("pending-")
        if pending:
            dispatcher.policy = Policy(self.presence)
            async def handler(request, context):
                dispatcher.policy.begin(key(0), 2, self.rp)
                dispatcher.policy.authorize_pin(key(0), 2, self.rp, token)
                await dispatcher.policy.consume_presence(key(0), 20)
                dispatcher.policy.take_authorization(key(0))
                operations.append("secret operation")
            dispatcher.register(4, handler)
        def poll(events, ready, timeout):
            stage[0] += 1
            if stage[0] == 1:
                iface.current = init
            elif stage[0] == 2:
                if pending:
                    iface.current = (7).to_bytes(4, "big") + b"\x90\x00\x01\x04" + bytes(56)
                else:
                    dispatcher.policy.begin(key(0), 2, self.rp)
                    dispatcher.policy.authorize_pin(key(0), 2, self.rp, token)
                    iface.current = (
                        (7).to_bytes(4, "big") + b"\x81\x00\x00" + bytes(57)
                        if scenario == "ping" else fragment
                    )
            elif stage[0] == 3:
                if pending:
                    if race:
                        self.assertEqual(operations, [], "queued invalidation must precede secret operation")
                    self.assertEqual(token, bytearray(b"secret"), "poll must run while waiting for presence")
                    if scenario in ("pending-usb", "pending-race-usb"):
                        ready[:] = [8, 0]
                        return True
                    if scenario == "pending-race-disconnect":
                        raise OSError("queued disconnect")
                    if scenario in ("pending-race-timeout", "pending-race-success"):
                        if scenario == "pending-race-timeout":
                            self.clock.now = 20
                        return False
                    if scenario == "pending-foreign-cancel":
                        iface.current = (8).to_bytes(4, "big") + cancel[4:]
                    elif scenario in ("pending-busy", "pending-race-busy-cancel"):
                        iface.current = (8).to_bytes(4, "big") + b"\x90\x00\x01\x04" + bytes(56)
                    else:
                        iface.current = cancel
                    ready[:] = [16, 64]
                    return True
                if scenario == "timeout":
                    now[0] = 501
                    return False
                if scenario == "usb-reset":
                    ready[:] = [8, 0]
                    return True
                if scenario == "disconnect":
                    raise OSError("disconnected")
                if scenario == "exception":
                    raise StopPoll()
                iface.current = sync if scenario == "init" else cancel
            elif stage[0] == 4 and scenario == "pending-race-busy-cancel":
                self.assertEqual(operations, [])
                self.assertEqual(token, bytearray(b"secret"))
                iface.current = cancel
            else:
                if scenario in ("pending-foreign-cancel", "pending-busy"):
                    self.assertEqual(token, bytearray(b"secret"))
                elif pending:
                    self.assertEqual(token, bytearray(6))
                raise StopPoll()
            ready[:] = [16, 64]
            return True

        async def checkpoint():
            if race and stage[0] == 2:
                self.assertTrue(self.presence.test_event(key(0), True))
            await asyncio.sleep(0)

        saved = {n: sys.modules.get(n) for n in ("trezorio", "utime", "trezor", "trezorcrypto")}
        sys.modules["trezorio"] = types.SimpleNamespace(POLL_READ=1, POLL_WRITE=2, USB_EVENT=8, poll=poll)
        sys.modules["utime"] = types.SimpleNamespace(ticks_ms=lambda: now[0])
        sys.modules["trezor"] = types.SimpleNamespace(loop=types.SimpleNamespace(checkpoint=checkpoint))
        sys.modules["trezorcrypto"] = types.SimpleNamespace(random=types.SimpleNamespace(bytes=lambda n: (7).to_bytes(n, "big")))
        try:
            if scenario == "reboot":
                task = handle_reports(iface, dispatcher)
                task.send(None)
                task.send(None)
                task.close()
            else:
                with self.assertRaises(StopPoll):
                    asyncio.run(handle_reports(iface, dispatcher))
            self.assertEqual(token, bytearray(6), scenario)
            self.assertIsNone(dispatcher.policy.key)
            if scenario == "pending-race-success":
                self.assertEqual(operations, ["secret operation"])
                self.assertEqual(sum(frame[4] == 0x90 and frame[7] == 0 for frame in responses), 1)
            elif race:
                self.assertEqual(operations, [])
                self.assertFalse(any(frame[4] == 0x90 and frame[7] == 0 for frame in responses))
            if scenario not in ("pending-foreign-cancel", "pending-busy", "pending-race-busy-cancel"):
                for at_reply in seen:
                    self.assertEqual(at_reply, bytes(6), scenario)
        finally:
            for name, original in saved.items():
                if original is None:
                    sys.modules.pop(name, None)
                else:
                    sys.modules[name] = original


if __name__ == "__main__":
    unittest.main()
