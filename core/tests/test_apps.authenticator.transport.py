import os
import sys
import types

sys.path.remove(os.path.dirname(__file__))
import unittest

sys.modules["trezorio"] = types.ModuleType("trezorio")
sys.modules["trezorio"].USB_EVENT = 0x08
sys.modules["trezorcrypto"] = types.ModuleType("trezorcrypto")
sys.modules["trezorcrypto"].random = types.SimpleNamespace(bytes=lambda n: b"\x01\x02\x03\x04")

from apps.authenticator.transport import HidAssembler, handle_reports, send_response
from apps.authenticator import transport as transport_module
from apps.authenticator import boot
from apps.authenticator.transport_types import TransportEvent


CID = 0x01020304
BROADCAST = 0xFFFFFFFF
# The suite owns these rather than reading them from the module: derived
# expectations agree with whatever the module says, including a wrong value.
ATTEMPTS = 10
WAIT_MS = 50


def initial(cid, command, payload=b"", declared=None):
    length = len(payload) if declared is None else declared
    return (
        cid.to_bytes(4, "big")
        + bytes((command, length >> 8, length & 0xFF))
        + payload[:57]
    ).ljust(64, b"\0")


def continuation(cid, sequence, payload=b""):
    return (cid.to_bytes(4, "big") + bytes((sequence,)) + payload[:59]).ljust(
        64, b"\0"
    )


async def checkpoint():
    return None


class Suspend:
    """A real suspension, so the report loop regains control mid-dispatch.

    An `async def` that returns without awaiting anything suspendable never gives
    the loop a turn, which is exactly why the assumed-presence build emits no
    keepalives: its presence provider returns True without waiting. A gesture
    build waits here.
    """

    def __await__(self):
        yield None


class SlowDispatcher:
    """One dispatch that yields a fixed number of times before it answers."""

    def __init__(self, steps, presence_remaining=None, answer=b"\x00ok"):
        self.steps = steps
        self.answer = answer
        self.aborts = []
        self.policy = types.SimpleNamespace(
            key=None, presence_remaining_ms=lambda: presence_remaining
        )

    def abort(self, event, reason):
        self.aborts.append(reason)

    async def dispatch(self, event):
        for _ in range(self.steps):
            await Suspend()
        return self.answer


class TestHidAssembler(unittest.TestCase):
    def setUp(self):
        self.transport = HidAssembler(new_cid=lambda: CID)
        init = self.transport.feed(initial(BROADCAST, 0x86, b"12345678"), 0)
        self.assertEqual(init.command, 0x86)
        self.assertEqual(init.cid, BROADCAST)
        # The tail is the CTAPHID version, the device version, and the
        # capability byte: CBOR and NMSG. NMSG is the one that says U2F is
        # not implemented, which is true and used not to be said.
        self.assertEqual(init.payload, b"12345678\x01\x02\x03\x04\x02\x00\x01\x00\x0c")

    def test_init_allocates_and_resynchronizes_channel(self):
        response = self.transport.feed(initial(CID, 0x86, b"abcdefgh"), 1)
        self.assertEqual(response.payload[:12], b"abcdefgh\x01\x02\x03\x04")

    def test_a_full_table_gives_up_a_channel_rather_than_the_device(self):
        # CTAPHID gives a host no way to say it has finished with a channel, so a
        # table that only ever grew would fill with identifiers nobody is using
        # and the key would stop answering until it was physically unplugged. The
        # seventeenth allocation is served, and the identifier that has gone
        # longest without being used is the one given up.
        next_cid = iter(range(1, 20))
        transport = HidAssembler(new_cid=lambda: next(next_cid))
        for number in range(16):
            event = transport.feed(initial(BROADCAST, 0x86, b"12345678"), number)
            self.assertEqual(event.command, 0x86)
        self.assertEqual(len(transport.channels), 16)
        seventeenth = transport.feed(initial(BROADCAST, 0x86, b"12345678"), 16)
        self.assertEqual(seventeenth.command, 0x86)
        self.assertEqual(seventeenth.payload[8:12], b"\x00\x00\x00\x11")
        self.assertEqual(len(transport.channels), 16)
        # The owner of channel one is told its channel is gone, which is the one
        # answer that tells it to allocate another.
        stale = transport.feed(initial(1, 0x81, b"x"), 17)
        self.assertEqual((stale.command, stale.payload), (0xBF, b"\x0b"))
        self.assertIn(2, transport.channels)
        # And the one after that gives up channel two, not the channel just
        # handed out: a new identifier joins the table at the recently-used end.
        eighteenth = transport.feed(initial(BROADCAST, 0x86, b"12345678"), 18)
        self.assertEqual(eighteenth.payload[8:12], b"\x00\x00\x00\x12")
        self.assertNotIn(2, transport.channels)
        self.assertIn(0x11, transport.channels)
        self.assertEqual(len(transport.channels), 16)

    def test_the_channel_given_up_is_the_one_longest_unused(self):
        next_cid = iter(range(1, 20))
        transport = HidAssembler(new_cid=lambda: next(next_cid))
        for number in range(16):
            transport.feed(initial(BROADCAST, 0x86, b"12345678"), number)
        # Channel one speaks, so it is no longer the one that has waited longest.
        ping = transport.feed(initial(1, 0x81, b"x"), 16)
        self.assertEqual((ping.command, ping.payload), (0x81, b"x"))
        transport.feed(initial(BROADCAST, 0x86, b"12345678"), 17)
        self.assertIn(1, transport.channels)
        self.assertNotIn(2, transport.channels)
        self.assertEqual(len(transport.channels), 16)

    def test_a_host_that_says_it_is_still_there_keeps_its_channel(self):
        # Re-initialising an existing channel is a host saying exactly that.
        next_cid = iter(range(1, 20))
        transport = HidAssembler(new_cid=lambda: next(next_cid))
        for number in range(16):
            transport.feed(initial(BROADCAST, 0x86, b"12345678"), number)
        again = transport.feed(initial(1, 0x86, b"12345678"), 16)
        self.assertEqual(again.payload[8:12], b"\x00\x00\x00\x01")
        transport.feed(initial(BROADCAST, 0x86, b"12345678"), 17)
        self.assertIn(1, transport.channels)
        self.assertNotIn(2, transport.channels)

    def test_the_capability_byte_denies_u2f_rather_than_implying_it(self):
        # CTAPHID has no way to say "I speak CBOR and not U2F" except by setting
        # NMSG. With the bit clear this device claimed U2F and then answered
        # CTAPHID_MSG with an error, which is how libfido2 came to report "msg"
        # supported on a key that has never implemented it.
        # Re-initialising the channel this fixture already owns, because the
        # fixture hands out one identifier and a second allocation would collide.
        init = self.transport.feed(initial(CID, 0x86, b"abcdefgh"), 0)
        self.assertEqual(init.payload[16] & 0x08, 0x08)
        self.assertEqual(init.payload[16] & 0x04, 0x04)
        self.assertEqual(init.payload[16] & 0x01, 0x00)

    def test_invalid_channels(self):
        for cid, command, payload, code in (
            (BROADCAST, 0x81, b"x", 0x0B),
            (0, 0x86, b"12345678", 0x0B),
            (0x11111111, 0x81, b"x", 0x0B),
            (CID, 0x86, b"short", 0x03),
        ):
            event = self.transport.feed(initial(cid, command, payload), 2)
            self.assertEqual((event.command, event.payload), (0xBF, bytes((code,))))

    def test_report_and_length_bounds(self):
        for report, code in (
            (initial(CID, 0x81, b"x")[:-1], 0x03),
            (initial(CID, 0x81, b"x") + b"x", 0x03),
            (initial(CID, 0x90, declared=1025), 0x03),
        ):
            event = self.transport.feed(report, 3)
            self.assertEqual((event.command, event.payload), (0xBF, bytes((code,))))

    def test_reassembly_and_immutable_payload(self):
        payload = b"x" * 57 + b"y" * 59 + b"z" * 4
        self.assertIsNone(self.transport.feed(initial(CID, 0x90, payload, 120), 10))
        self.assertIsNone(self.transport.feed(continuation(CID, 0, payload[57:]), 11))
        event = self.transport.feed(continuation(CID, 1, payload[116:]), 12)
        self.assertEqual((event.cid, event.command, event.payload), (CID, 0x90, payload))
        self.assertTrue(isinstance(event.payload, bytes))

    def test_bad_continuation_sequence_aborts(self):
        for sequence in (1, 2, 127):
            self.assertIsNone(self.transport.feed(initial(CID, 0x90, b"x" * 57, 60), 20))
            event = self.transport.feed(continuation(CID, sequence, b"yyy"), 21)
            self.assertEqual((event.command, event.payload), (0xBF, b"\x04"))
        self.assertIsNone(self.transport.feed(initial(CID, 0x90, b"x" * 57, 120), 30))
        self.assertIsNone(self.transport.feed(continuation(CID, 0, b"y" * 59), 31))
        event = self.transport.feed(continuation(CID, 0, b"zzzz"), 32)
        self.assertEqual((event.command, event.payload), (0xBF, b"\x04"))

    def test_foreign_channel_does_not_replace_inflight(self):
        self.assertIsNone(self.transport.feed(initial(CID, 0x90, b"x" * 57, 60), 40))
        busy = self.transport.feed(initial(0x11111111, 0x81, b"abc"), 41)
        self.assertEqual((busy.cid, busy.command, busy.payload), (0x11111111, 0xBF, b"\x06"))
        self.assertIsNone(self.transport.feed(continuation(0x11111111, 0), 42))
        event = self.transport.feed(continuation(CID, 0, b"yyy"), 43)
        self.assertEqual(event.payload, b"x" * 57 + b"yyy")

    def test_timeout_aborts_inflight(self):
        self.assertIsNone(self.transport.feed(initial(CID, 0x90, b"x" * 57, 60), 100))
        event = self.transport.tick(601)
        self.assertEqual((event.cid, event.command, event.payload), (CID, 0xBF, b"\x05"))
        stale = self.transport.feed(continuation(CID, 0, b"yyy"), 602)
        self.assertEqual((stale.command, stale.payload), (0xBF, b"\x04"))

    def test_timeout_handles_tick_wraparound(self):
        self.assertIsNone(
            self.transport.feed(initial(CID, 0x90, b"x" * 57, 60), (1 << 30) - 100)
        )
        self.assertIsNone(self.transport.tick(399))
        self.assertEqual(self.transport.tick(401).payload, b"\x05")

    def test_malformed_current_frame_aborts(self):
        self.assertIsNone(self.transport.feed(initial(CID, 0x90, b"x" * 57, 60), 400))
        self.assertEqual(self.transport.feed(initial(CID, 0x91, b"bad"), 401).payload, b"\x03")
        self.assertEqual(self.transport.feed(continuation(CID, 0, b"yyy"), 402).payload, b"\x04")

    def test_exact_message_limit(self):
        payload = b"p" * 1024
        self.assertIsNone(self.transport.feed(initial(CID, 0x90, payload), 1))
        event = None
        for sequence in range(17):
            event = self.transport.feed(
                continuation(CID, sequence, payload[57 + sequence * 59 :]), 2 + sequence
            )
        self.assertEqual(event.payload, payload)

    def test_cancel_and_init_abort(self):
        self.assertIsNone(self.transport.feed(initial(CID, 0x90, b"x" * 57, 60), 200))
        cancelled = self.transport.feed(initial(CID, 0x91), 201)
        self.assertEqual((cancelled.command, cancelled.payload), (0x91, b""))
        self.assertEqual(self.transport.feed(continuation(CID, 0), 202).payload, b"\x04")
        self.assertIsNone(self.transport.feed(initial(CID, 0x90, b"x" * 57, 60), 203))
        restarted = self.transport.feed(initial(CID, 0x86, b"abcdefgh"), 204)
        self.assertEqual(restarted.command, 0x86)
        self.assertEqual(self.transport.feed(continuation(CID, 0), 205).payload, b"\x04")

    def test_cancel_only_aborts_its_active_channel(self):
        other = 0x05060708
        assigned = iter((CID, other))
        transport = HidAssembler(new_cid=lambda: next(assigned))
        transport.feed(initial(BROADCAST, 0x86, b"12345678"), 0)
        transport.feed(initial(BROADCAST, 0x86, b"abcdefgh"), 1)
        self.assertEqual(set(transport.channels), {CID, other})

        self.assertIsNone(transport.feed(initial(CID, 0x90, b"x" * 57, 60), 2))
        self.assertIsNone(transport.feed(initial(other, 0x91), 3))
        self.assertIsNone(transport.feed(initial(0x11111111, 0x91), 4))
        self.assertIsNone(transport.cancel(0x11111111))
        self.assertEqual(set(transport.channels), {CID, other})
        self.assertEqual(transport.cid, CID)
        complete = transport.feed(continuation(CID, 0, b"yyy"), 5)
        self.assertEqual((complete.cid, complete.command, complete.payload), (CID, 0x90, b"x" * 57 + b"yyy"))

        self.assertIsNone(transport.feed(initial(CID, 0x90, b"x" * 57, 60), 6))
        cancelled = transport.feed(initial(CID, 0x91), 7)
        self.assertEqual((cancelled.cid, cancelled.command, cancelled.payload), (CID, 0x91, b""))
        self.assertIsNone(transport.cid)
        self.assertEqual(transport.feed(continuation(CID, 0, b"yyy"), 8).payload, b"\x04")

    def test_disconnect_changes_generation_and_clears_channels(self):
        generation = self.transport.connection_generation
        self.assertIsNone(self.transport.feed(initial(CID, 0x90, b"x" * 57, 60), 300))
        self.transport.disconnect()
        self.assertEqual(self.transport.connection_generation, generation + 1)
        error = self.transport.feed(initial(CID, 0x81, b"x"), 301)
        self.assertEqual((error.command, error.payload), (0xBF, b"\x0b"))
        self.assertEqual(error.connection_generation, generation + 1)

    def test_event_defensively_copies_bounded_payload(self):
        mutable = bytearray(b"abc")
        event = TransportEvent(1, CID, 0x90, mutable)
        mutable[0] = 0
        self.assertEqual(event.payload, b"abc")
        with self.assertRaises(ValueError):
            TransportEvent(1, CID, 0x90, bytes(1025))

    def test_deterministic_malformed_report_corpus(self):
        import random

        source = random.Random(20260925)
        for now_ms in range(1000):
            length = source.choice((0, 1, 3, 4, 5, 7, 63, 64, 65, 128))
            report = bytes(source.randrange(256) for _ in range(length))
            event = self.transport.feed(report, now_ms)
            self.assertLessEqual(len(self.transport.payload), 1024)
            self.assertLessEqual(len(self.transport.channels), 16)
            if event is not None:
                self.assertLessEqual(len(event.payload), 1024)
                if length != 64:
                    self.assertEqual((event.command, event.payload), (0xBF, b"\x03"))


class TestHidOutput(unittest.TestCase):
    def test_loop_sends_nothing_for_non_active_cancel(self):
        class StopPoll(Exception):
            pass

        other = 0x05060708

        class Interface:
            def __init__(self):
                self.reports = [
                    initial(BROADCAST, 0x86, b"12345678"),
                    initial(BROADCAST, 0x86, b"abcdefgh"),
                    initial(CID, 0x81, b"x" * 57, 60),
                    initial(other, 0x91),
                    initial(0x11111111, 0x91),
                    continuation(CID, 0, b"yyy"),
                ]
                self.frames = []
                self.current = b""

            def iface_num(self):
                return 0x10

            def read(self, target, offset):
                target[:] = self.current

            def write(self, frame):
                self.frames.append(frame)
                return 64

        iface = Interface()
        trezorio = sys.modules["trezorio"]
        trezorio.POLL_READ = 1
        trezorio.POLL_WRITE = 2

        def poll(events, ready, timeout):
            if not iface.reports:
                raise StopPoll()
            iface.current = iface.reports.pop(0)
            ready[:] = [iface.iface_num(), 64]
            return True

        trezorio.poll = poll
        sys.modules["utime"] = types.SimpleNamespace(ticks_ms=lambda: 10)
        sys.modules["trezor"] = types.SimpleNamespace(
            loop=types.SimpleNamespace(checkpoint=checkpoint)
        )
        random_bytes = sys.modules["trezorcrypto"].random.bytes
        assigned = iter((CID, other))
        sys.modules["trezorcrypto"].random.bytes = lambda n: next(assigned).to_bytes(4, "big")
        try:
            with self.assertRaises(StopPoll):
                handle_reports(iface).send(None)
        finally:
            sys.modules["trezorcrypto"].random.bytes = random_bytes
        self.assertEqual([frame[4] for frame in iface.frames], [0x86, 0x86, 0x81, 0x00])
        self.assertEqual(iface.frames[2][7:64], b"x" * 57)
        self.assertEqual(iface.frames[3][5:8], b"yyy")

    def test_usb_reset_event_clears_allocated_channels(self):
        class StopPoll(Exception):
            pass

        class Interface:
            def __init__(self):
                self.frames = []
                self.current = b""

            def iface_num(self):
                return 0x10

            def read(self, target, offset):
                target[:] = self.current

            def write(self, frame):
                self.frames.append(frame)
                return 64

        iface = Interface()
        items = [initial(BROADCAST, 0x86, b"12345678"), "reset", initial(CID, 0x81, b"x")]
        trezorio = sys.modules["trezorio"]
        trezorio.POLL_READ = 1
        trezorio.POLL_WRITE = 2
        trezorio.USB_EVENT = 0x08

        def poll(events, ready, timeout):
            self.assertIn(trezorio.USB_EVENT, events)
            if not items:
                raise StopPoll()
            item = items.pop(0)
            if item == "reset":
                ready[:] = [trezorio.USB_EVENT, 2]
            else:
                iface.current = item
                ready[:] = [iface.iface_num(), 64]
            return True

        trezorio.poll = poll
        sys.modules["utime"] = types.SimpleNamespace(ticks_ms=lambda: 10)
        sys.modules["trezor"] = types.SimpleNamespace(
            loop=types.SimpleNamespace(checkpoint=checkpoint)
        )
        with self.assertRaises(StopPoll):
            handle_reports(iface).send(None)
        self.assertEqual([(f[4], f[7]) for f in iface.frames], [(0x86, 49), (0xBF, 0x0B)])

    def test_loop_reports_short_usb_frame_even_when_driver_raises(self):
        class StopPoll(Exception):
            pass

        class Interface:
            def __init__(self):
                self.frames = []

            def iface_num(self):
                return 0x10

            def read(self, target, offset):
                target[:63] = initial(CID, 0x81, b"a")[:63]
                raise RuntimeError("Unexpected read length")

            def write(self, frame):
                self.frames.append(frame)
                return 64

        iface = Interface()
        reads = [1]

        def poll(events, ready, timeout):
            if not reads:
                raise StopPoll()
            reads.pop()
            ready[1] = 64
            return True

        trezorio = sys.modules["trezorio"]
        trezorio.POLL_READ = 1
        trezorio.POLL_WRITE = 2
        trezorio.poll = poll
        sys.modules["utime"] = types.SimpleNamespace(ticks_ms=lambda: 10)
        sys.modules["trezor"] = types.SimpleNamespace(
            loop=types.SimpleNamespace(checkpoint=checkpoint)
        )
        with self.assertRaises(StopPoll):
            handle_reports(iface).send(None)
        self.assertEqual((iface.frames[0][4], iface.frames[0][7]), (0xBF, 0x03))

    def test_boot_drives_bounded_service_coroutine(self):
        class Interface:
            def __init__(self):
                self.frames = []

            def iface_num(self):
                return 0x10

            def read(self, target, offset):
                target[:] = initial(BROADCAST, 0x86, b"12345678")

            def write(self, frame):
                self.frames.append(frame)
                return 64

        class StopPoll(Exception):
            pass

        iface = Interface()
        reads = [1]

        def poll(events, ready, timeout):
            if not reads:
                raise StopPoll()
            reads.pop()
            ready[1] = 64
            return True

        trezorio = sys.modules["trezorio"]
        trezorio.POLL_READ = 1
        trezorio.POLL_WRITE = 2
        trezorio.poll = poll
        sys.modules["utime"] = types.SimpleNamespace(ticks_ms=lambda: 10)
        driver = types.SimpleNamespace(run=lambda task: task.send(None), checkpoint=checkpoint)
        sys.modules["trezor"] = types.SimpleNamespace(loop=driver)
        with self.assertRaises(StopPoll):
            boot(iface)
        self.assertEqual(iface.frames[0][4], 0x86)

    def test_response_frames_have_exact_length_sequence_and_padding(self):
        class Interface:
            def __init__(self):
                self.frames = []

            def write(self, frame):
                self.frames.append(frame)
                return 64

        iface = Interface()
        payload = bytes(range(120))
        with self.assertRaises(StopIteration):
            send_response(iface, CID, 0x90, payload).send(None)
        self.assertEqual(
            iface.frames,
            [
                b"\x01\x02\x03\x04\x90\x00\x78" + payload[:57],
                b"\x01\x02\x03\x04\x00" + payload[57:116],
                b"\x01\x02\x03\x04\x01" + payload[116:] + bytes(55),
            ],
        )

    def test_response_rejects_oversized_payload(self):
        class Interface:
            def write(self, frame):
                self.fail("unexpected write")

        with self.assertRaises(ValueError):
            send_response(Interface(), CID, 0x90, bytes(1025)).send(None)

    def test_response_rejects_partial_usb_writes(self):
        class Interface:
            def iface_num(self):
                return 0x10

            def write(self, frame):
                return 63

        trezorio = sys.modules["trezorio"]
        trezorio.POLL_WRITE = 2
        trezorio.poll = lambda events, ready, timeout: False
        with self.assertRaises(OSError):
            send_response(Interface(), CID, 0x81, b"abc").send(None)

    def test_write_retry_bounds_are_what_the_suite_assumes(self):
        self.assertEqual(transport_module.WRITE_ATTEMPTS, ATTEMPTS)
        self.assertEqual(transport_module.WRITE_WAIT_MS, WAIT_MS)

    def test_response_outlasts_a_busy_endpoint_on_every_frame(self):
        """The failure that cost a working key: this is what silicon does.

        USBIF.write raises when the host has not collected the previous report,
        which is the normal state a microsecond after the previous write. Every
        frame after the first used to die here.
        """

        class Interface:
            def __init__(self):
                self.frames = []
                self.refusals = 0
                self.busy = True

            def iface_num(self):
                return 0x10

            def write(self, frame):
                if self.busy:
                    self.busy = False
                    self.refusals += 1
                    raise OSError("Write failed")
                self.busy = True
                self.frames.append(frame)
                return 64

        iface = Interface()
        waited = []
        trezorio = sys.modules["trezorio"]
        trezorio.POLL_READ = 1
        trezorio.POLL_WRITE = 2

        def poll(events, ready, timeout):
            waited.append((tuple(events), timeout))
            return True

        trezorio.poll = poll
        payload = bytes(range(120))
        with self.assertRaises(StopIteration):
            send_response(iface, CID, 0x90, payload).send(None)
        self.assertEqual(
            iface.frames,
            [
                b"\x01\x02\x03\x04\x90\x00\x78" + payload[:57],
                b"\x01\x02\x03\x04\x00" + payload[57:116],
                b"\x01\x02\x03\x04\x01" + payload[116:] + bytes(55),
            ],
        )
        self.assertEqual(iface.refusals, 3)
        # Each refusal waits for write readiness on this interface, and asks for
        # it with the write bit set, which is what makes the poll report it.
        self.assertEqual(waited, [((0x10 | 2,), WAIT_MS)] * 3)

    def test_response_gives_up_on_an_interface_that_never_accepts(self):
        """A dead interface must not wedge the applet forever."""

        class Interface:
            def __init__(self):
                self.attempts = 0

            def iface_num(self):
                return 0x10

            def write(self, frame):
                self.attempts += 1
                raise OSError("Write failed")

        iface = Interface()
        trezorio = sys.modules["trezorio"]
        trezorio.POLL_WRITE = 2
        trezorio.poll = lambda events, ready, timeout: False
        with self.assertRaises(OSError):
            send_response(iface, CID, 0x81, b"abc").send(None)
        self.assertEqual(iface.attempts, ATTEMPTS)

    def test_hid_loop_keeps_the_channel_when_the_endpoint_is_busy(self):
        """The symptom, end to end: a long answer and a surviving channel.

        A busy write used to surface as OSError, which the loop read as a
        disconnect and answered by clearing every channel. The host saw one frame
        of a four-frame answer and then INVALID_CHANNEL on its next request.
        """

        class StopPoll(Exception):
            pass

        echoed = bytes(range(200))

        class Interface:
            def __init__(self):
                self.reports = [
                    initial(BROADCAST, 0x86, b"12345678"),
                    initial(CID, 0x81, echoed, declared=200),
                    continuation(CID, 0, echoed[57:116]),
                    continuation(CID, 1, echoed[116:175]),
                    continuation(CID, 2, echoed[175:]),
                    initial(CID, 0x81, b"after"),
                ]
                self.frames = []
                self.current = b""
                self.refusals = 0
                self.busy = True

            def iface_num(self):
                return 0x10

            def read(self, target, offset):
                target[:] = self.current

            def write(self, frame):
                if self.busy:
                    self.busy = False
                    self.refusals += 1
                    raise OSError("Write failed")
                self.busy = True
                self.frames.append(frame)
                return 64

        iface = Interface()
        trezorio = sys.modules["trezorio"]
        trezorio.POLL_READ = 1
        trezorio.POLL_WRITE = 2
        trezorio.USB_EVENT = 0x08

        def poll(events, ready, timeout):
            # A wait for write readiness must not consume an input report.
            if any(event & trezorio.POLL_WRITE for event in events):
                return False
            if not iface.reports:
                raise StopPoll()
            iface.current = iface.reports.pop(0)
            ready[1] = len(iface.current)
            return True

        trezorio.poll = poll
        sys.modules["utime"] = types.SimpleNamespace(ticks_ms=lambda: 10)
        sys.modules["trezor"] = types.SimpleNamespace(
            loop=types.SimpleNamespace(checkpoint=checkpoint)
        )
        saved_auth = sys.modules.get("trezorauth")
        sys.modules["trezorauth"] = types.SimpleNamespace(
            OK=0, UNPROVISIONED=1, PIN_AUTH_BLOCKED=4, MIN_PIN_CODE_POINTS=8,
            status=lambda: (1, 0, 0),
        )
        try:
            with self.assertRaises(StopPoll):
                handle_reports(iface).send(None)
        finally:
            if saved_auth is None:
                del sys.modules["trezorauth"]
            else:
                sys.modules["trezorauth"] = saved_auth

        self.assertEqual([frame[4] for frame in iface.frames],
                         [0x86, 0x81, 0x00, 0x01, 0x02, 0x81])
        # The whole echo came back, not just its first frame.
        answer = iface.frames[1][7:64]
        for frame in iface.frames[2:5]:
            answer += frame[5:64]
        self.assertEqual(answer[:200], echoed)
        # And the channel is still the same one: a request after the long answer
        # is echoed rather than refused with INVALID_CHANNEL.
        self.assertEqual(iface.frames[5][4], 0x81)
        self.assertEqual(iface.frames[5][7:12], b"after")
        self.assertEqual(iface.refusals, 6)

    def keepalive_run(self, dispatcher, silent_polls=12, tick_ms=50,
                      refuse_command=None):
        """Drive the loop over one CBOR request and then a span of silence.

        The clock advances by `tick_ms` per silent poll, which is what makes the
        cadence assertions exact rather than approximate.
        """

        class StopPoll(Exception):
            pass

        clock = [0]

        class Interface:
            def __init__(self):
                self.reports = [
                    initial(BROADCAST, 0x86, b"12345678"),
                    initial(CID, 0x90, b"\x04"),
                ]
                self.frames = []
                self.current = b""

            def iface_num(self):
                return 0x10

            def read(self, target, offset):
                target[:] = self.current

            def write(self, frame):
                if refuse_command is not None and frame[4] == refuse_command:
                    raise OSError("Write failed")
                self.frames.append(frame)
                return 64

        iface = Interface()
        trezorio = sys.modules["trezorio"]
        trezorio.POLL_READ = 1
        trezorio.POLL_WRITE = 2
        trezorio.USB_EVENT = 0x08
        polls = [0]

        def poll(events, ready, timeout):
            # A wait for write readiness must not consume an input report.
            if any(event & trezorio.POLL_WRITE for event in events):
                return False
            if iface.reports:
                iface.current = iface.reports.pop(0)
                ready[1] = len(iface.current)
                return True
            polls[0] += 1
            if polls[0] > silent_polls:
                raise StopPoll()
            clock[0] += tick_ms
            return False

        trezorio.poll = poll
        sys.modules["utime"] = types.SimpleNamespace(ticks_ms=lambda: clock[0])
        sys.modules["trezor"] = types.SimpleNamespace(
            loop=types.SimpleNamespace(checkpoint=checkpoint)
        )
        with self.assertRaises(StopPoll):
            handle_reports(iface, dispatcher).send(None)
        return iface.frames

    def test_a_working_dispatch_is_kept_alive_at_the_stated_interval(self):
        """Two hundred milliseconds of waiting, at a hundred per keepalive."""
        dispatcher = SlowDispatcher(steps=5)
        frames = self.keepalive_run(dispatcher)
        self.assertEqual([frame[4] for frame in frames],
                         [0x86, 0xBB, 0xBB, 0x90])
        # The answer is last, and it is the real one.
        self.assertEqual(frames[-1][7:9], b"\x00o")
        # Spacing, not a frame per poll: four polls were offered a keepalive and
        # two of them were inside the interval of the one before.
        self.assertEqual(len([f for f in frames if f[4] == 0xBB]), 2)

    def test_the_status_says_working_when_nobody_is_being_waited_for(self):
        frames = self.keepalive_run(SlowDispatcher(steps=5))
        for frame in frames:
            if frame[4] == 0xBB:
                self.assertEqual(frame[5:8], b"\x00\x01\x01")

    def test_the_status_says_a_person_is_needed_during_a_presence_wait(self):
        """A platform shows a prompt for this and a spinner for the other."""
        frames = self.keepalive_run(SlowDispatcher(steps=5, presence_remaining=500))
        keepalives = [frame for frame in frames if frame[4] == 0xBB]
        self.assertTrue(keepalives)
        for frame in keepalives:
            self.assertEqual(frame[5:8], b"\x00\x01\x02")

    def test_an_answer_that_is_ready_is_not_preceded_by_a_keepalive(self):
        # Nothing to wait for, so nothing to say about waiting.
        frames = self.keepalive_run(SlowDispatcher(steps=0))
        self.assertEqual([frame[4] for frame in frames], [0x86, 0x90])

    def test_a_keepalive_that_cannot_be_written_does_not_kill_the_channel(self):
        """A keepalive nobody collected is not a lifecycle event.

        The answer's own write is what decides whether the channel is alive. If a
        failed keepalive tore the channel down, a busy host would cost the very
        transaction the keepalive exists to protect.
        """
        dispatcher = SlowDispatcher(steps=5)
        frames = self.keepalive_run(dispatcher, refuse_command=0xBB)
        # No keepalive got out, and the answer still did.
        self.assertEqual([frame[4] for frame in frames], [0x86, 0x90])
        self.assertEqual(frames[-1][7:9], b"\x00o")
        self.assertNotIn("disconnect", dispatcher.aborts)

    def test_a_second_dispatch_starts_its_own_cadence(self):
        """A new command must hear from the device straight away.

        If the interval carried over from the command before it, the first
        keepalive of a slow command could be held back by most of an interval --
        time taken from the only budget that matters. The timing here is chosen so
        that a carried-over cadence would swallow the second keepalive entirely:
        the second dispatch's first offer falls sixty milliseconds after the first
        dispatch's keepalive, inside the hundred-millisecond interval.
        """

        class StopPoll(Exception):
            pass

        clock = [0]
        dispatcher = SlowDispatcher(steps=2)

        class Interface:
            def __init__(self):
                self.frames = []
                self.current = b""

            def iface_num(self):
                return 0x10

            def read(self, target, offset):
                target[:] = self.current

            def write(self, frame):
                self.frames.append(frame)
                return 64

        iface = Interface()
        # None is a poll that brought nothing, which is when a keepalive is due.
        schedule = [
            initial(BROADCAST, 0x86, b"12345678"),
            initial(CID, 0x90, b"\x04"), None, None,
            initial(CID, 0x90, b"\x04"), None, None,
        ]
        trezorio = sys.modules["trezorio"]
        trezorio.POLL_READ = 1
        trezorio.POLL_WRITE = 2
        trezorio.USB_EVENT = 0x08

        def poll(events, ready, timeout):
            if any(event & trezorio.POLL_WRITE for event in events):
                return False
            if not schedule:
                raise StopPoll()
            entry = schedule.pop(0)
            clock[0] += 20
            if entry is None:
                return False
            iface.current = entry
            ready[1] = len(entry)
            return True

        trezorio.poll = poll
        sys.modules["utime"] = types.SimpleNamespace(ticks_ms=lambda: clock[0])
        sys.modules["trezor"] = types.SimpleNamespace(
            loop=types.SimpleNamespace(checkpoint=checkpoint)
        )
        with self.assertRaises(StopPoll):
            handle_reports(iface, dispatcher).send(None)
        self.assertEqual([frame[4] for frame in iface.frames],
                         [0x86, 0xBB, 0x90, 0xBB, 0x90])

    def test_hid_loop_routes_getinfo_ping_cancel_and_errors(self):
        class StopPoll(Exception):
            pass

        class Interface:
            def __init__(self):
                self.reports = [
                    initial(BROADCAST, 0x86, b"12345678"),
                    initial(CID, 0x81, b"hi"),
                    initial(CID, 0x90, b"\x04"),
                    initial(CID, 0x90, b"\x01"),
                    initial(CID, 0x90),
                    initial(CID, 0x91),
                    initial(CID, 0xBB, b"\x01"),
                ]
                self.frames = []
                self.current = b""

            def iface_num(self):
                return 0x10

            def read(self, target, offset):
                target[:] = self.current

            def write(self, frame):
                self.frames.append(frame)
                return 64

        iface = Interface()
        trezorio = sys.modules["trezorio"]
        trezorio.POLL_READ = 1
        trezorio.POLL_WRITE = 2

        def poll(events, ready, timeout):
            if not iface.reports:
                raise StopPoll()
            iface.current = iface.reports.pop(0)
            ready[1] = len(iface.current)
            return True

        trezorio.poll = poll
        sys.modules["utime"] = types.SimpleNamespace(ticks_ms=lambda: 10)
        sys.modules["trezor"] = types.SimpleNamespace(
            loop=types.SimpleNamespace(checkpoint=checkpoint)
        )
        # The default dispatcher answers GetInfo from the vault, so the loop
        # needs one. Without it the handler would raise and the loop would send a
        # one-byte error, which still looks like a routed response.
        saved_auth = sys.modules.get("trezorauth")
        sys.modules["trezorauth"] = types.SimpleNamespace(
            OK=0, UNPROVISIONED=1, PIN_AUTH_BLOCKED=4, MIN_PIN_CODE_POINTS=8,
            status=lambda: (1, 0, 0),
        )
        try:
            with self.assertRaises(StopPoll):
                handle_reports(iface).send(None)
        finally:
            if saved_auth is None:
                del sys.modules["trezorauth"]
            else:
                sys.modules["trezorauth"] = saved_auth
        commands = [frame[4] for frame in iface.frames]
        # GetInfo reports the whole surface, which now includes credential
        # management under both of its command numbers, so the response spans four
        # frames: the first and three continuations.
        self.assertEqual(commands,
                         [0x86, 0x81, 0x90, 0x00, 0x01, 0x02, 0x90, 0xBF, 0xBF])
        self.assertEqual(iface.frames[1][7:9], b"hi")
        self.assertIn(b"FIDO_2_1", b"".join(iface.frames[2:6]))
        # makeCredential is routed now, so an empty body is the decoder's
        # answer rather than an unknown command.
        self.assertEqual(iface.frames[6][7:8], b"\x12")
        self.assertEqual(iface.frames[7][7:8], b"\x03")
        self.assertEqual(iface.frames[8][7:8], b"\x01")


if __name__ == "__main__":
    unittest.main()
