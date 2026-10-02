"""One-slot, bounded CTAPHID transport for the dedicated authenticator."""

from .transport_types import TransportEvent

REPORT_SIZE = 64
MAX_MESSAGE_SIZE = 1024
FRAME_TIMEOUT_MS = 500
MAX_CHANNELS = 16
BROADCAST = 0xFFFFFFFF

# What the INIT reply claims this device can do. CBOR, and explicitly not U2F:
# NMSG is the bit that says CTAPHID_MSG is unimplemented, and leaving it clear
# claimed U2F while the only answer to a U2F message was an error. libfido2 read
# the claim back as "msg" supported, which is how the mistake was found. WINK is
# absent for the same reason it has always been: there is nothing to blink.
CAPABILITY_CBOR = 0x04
CAPABILITY_NMSG = 0x08
CAPABILITIES = CAPABILITY_CBOR | CAPABILITY_NMSG

PING = 0x81
INIT = 0x86
CBOR = 0x90
CANCEL = 0x91
KEEPALIVE = 0xBB
ERROR = 0xBF

INVALID_CMD = 0x01
INVALID_LEN = 0x03
INVALID_SEQ = 0x04
MSG_TIMEOUT = 0x05
CHANNEL_BUSY = 0x06
INVALID_CID = 0x0B
OTHER = 0x7F

# CTAPHID keepalive statuses: still working, and waiting for the person.
KEEPALIVE_PROCESSING = 0x01
KEEPALIVE_UP_NEEDED = 0x02
# A host abandons a transaction after three seconds of silence and restarts that
# clock on every keepalive it receives. CTAP asks for one at least every hundred
# milliseconds, which is comfortably inside the three.
KEEPALIVE_INTERVAL_MS = 100

# Tick arithmetic is masked so a wrapping counter cannot make an interval look
# enormous, or a deadline look as though it never arrives.
_TICKS_MASK = (1 << 30) - 1


def _random_cid() -> int:
    from trezorcrypto import random

    return int.from_bytes(random.bytes(4), "big")


class HidAssembler:
    """Reassemble at most one request and retain only bounded channel state."""

    def __init__(self, new_cid=None) -> None:
        self._new_cid = new_cid or _random_cid
        self.connection_generation = 0
        # Ordered oldest-used first, which is what makes it possible to say which
        # identifier to give up when the table is full. A list, because sixteen
        # entries make the cost of looking one up irrelevant and because a set has
        # no order to read.
        self.channels = []
        self._abort()

    def _abort(self) -> None:
        if hasattr(self, "payload"):
            for i in range(len(self.payload)):
                self.payload[i] = 0
        self.cid = None
        self.command = 0
        self.length = 0
        self.payload = bytearray()
        self.sequence = 0
        self.last_ms = 0

    def _mark_used(self, cid: int) -> None:
        """Record that this channel is still in use."""
        if self.channels[-1] != cid:
            self.channels.remove(cid)
            self.channels.append(cid)

    def _event(self, cid: int, command: int, payload: bytes) -> TransportEvent:
        return TransportEvent(self.connection_generation, cid, command, payload)

    def _error(self, cid: int, code: int) -> TransportEvent:
        return self._event(cid, ERROR, bytes((code,)))

    def tick(self, now_ms: int) -> TransportEvent | None:
        elapsed = (now_ms - self.last_ms) & _TICKS_MASK
        if self.cid is not None and elapsed > FRAME_TIMEOUT_MS:
            cid = self.cid
            self._abort()
            return self._error(cid, MSG_TIMEOUT)
        return None

    def disconnect(self) -> None:
        self._abort()
        self.channels.clear()
        self.connection_generation += 1

    def cancel(self, cid: int) -> TransportEvent | None:
        if self.cid != cid:
            return None
        self._abort()
        return self._event(cid, CANCEL, b"")

    def _init(self, cid: int, nonce: bytes) -> TransportEvent:
        if len(nonce) != 8:
            return self._error(cid, INVALID_LEN)
        if cid == BROADCAST:
            if len(self.channels) >= MAX_CHANNELS:
                # CTAPHID gives a host no way to say it has finished with a
                # channel: a process that stops talking leaves its identifier
                # behind forever. Refusing here meant a key that answered sixteen
                # hosts and then nobody, until someone unplugged it -- so the
                # identifier that has gone longest without being used is given up
                # instead. Its owner, if there is still one, gets
                # CTAP1_ERR_INVALID_CHANNEL on its next frame, which is precisely
                # the answer that tells a host to allocate again. Nothing is
                # protected by a channel number -- any process that can reach the
                # device can use any identifier it knows -- so giving one up
                # protects nothing less than it did before.
                del self.channels[0]
            assigned = self._new_cid()
            if assigned in (0, BROADCAST) or assigned in self.channels:
                return self._error(cid, OTHER)
            self.channels.append(assigned)
        elif cid in self.channels:
            assigned = cid
            self._mark_used(cid)
        else:
            return self._error(cid, INVALID_CID)
        return self._event(
            cid,
            INIT,
            nonce + assigned.to_bytes(4, "big") + b"\x02\x00\x01\x00"
            + bytes((CAPABILITIES,)),
        )

    def feed(self, report: bytes, now_ms: int) -> TransportEvent | None:
        expired = self.tick(now_ms)
        if expired is not None:
            return expired
        cid = int.from_bytes(report[:4], "big")
        if len(report) != REPORT_SIZE:
            if self.cid == cid:
                self._abort()
            return self._error(cid, INVALID_LEN)
        marker = report[4]
        if marker == CANCEL:
            length = (report[5] << 8) | report[6]
            if length:
                if self.cid == cid:
                    self._abort()
                return self._error(cid, INVALID_LEN)
            return self.cancel(cid)
        if cid == 0 or (cid == BROADCAST and marker != INIT):
            return self._error(cid, INVALID_CID)

        if marker & 0x80:
            if self.cid is not None and self.cid != cid:
                return self._error(cid, CHANNEL_BUSY)
            if marker == INIT:
                if self.cid == cid:
                    self._abort()
                length = (report[5] << 8) | report[6]
                if length != 8:
                    return self._error(cid, INVALID_LEN)
                return self._init(cid, bytes(report[7:15]))
            if cid not in self.channels:
                return self._error(cid, INVALID_CID)
            self._mark_used(cid)
            if self.cid == cid:
                self._abort()
                return self._error(cid, INVALID_SEQ)
            length = (report[5] << 8) | report[6]
            if length > MAX_MESSAGE_SIZE:
                return self._error(cid, INVALID_LEN)
            if length <= 57:
                return self._event(cid, marker, bytes(report[7 : 7 + length]))
            self.cid = cid
            self.command = marker
            self.length = length
            self.payload = bytearray(report[7:64])
            self.sequence = 0
            self.last_ms = now_ms
            return None

        if self.cid is None:
            return self._error(cid, INVALID_SEQ)
        if cid != self.cid:
            return None
        if marker != self.sequence:
            self._abort()
            return self._error(cid, INVALID_SEQ)
        remaining = self.length - len(self.payload)
        self.payload.extend(report[5 : 5 + min(remaining, 59)])
        self.sequence += 1
        self.last_ms = now_ms
        if len(self.payload) < self.length:
            return None
        event = self._event(cid, self.command, self.payload)
        self._abort()
        return event


# How many times one report is offered before the interface is called dead, and
# how long each offer waits for the host to collect the previous report. A busy
# endpoint and a vanished one arrive here as the same OSError, so the only honest
# way to tell them apart is to keep offering for a bounded while. The common case
# costs one wait of about a millisecond: that is how long the host takes to poll
# an interrupt IN endpoint.
WRITE_ATTEMPTS = 10
WRITE_WAIT_MS = 50


def _write_report(iface, frame) -> None:
    """Put one report on the wire, outlasting a host that has not read yet.

    USBIF.write does not report a busy IN endpoint by returning zero; it raises
    OSError, exactly as it does for an interface that is gone. So the retry has to
    wrap the call rather than inspect its result.

    This is why a multi-report answer used to lose every frame after the first.
    The second write is issued about a microsecond after the first, long before
    the host has polled the endpoint, so it always raised -- and the caller read
    that raise as a disconnect and cleared the channel. Single-frame answers were
    unaffected, which is why INIT and a short PING worked on real hardware while
    GetInfo never did, and why the emulator never showed it: a UDP send has no
    busy state to report.
    """
    import trezorio

    for attempt in range(WRITE_ATTEMPTS):
        try:
            written = iface.write(frame)
        except OSError:
            # Out of attempts: pass the interface's own error on, and let the
            # caller tear the channel down. A half-sent message is not a message.
            if attempt == WRITE_ATTEMPTS - 1:
                raise
        else:
            # A short count is not busy-ness, and retrying would duplicate what
            # already went out.
            if written != REPORT_SIZE:
                raise OSError("partial CTAPHID write")
            return
        ready = [0, 0]
        trezorio.poll((iface.iface_num() | trezorio.POLL_WRITE,), ready, WRITE_WAIT_MS)


async def send_response(iface, cid: int, command: int, payload: bytes) -> None:
    """Write one bounded response without retaining a list of frames."""
    if not 0 < cid <= BROADCAST or not 0x80 <= command <= 0xFF:
        raise ValueError("invalid CTAPHID response")
    if len(payload) > MAX_MESSAGE_SIZE:
        raise ValueError("CTAPHID response too large")

    length = len(payload)
    offset = 0
    sequence = 0
    while True:
        if offset == 0:
            frame = (
                cid.to_bytes(4, "big")
                + bytes((command, length >> 8, length & 0xFF))
                + payload[:57]
            )
            offset = min(length, 57)
        else:
            frame = (
                cid.to_bytes(4, "big")
                + bytes((sequence,))
                + payload[offset : offset + 59]
            )
            offset += min(length - offset, 59)
            sequence += 1
        frame += bytes(REPORT_SIZE - len(frame))
        _write_report(iface, frame)
        if offset == length:
            return


class _Keepalive:
    """Says the device is still working, and which kind of waiting it is doing.

    Without this, a command that outlasts the host's transaction timeout is
    indistinguishable from a dead device, and a build that waits for a physical
    confirmation could not work at all: nobody inserts a card inside three
    seconds. The status matters as much as the frame, because a platform shows a
    prompt for one kind of waiting and a spinner for the other.

    Failing to send one is deliberately not a lifecycle event. Whether the channel
    is still alive is decided by the answer's own write, which is what the caller
    is actually waiting for; a keepalive nobody collected says nothing about that.
    """

    def __init__(self) -> None:
        self.event = None
        self.last_ms = None

    async def offer(self, iface, dispatcher, event, now_ms) -> None:
        if self.event is not event:
            # A different dispatch: speak at once rather than after an interval,
            # so a host learns immediately that work has begun.
            self.event = event
            self.last_ms = None
        if (
            self.last_ms is not None
            and ((now_ms - self.last_ms) & _TICKS_MASK) < KEEPALIVE_INTERVAL_MS
        ):
            return
        self.last_ms = now_ms
        status = (
            KEEPALIVE_UP_NEEDED
            if dispatcher.policy.presence_remaining_ms() is not None
            else KEEPALIVE_PROCESSING
        )
        try:
            await send_response(iface, event.cid, KEEPALIVE, bytes((status,)))
        except OSError:
            pass


class _PendingDispatch:
    """One cooperative dispatch; keep polling USB while presence is awaited."""

    def __init__(self):
        self.event = None
        self.task = None

    def start(self, dispatcher, event):
        self.event = event
        self.task = dispatcher.dispatch(event)

    def step(self):
        try:
            self.task.send(None)
        except StopIteration as result:
            self.event = None
            self.task = None
            return result.value
        return None

    def close(self):
        task = self.task
        self.event = None
        self.task = None
        if task is not None:
            task.close()

    def expire(self, dispatcher):
        """Abort an expired presence wait without ever resuming its handler."""
        if self.event is None or dispatcher.policy.presence_remaining_ms() != 0:
            return None
        event = self.event
        try:
            dispatcher.abort(event, "timeout")
        finally:
            self.close()
        return event

    def feed(self, transport, report, now):
        if self.event is None:
            return transport.feed(report, now)
        cid = int.from_bytes(report[:4], "big")
        if len(report) != REPORT_SIZE:
            return transport._error(cid, INVALID_LEN)
        command = report[4]
        if command == CANCEL:
            if cid != self.event.cid:
                return None
            if report[5] or report[6]:
                return transport._error(cid, INVALID_LEN)
            return transport._event(cid, CANCEL, b"")
        if command == INIT and cid == self.event.cid:
            return transport.feed(report, now)
        return transport._error(cid, CHANNEL_BUSY)


async def handle_reports(iface, dispatcher=None) -> None:
    from .dispatcher import default_dispatcher

    if dispatcher is None:
        import utime

        # This runs once for the life of the applet, so it is the moment the
        # device powered up -- the reference Reset's ten-second window needs.
        dispatcher = default_dispatcher(started_ms=utime.ticks_ms())
    transport = HidAssembler()
    pending = _PendingDispatch()
    try:
        await _handle_reports(iface, dispatcher, transport, pending, _Keepalive())
    finally:
        # Also covers generator close, interpreter reboot, and unexpected failures.
        try:
            pending.close()
        finally:
            transport.disconnect()
            dispatcher.abort(None, "reboot-or-exit")


async def _handle_reports(iface, dispatcher, transport, pending,
                          keepalive) -> None:
    import trezorio
    import utime

    from trezor import loop

    while True:
        try:
            ready = [0, 0]
            timeout = (
                10 if pending.event is not None
                else (FRAME_TIMEOUT_MS if transport.cid is not None else 1000)
            )
            remaining = dispatcher.policy.presence_remaining_ms()
            if pending.event is not None and remaining is not None:
                timeout = min(timeout, remaining)
            input_ready = trezorio.poll(
                (iface.iface_num() | trezorio.POLL_READ, trezorio.USB_EVENT),
                ready,
                timeout,
            )
            if not input_ready:
                event = transport.tick(utime.ticks_ms())
            elif ready[0] == trezorio.USB_EVENT:
                pending.close()
                transport.disconnect()
                dispatcher.abort(None, "usb-reset-or-disconnect")
                event = None
            else:
                size = ready[1]
                if size > REPORT_SIZE:
                    event = pending.feed(transport, b"", utime.ticks_ms())
                else:
                    report = bytearray(REPORT_SIZE)
                    try:
                        iface.read(report, 0)
                    except RuntimeError:
                        # USBIF read rejects a short physical report after copying it.
                        event = pending.feed(
                            transport, memoryview(report)[: REPORT_SIZE - 1], utime.ticks_ms()
                        )
                    else:
                        event = pending.feed(
                            transport, memoryview(report)[:size], utime.ticks_ms()
                        )
                    finally:
                        for i in range(len(report)):
                            report[i] = 0
            if event is not None:
                active = dispatcher.policy.key
                if event.command == CANCEL:
                    pending.close()
                    dispatcher.abort(event, "cancel")
                elif event.command == INIT:
                    pending.close()
                    dispatcher.abort(event, "channel-init")
                elif (
                    event.command == ERROR
                    and event.payload != bytes((CHANNEL_BUSY,))
                    and (
                        active is None or (
                            active.cid == event.cid
                            and active.connection_generation == event.connection_generation
                        )
                    )
                ):
                    pending.close()
                    dispatcher.abort(
                        event,
                        "timeout" if event.payload == bytes((MSG_TIMEOUT,)) else "transport-error",
                    )
            expired = pending.expire(dispatcher)
            if expired is not None:
                # Match the existing generic failure from a denied presence wait.
                # Cleanup/slot release must precede any output for this poll.
                await send_response(iface, expired.cid, CBOR, bytes((OTHER,)))
            if event is not None and event.command != CANCEL and event.cid != 0:
                command = event.command
                payload = event.payload
                if command == PING:
                    dispatcher.abort(event, "new-request")
                elif command == CBOR:
                    if payload:
                        pending.start(dispatcher, event)
                        payload = pending.step()
                        if payload is None:
                            await loop.checkpoint()
                            continue
                    else:
                        dispatcher.abort(event, "invalid-length")
                        command, payload = ERROR, bytes((INVALID_LEN,))
                elif command not in (INIT, ERROR):
                    dispatcher.abort(event, "invalid-command")
                    command, payload = ERROR, bytes((INVALID_CMD,))
                await send_response(iface, event.cid, command, payload)
            # Drain queued input before resuming an authorization waiter. In
            # particular, a fresh edge must not overtake CANCEL or USB reset.
            # Even foreign/busy traffic is followed by another poll so it cannot
            # hide lifecycle invalidation queued immediately behind it.
            if not input_ready and pending.event is not None:
                response_event = pending.event
                response = pending.step()
                if response is not None:
                    await send_response(iface, response_event.cid, CBOR, response)
                else:
                    # Still working, and the host has to be told so or it will
                    # give up. This is the only place it can be told: no input
                    # arrived this poll, so no lifecycle event is queued behind
                    # the keepalive, and expiry has already been dealt with.
                    await keepalive.offer(
                        iface, dispatcher, response_event, utime.ticks_ms()
                    )
        except OSError:
            pending.close()
            transport.disconnect()
            dispatcher.abort(None, "disconnect")
        await loop.checkpoint()
