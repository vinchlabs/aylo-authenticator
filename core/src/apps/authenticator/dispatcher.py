"""Typed CTAP command dispatch. Decides nothing a command is allowed to do."""

from .cbor_codec import CtapError, decode_request, encode_response
from .command_types import CommandContext
from .policy import CONTINUATION, Policy
from .protocol import GET_INFO

# The payloads a live transaction is allowed to survive, byte for byte. A
# continuation is the one case where a second request reuses an authorization
# already paid for, so the exemption is spelled out as whole payloads rather than
# as a command number: anything else on the channel, including a different
# credential-management subcommand, ends the transaction it arrives on.
CONTINUATION_PAYLOADS = (
    b"\x08",              # authenticatorGetNextAssertion
    b"\x0a\xa1\x01\x03",  # credentialManagement: enumerateRPsGetNextRP
    b"\x0a\xa1\x01\x05",  # credentialManagement: enumerateCredentialsGetNextCredential
    b"\x41\xa1\x01\x03",  # the same two under the preview command number
    b"\x41\xa1\x01\x05",
)

# Credential management has two command numbers. 0x0A is CTAP 2.1's; 0x41 is the
# number CTAP 2.1-PRE gave the same thing, and it is not optional in practice --
# libfido2 1.10, which is what Debian 12 and Ubuntu 22.04 ship and therefore what
# OpenSSH uses on them, sends 0x41 and nothing else. A key that answers only 0x0A
# cannot enumerate or delete a resident credential from those systems at all. The
# subcommands, the authorization and the handler are identical; only the number
# differs, so one handler serves both.
COMMANDS = (1, 2, 4, 6, 7, 8, 10, 11, 0x41)


class Dispatcher:
    def __init__(self, cleanup=None) -> None:
        self._handlers = {}
        self.policy = Policy()
        self._cleanup = cleanup

    def register(self, command: int, handler) -> None:
        if command not in COMMANDS:
            raise ValueError("unsupported CTAP command")
        if command in self._handlers:
            raise ValueError("duplicate CTAP handler")
        self._handlers[command] = handler

    def abort(self, event, reason: str) -> None:
        """Erase policy state before any observer or error response."""
        self.policy.abort(reason)
        context = None if event is None else CommandContext(
            event.connection_generation, event.cid,
            event.payload[0] if event.command == 0x90 and event.payload else event.command,
        )
        if self._cleanup is not None:
            self._cleanup(context, reason)

    def _error(self, event, reason: str, code: int) -> bytes:
        try:
            self.abort(event, reason)
        except Exception:
            return b"\x7f"
        return bytes((code,))

    async def dispatch(self, event) -> bytes:
        """Return a full CTAPHID CBOR payload, including its status byte."""
        active = self.policy.key
        if active is not None and not (
            active.connection_generation == event.connection_generation
            and active.cid == event.cid
            and event.command == 0x90
            and event.payload in CONTINUATION_PAYLOADS
            and self.policy.state == CONTINUATION
        ):
            try:
                self.abort(event, "new-request")
            except Exception:
                return bytes((0x7F,))
        if event.command != 0x90:
            return self._error(event, "invalid-command", 0x01)
        if not event.payload:
            return self._error(event, "validation", 0x03)
        command = event.payload[0]
        if command not in COMMANDS:
            return self._error(event, "invalid-command", 0x01)
        handler = self._handlers.get(command)
        if handler is None and command != 4:
            return self._error(event, "operation-denied", 0x27)
        try:
            request = decode_request(command, event.payload[1:])
            if handler is None:
                return b"\x00" + GET_INFO
            context = CommandContext(event.connection_generation, event.cid, command)
            value = await handler(request, context)
            if self.policy.key is not None:
                self.policy.complete_response(self.policy.key)
            return b"\x00" if value is None else b"\x00" + encode_response(value)
        except CtapError as exc:
            return self._error(event, "validation", exc.code)
        except Exception:
            return self._error(event, "exception", 0x7F)


def default_dispatcher(cleanup=None, started_ms=None) -> Dispatcher:
    """The handler set this firmware actually serves.

    Dispatcher stays handler-agnostic so tests can assemble any subset; this is
    the one place that says which subset is real. A command left without a
    handler is answered CTAP2_ERR_OPERATION_DENIED, so the surface grows only as
    handlers are enabled and tested rather than by default. Every CTAP command
    this firmware accepts now has one.

    `started_ms` is when this device powered up, which only Reset needs and only
    the transport can honestly supply. Without it Reset refuses, because a window
    that cannot be shown to be open must not be treated as open.
    """
    from . import (
        client_pin, credential_management, get_assertion, get_info,
        make_credential, reset,
    )

    dispatcher = Dispatcher(cleanup)
    get_info.register(dispatcher)
    client_pin.register(dispatcher)
    make_credential.register(dispatcher)
    get_assertion.register(dispatcher)
    credential_management.register(dispatcher)
    reset.register(dispatcher, started_ms=started_ms)
    return dispatcher
