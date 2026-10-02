"""Command dispatch does not grant unregistered operations or retain state."""

import asyncio
import os
import sys
import types

sys.path.remove(os.path.dirname(__file__))
import unittest

from apps.authenticator.dispatcher import Dispatcher
from apps.authenticator.transport_types import TransportEvent
from apps.authenticator.transport import handle_reports


def event(command, body=b"", generation=3, cid=7):
    return TransportEvent(generation, cid, 0x90, bytes((command,)) + body)


class DispatchTests(unittest.TestCase):
    def run_dispatch(self, dispatcher, message):
        return asyncio.run(dispatcher.dispatch(message))

    def test_get_info_only_until_handler_registration(self):
        dispatcher = Dispatcher()
        self.assertTrue(self.run_dispatch(dispatcher, event(4)).startswith(b"\x00\xa4"))
        self.assertEqual(self.run_dispatch(dispatcher, event(1, b"\xa0")), b"\x27")
        # largeBlobs: a command CTAP defines and this firmware does not serve.
        self.assertEqual(self.run_dispatch(dispatcher, event(0x0C)), b"\x01")
        self.assertEqual(self.run_dispatch(dispatcher, event(4, b"\xa0")), b"\x02")

    def test_registered_handler_gets_typed_request_and_encoded_response(self):
        dispatcher = Dispatcher()

        async def handler(request, message):
            self.assertEqual(request.__class__.__name__, "GetAssertionRequest")
            self.assertFalse(hasattr(request, "raw"))
            self.assertEqual((message.connection_generation, message.cid), (3, 7))
            self.assertFalse(hasattr(message, "payload"))
            return {1: b"ok"}

        dispatcher.register(2, handler)
        request = b"\xa2\x01\x6bexample.com\x02\x58\x20" + bytes(32)
        self.assertEqual(self.run_dispatch(dispatcher, event(2, request)), b"\x00\xa1\x01\x42ok")
        with self.assertRaises(ValueError):
            dispatcher.register(2, handler)

    def test_management_metadata_handler_auth_ignores_extra_params(self):
        dispatcher = Dispatcher()

        async def handler(request, context):
            self.assertEqual(request.__class__.__name__, "CredentialManagementRequest")
            self.assertEqual(request.auth_material, expected)
            self.assertFalse(hasattr(request, "subcommand_params"))
            self.assertFalse(hasattr(context, "payload"))
            return {1: True}

        dispatcher.register(10, handler)
        for expected in (b"\x01", b"\x02"):
            body = b"\xa4\x01" + expected + b"\x02\xa1\x18\x63\xf4\x03\x01\x04\x50" + bytes(16)
            self.assertEqual(self.run_dispatch(dispatcher, event(10, body)), b"\x00\xa1\x01\xf5")

    def test_management_parameter_handler_gets_exact_auth_bytes_without_raw_map(self):
        dispatcher = Dispatcher()

        async def handler(request, context):
            self.assertEqual(request.__class__.__name__, "CredentialManagementRequest")
            self.assertEqual(request.auth_material, expected)
            self.assertFalse(hasattr(request, "subcommand_params"))
            self.assertFalse(hasattr(context, "payload"))
            return {1: True}

        dispatcher.register(10, handler)
        descriptor = b"\xa2\x62id\x41x\x64type\x6apublic-key"
        for subcommand, params in ((b"\x04", b"\xa2\x01\x58\x20" + bytes(32) + b"\x18\x63\xf4"),
                                   (b"\x06", b"\xa2\x02" + descriptor + b"\x18\x63\xf4"),
                                   (b"\x07", b"\xa3\x02" + descriptor + b"\x03\xa1\x62id\x41u\x18\x63\xf4")):
            expected = subcommand + params
            body = b"\xa4\x01" + subcommand + b"\x02" + params + b"\x03\x01\x04\x50" + bytes(16)
            self.assertEqual(self.run_dispatch(dispatcher, event(10, body)), b"\x00\xa1\x01\xf5")

    def test_errors_invoke_cleanup_before_response(self):
        calls = []

        def cleanup(message, reason):
            calls.append((message.cid, message.command, reason))

        dispatcher = Dispatcher(cleanup=cleanup)

        async def exploding(request, message):
            raise RuntimeError("secret operation failed")

        dispatcher.register(2, exploding)
        malformed = event(2, b"\xbf\xff")
        self.assertEqual(self.run_dispatch(dispatcher, malformed), b"\x12")
        self.assertEqual(calls, [(7, 2, "validation")])
        calls.clear()
        valid = event(2, b"\xa2\x01\x6bexample.com\x02\x58\x20" + bytes(32))
        self.assertEqual(self.run_dispatch(dispatcher, valid), b"\x7f")
        self.assertEqual(calls, [(7, 2, "exception")])
        dispatcher.abort(valid, "disconnect")
        self.assertEqual(calls[-1], (7, 2, "disconnect"))

    def test_cleanup_failure_still_fails_closed(self):
        def broken_cleanup(message, reason):
            raise RuntimeError("cleanup failed")

        dispatcher = Dispatcher(cleanup=broken_cleanup)
        self.assertEqual(self.run_dispatch(dispatcher, event(2, b"\xbf\xff")), b"\x7f")

    def test_hid_loop_routes_registered_typed_handler(self):
        class StopPoll(Exception):
            pass

        class Interface:
            def __init__(self):
                body = b"\x02\xa2\x01\x6bexample.com\x02\x58\x20" + bytes(32)
                self.reports = [
                    (0xFFFFFFFF).to_bytes(4, "big") + b"\x86\x00\x08abcdefgh" + bytes(49),
                    (7).to_bytes(4, "big") + bytes((0x90, 0, len(body))) + body + bytes(57 - len(body)),
                ]
                self.current = b""
                self.frames = []

            def iface_num(self):
                return 0x10

            def read(self, target, offset):
                target[:] = self.current

            def write(self, frame):
                self.frames.append(frame)
                return 64

        iface = Interface()
        dispatcher = Dispatcher()

        async def handler(request, message):
            return {1: request.rp_id}

        dispatcher.register(2, handler)
        old = {name: sys.modules.get(name) for name in ("trezorio", "utime", "trezor", "trezorcrypto")}
        io = types.ModuleType("trezorio")
        io.POLL_READ = 1
        io.POLL_WRITE = 2
        io.USB_EVENT = 8

        def poll(events, ready, timeout):
            if not iface.reports:
                raise StopPoll()
            iface.current = iface.reports.pop(0)
            ready[:] = [iface.iface_num(), 64]
            return True

        async def checkpoint():
            return None

        io.poll = poll
        sys.modules["trezorio"] = io
        sys.modules["utime"] = types.SimpleNamespace(ticks_ms=lambda: 1)
        sys.modules["trezor"] = types.SimpleNamespace(loop=types.SimpleNamespace(checkpoint=checkpoint))
        crypto = types.ModuleType("trezorcrypto")
        crypto.random = types.SimpleNamespace(bytes=lambda n: (7).to_bytes(n, "big"))
        sys.modules["trezorcrypto"] = crypto
        try:
            with self.assertRaises(StopPoll):
                handle_reports(iface, dispatcher).send(None)
        finally:
            for name, original in old.items():
                if original is None:
                    sys.modules.pop(name, None)
                else:
                    sys.modules[name] = original
        self.assertEqual(iface.frames[1][4:8], b"\x90\x00\x0f\x00")
        self.assertIn(b"example.com", iface.frames[1])


if __name__ == "__main__":
    unittest.main()
