"""Minimal bounded USB polling primitive for authenticator services."""

import trezorio


class _Checkpoint:
    def __await__(self):
        yield None

    __iter__ = __await__


def checkpoint():
    return _Checkpoint()


def run(task) -> None:
    """Drive the sole authenticator task between bounded USB poll steps."""
    while True:
        try:
            task.send(None)
        except StopIteration:
            return


def poll_read(iface, timeout_ms: int = 1000) -> int:
    if not 0 <= timeout_ms <= 1000:
        raise ValueError("invalid poll timeout")
    ready = [0, 0]
    if trezorio.poll((iface.iface_num() | trezorio.POLL_READ,), ready, timeout_ms):
        return ready[1]
    return 0
