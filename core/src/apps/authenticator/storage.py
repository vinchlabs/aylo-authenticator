"""Bounded storage interface with no backend, on purpose.

Every call here fails closed. Credentials live in the vault, which the applet
reaches through `trezorauth`, so nothing persistent is reachable from this side.
"""

MAX_VALUE_LENGTH = 1024


class StorageUnavailable(Exception):
    pass


def _check_key(key: int) -> None:
    if not 0 <= key <= 0xFFFF:
        raise ValueError("invalid storage key")


def read(key: int) -> bytes:
    _check_key(key)
    raise StorageUnavailable("secure authenticator storage unavailable")


def write(key: int, value: bytes) -> None:
    _check_key(key)
    if len(value) > MAX_VALUE_LENGTH:
        raise ValueError("storage value too long")
    raise StorageUnavailable("secure authenticator storage unavailable")


def delete(key: int) -> None:
    _check_key(key)
    raise StorageUnavailable("secure authenticator storage unavailable")
