"""Deterministic bounded CTAP request-parser corpus (CPython, no hardware)."""

import pathlib
import random
import signal
import sys
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2] / "src"))

from apps.authenticator import cbor_codec as codec


COMMANDS = (1, 2, 4, 6, 7, 8, 10, 11)
SEEDS = (
    b"", b"\xa0", b"\xbf\xff", b"\x9f\xff", b"\xff",
    b"\xa2\x01\x00\x01\x01", b"\xa2\x02\x00\x01\x00",
    b"\xa1\x18\x01\x00", b"\xa1\x01\xc0\x00",
    b"\xa1\x01\x58\xff" + bytes(255),
    b"\xba\xff\xff\xff\xff", bytes(1024), bytes(1025),
)


def corpus():
    for value in SEEDS:
        yield value
    generator = random.Random(0x435441503231)
    lengths = (0, 1, 2, 3, 4, 16, 32, 64, 128, 255, 512, 1024, 1025)
    for index in range(1500):
        size = lengths[index % len(lengths)]
        yield generator.randbytes(size)


def main():
    before = (tuple(codec._SCHEMAS.items()), tuple(codec._NO_PARAMS.items()))
    signal.alarm(30)
    start = time.monotonic()
    checked = 0
    try:
        for payload in corpus():
            for command in COMMANDS:
                try:
                    codec.decode_request(command, payload)
                except codec.CtapError:
                    pass
                checked += 1
            assert before == (tuple(codec._SCHEMAS.items()), tuple(codec._NO_PARAMS.items()))
    finally:
        signal.alarm(0)
    print("CTAP CBOR fuzz PASS: %d parses, %.3fs, no uncaught exception or parser state mutation" % (checked, time.monotonic() - start))


if __name__ == "__main__":
    main()
