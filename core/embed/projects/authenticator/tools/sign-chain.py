#!/usr/bin/env python3
"""Sign one boot-chain artifact with one of the project's own key sets.

    sign-chain.py KEYSET FILE [--keys PATH] [--indexes 1:2]

KEYSET is boardloader_keys, bootloader_keys or vendor_keys. Which one is correct is a
property of what verifies the artifact, not of the artifact's name:

    bootloader image  <- boardloader_keys  (the boardloader checks it)
    vendor header     <- bootloader_keys   (the bootloader checks it)
    firmware image    <- vendor_keys       (the vendor header carries them)

The digest comes from headertool (-d), the CoSi signature is produced here, and the
signature goes back through headertool (-s). The alternative, headertool -S, puts a
root private key in a command line; this does not.

The key file is JSON and is never part of this repository:

    {"sets": {"boardloader_keys": [{"private": "<64 hex>", "public": "<64 hex>"},
                                   ... three entries ...],
              "bootloader_keys":  [...],
              "vendor_keys":      [...]}}

Give its path with --keys or in AYLO_ROOT_KEYS. For keys that outlive the device,
prefer the offline flow in docs/authenticator/activation.md, where the private halves
never reach a networked machine at all.
"""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import re
import subprocess
import sys

TOOLS = pathlib.Path(__file__).resolve().parent
# tools -> authenticator -> projects -> embed -> core -> repository root
REPO = TOOLS.parents[4]
HEADERTOOL = REPO / "core/tools/trezor_core_tools/headertool.py"

KEYSETS = ("boardloader_keys", "bootloader_keys", "vendor_keys")


def headertool(*args: str) -> str:
    result = subprocess.run(
        [sys.executable, str(HEADERTOOL), *args],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise SystemExit(f"headertool {' '.join(args)} failed:\n{result.stderr}")
    return result.stdout


def parse_indexes(raw: str) -> tuple[int, ...]:
    try:
        indexes = tuple(int(part) for part in raw.split(":"))
    except ValueError:
        raise SystemExit(f"--indexes wants colon-separated integers, got {raw!r}")
    if len(indexes) < 2:
        raise SystemExit("at least two signers are required (2-of-3)")
    if not all(1 <= i <= 3 for i in indexes):
        raise SystemExit("key indexes are 1-based and at most 3")
    if len(set(indexes)) != len(indexes):
        raise SystemExit("a key cannot sign twice")
    return indexes


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("keyset", choices=KEYSETS)
    parser.add_argument("target", help="artifact to sign, modified in place")
    parser.add_argument(
        "--keys",
        default=os.environ.get("AYLO_ROOT_KEYS"),
        help="path to the root key JSON (default: $AYLO_ROOT_KEYS)",
    )
    parser.add_argument(
        "--indexes",
        default="1:2",
        help="which 1-based keys sign, colon separated (default 1:2); the third "
        "stays unused so it can replace either if one is lost",
    )
    args = parser.parse_args()

    if not args.keys:
        raise SystemExit(
            "no key file: pass --keys PATH or set AYLO_ROOT_KEYS. This repository "
            "contains no private keys and must not acquire any."
        )
    keyfile = pathlib.Path(args.keys)
    if not keyfile.is_file():
        raise SystemExit(f"key file not found: {keyfile}")

    indexes = parse_indexes(args.indexes)
    document = json.loads(keyfile.read_text())
    try:
        entries = document["sets"][args.keyset]
    except KeyError:
        raise SystemExit(f"key file has no set {args.keyset!r}")
    if len(entries) < max(indexes):
        raise SystemExit(
            f"set {args.keyset!r} holds {len(entries)} keys, "
            f"index {max(indexes)} was requested"
        )

    sys.path.insert(0, str(REPO / "python/src"))
    from trezorlib import cosi

    privkeys = [bytes.fromhex(entries[i - 1]["private"]) for i in indexes]

    out = headertool("-d", args.target)
    # The digest is the only hex blob of that length the tool prints; matching it
    # rather than a line position keeps this working if the wording changes.
    found = re.findall(r"\b[0-9a-f]{64}\b", out)
    if len(found) != 1:
        raise SystemExit(f"expected one digest from headertool -d, got: {out!r}")
    digest = bytes.fromhex(found[0])

    signature = cosi.sign_with_privkeys(digest, privkeys)
    mask = ":".join(str(i) for i in indexes)
    print(headertool(args.target, "-s", mask, signature.hex()).strip())

    # Re-read and report, so the result is checked by the same parser the device
    # effectively uses rather than trusted because the write returned success.
    print(headertool(args.target).strip())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
