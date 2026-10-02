"""Write a release record describing an artifact and the tree that produced it.

Separate from audit_release.py on purpose: a gate that fills in its own answers is not
a gate. This collects facts, refuses to invent the ones it cannot collect, and leaves
the human answers blank so the audit fails until a person supplies them.

    python3 release_record.py --image PATH --unsigned PATH --mode development \
        --security-version 3 --build-command "..." --out release.json
"""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import re
import subprocess
import sys

MODEL = "T3T1"
PRODUCT = "authenticator"


def _run(command, cwd):
    try:
        done = subprocess.run(command, cwd=cwd, capture_output=True, text=True,
                              timeout=120)
    except (OSError, subprocess.TimeoutExpired):
        return None
    return done.stdout.strip() if done.returncode == 0 else None


def _commit(repo):
    return _run(["git", "rev-parse", "HEAD"], repo)


def _submodules(repo):
    """name -> revision, from git's own view rather than from a list kept by hand."""
    text = _run(["git", "submodule", "status", "--recursive"], repo)
    if text is None:
        return {}
    found = {}
    for line in text.splitlines():
        match = re.match(r"^[\s+\-U]?([0-9a-f]{40})\s+(\S+)", line.strip())
        if match:
            found[match.group(2)] = match.group(1)
    return found


def _toolchain(repo):
    """Only the versions that can actually be read. A tool that is absent is recorded
    as absent rather than as a guess, so the record cannot claim a pin it lacks."""
    found = {}
    for name, command in (
        ("rustc", ["rustc", "--version"]),
        ("cargo", ["cargo", "--version"]),
        ("arm-none-eabi-gcc", ["arm-none-eabi-gcc", "--version"]),
        ("python", [sys.executable, "--version"]),
    ):
        text = _run(command, repo)
        if text:
            found[name] = text.splitlines()[0]
    return found


def _usb_identity(mode):
    # Development is the allocated pid.codes pair this project uses. Production has no
    # allocation yet, and a placeholder here would be a production record that passes
    # the audit while naming an identity nobody granted -- so it is left absent and
    # the audit refuses the record until it is supplied.
    if mode == "development":
        return {"vendor": 0x1209, "product": 0x53C1}
    return None


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--image", type=pathlib.Path, required=True)
    parser.add_argument("--unsigned", type=pathlib.Path, required=True,
                        help="the payload before signing, for the reproducible hash")
    parser.add_argument("--mode", choices=("development", "production"),
                        required=True)
    parser.add_argument("--security-version", type=int, required=True)
    parser.add_argument("--build-command", required=True)
    parser.add_argument("--repo", type=pathlib.Path,
                        default=pathlib.Path(__file__).resolve().parents[4])
    parser.add_argument("--out", type=pathlib.Path, required=True)
    arguments = parser.parse_args()

    image = arguments.image.read_bytes()
    unsigned = arguments.unsigned.read_bytes()
    commit = _commit(arguments.repo)

    record = {
        "mode": arguments.mode,
        "model": MODEL,
        "product": PRODUCT,
        "source_commit": commit or "",
        "submodules": _submodules(arguments.repo),
        "toolchain": _toolchain(arguments.repo),
        "build_command": arguments.build_command,
        "unsigned_sha256": hashlib.sha256(unsigned).hexdigest(),
        "image_sha256": hashlib.sha256(image).hexdigest(),
        "image_bytes": len(image),
        "security_version": arguments.security_version,
        "signing_keys": {
            "generation": 0 if arguments.mode == "development" else 0,
            "development": arguments.mode == "development",
        },
        # Left for a person. Every one of these fails the audit while it is false,
        # which is the only reason writing them down accomplishes anything.
        "checklist": {},
    }
    identity = _usb_identity(arguments.mode)
    if identity is not None:
        record["usb_identity"] = identity

    arguments.out.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n",
                             encoding="utf-8")
    print("wrote %s" % arguments.out)
    print("  commit      %s" % (commit or "UNKNOWN -- git could not be read"))
    print("  submodules  %d pinned" % len(record["submodules"]))
    print("  toolchain   %s" % ", ".join(sorted(record["toolchain"])) or "none")
    print("  unsigned    %s" % record["unsigned_sha256"])
    print("  image       %s  (%d bytes)" % (record["image_sha256"],
                                            record["image_bytes"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
