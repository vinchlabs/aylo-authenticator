"""The release gate for the authenticator image.

audit_image.py asks whether an artifact was built from this design. This asks whether
an artifact is a release: whether the record in front of us describes these exact
bytes, whether the inputs that produced them were pinned, whether it is signed by keys
that are not public knowledge, and whether the things only a person can check have
been answered by a person.

Every rule here is one a perfectly good artifact can still fail. A rule that passes
for everything is not a gate.

    python3 audit_release.py --record release.json --image authenticator.bin \
        [--mode production]

Exits 0 and prints one PASS line, or exits 1 and prints every reason.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import re
import sys

# The counter in STM32U5 secret flash is a unary run of 16-byte lines over 0x400
# bytes, so it represents 0..63 and nothing above. A release that names 64 cannot be
# committed by the bootloader and would install and then refuse to boot.
MONOTONIC_MAX = 63

# A release must say which of these it is, because the two have different rules.
MODES = ("development", "production")

# Fields the record has to carry for the build to be reproducible from it alone.
# Each one is something a second person needs in order to rebuild these bytes.
REQUIRED_FIELDS = (
    "mode",              # development or production
    "model",             # T3T1
    "product",           # authenticator
    "source_commit",     # the commit the tree was at
    "submodules",        # name -> revision, for every submodule that is built
    "toolchain",         # name -> version or hash, enough to pin the compiler
    "build_command",     # the exact command, so it can be run again
    "unsigned_sha256",   # the payload hash before signing
    "image_sha256",      # the signed image hash, which must match --image
    "image_bytes",       # the length, so a truncated artifact is caught
    "security_version",  # the monotonic value this release claims
    "usb_identity",      # {"vendor": int, "product": int}
    "signing_keys",      # {"generation": int, "development": bool}
    "checklist",         # name -> bool, the human sign-offs
)

MODEL = "T3T1"
PRODUCT = "authenticator"

# A hex digest and nothing else. Accepting "sha256:..." or uppercase would mean two
# spellings of one fact, and a comparison that silently fails on the other.
DIGEST = re.compile(r"^[0-9a-f]{64}$")

# Development identity, from audit_image.py. A production release may not carry it.
DEV_IDENTITY = (0x1209, 0x53C1)

# Every one of these has to be answered true before a production release. They are
# the items that no program can check, which is exactly why they are listed rather
# than assumed.
PRODUCTION_CHECKLIST = (
    "two_offline_root_key_backups",
    "release_key_rotation_procedure",
    "second_authenticator_enrolled",
    "recovery_codes_recorded",
    "independent_hash_comparison",
    "independent_security_review",
    "option_bytes_readback_recorded",
)


class Problems:
    """Collects every reason rather than stopping at the first."""

    def __init__(self) -> None:
        self.reasons: list[str] = []

    def require(self, condition: object, reason: str) -> bool:
        if not condition:
            self.reasons.append(reason)
            return False
        return True


def _digest(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def check_release(record: dict, image: bytes, image_name: str) -> list[str]:
    """Returns every reason this is not a release, or an empty list."""
    problems = Problems()

    missing = [field for field in REQUIRED_FIELDS if field not in record]
    for field in missing:
        problems.require(False, "the record does not say %s" % field)
    if missing:
        # Without the fields there is nothing to judge, and guessing which checks
        # can still run would mean reporting a release as nearly valid.
        return problems.reasons

    mode = record["mode"]
    problems.require(mode in MODES,
                     "mode is %r, which is neither of %s" % (mode, MODES))
    problems.require(record["model"] == MODEL,
                     "model is %r, not %s" % (record["model"], MODEL))
    problems.require(record["product"] == PRODUCT,
                     "product is %r, not %s" % (record["product"], PRODUCT))

    # The record must describe these bytes. This is the rule that makes every other
    # field mean something: without it the record could describe a different build.
    actual = hashlib.sha256(image).hexdigest()
    problems.require(DIGEST.match(str(record["image_sha256"])),
                     "image_sha256 is not a lowercase hex sha256 digest")
    problems.require(record["image_sha256"] == actual,
                     "the record says the image is %s, but %s hashes to %s"
                     % (record["image_sha256"], image_name, actual))
    problems.require(DIGEST.match(str(record["unsigned_sha256"])),
                     "unsigned_sha256 is not a lowercase hex sha256 digest")
    problems.require(record["unsigned_sha256"] != record["image_sha256"],
                     "the unsigned and signed hashes are equal, so one of them is "
                     "not what it claims to be")
    problems.require(record["image_bytes"] == len(image),
                     "the record says %r bytes, the image is %d"
                     % (record["image_bytes"], len(image)))

    # Reproducibility inputs. Present is not enough: a blank commit or an empty
    # toolchain map pins nothing, and would let a record claim reproducibility it
    # cannot support.
    commit = str(record["source_commit"])
    problems.require(re.match(r"^[0-9a-f]{40}$", commit),
                     "source_commit %r is not a full 40-character hash" % commit)
    problems.require(isinstance(record["submodules"], dict),
                     "submodules is not a map of name to revision")
    toolchain = record["toolchain"]
    problems.require(isinstance(toolchain, dict) and len(toolchain) > 0,
                     "toolchain pins nothing")
    problems.require(str(record["build_command"]).strip() != "",
                     "build_command is empty, so the build cannot be repeated")

    version = record["security_version"]
    problems.require(isinstance(version, int) and not isinstance(version, bool),
                     "security_version %r is not an integer" % (version,))
    if isinstance(version, int) and not isinstance(version, bool):
        problems.require(version > 0,
                         "security_version is %d; a release with no anti-rollback "
                         "value has no anti-rollback" % version)
        problems.require(version <= MONOTONIC_MAX,
                         "security_version %d is above %d, which the counter cannot "
                         "hold -- the image would install and refuse to boot"
                         % (version, MONOTONIC_MAX))

    identity = record["usb_identity"]
    problems.require(isinstance(identity, dict)
                     and set(identity) == {"vendor", "product"},
                     "usb_identity must be a map of exactly vendor and product")
    keys = record["signing_keys"]
    problems.require(isinstance(keys, dict)
                     and set(keys) == {"generation", "development"},
                     "signing_keys must be a map of exactly generation and "
                     "development")

    checklist = record["checklist"]
    problems.require(isinstance(checklist, dict),
                     "checklist is not a map of item to answer")

    if mode == "production" and isinstance(keys, dict):
        # The development private keys are public knowledge -- the comment in
        # root_keys.h says so and names where they are published -- so a production
        # release signed with them is a release anyone can forge.
        problems.require(keys.get("development") is False,
                         "a production release is signed with development keys, "
                         "whose private halves are published")
        problems.require(isinstance(keys.get("generation"), int)
                         and not isinstance(keys.get("generation"), bool)
                         and keys.get("generation") > 0,
                         "a production release must name a signing key generation")
    if mode == "production" and isinstance(identity, dict):
        problems.require(
            (identity.get("vendor"), identity.get("product")) != DEV_IDENTITY,
            "a production release carries the development USB identity %04x:%04x"
            % DEV_IDENTITY)
    if mode == "production" and isinstance(checklist, dict):
        for item in PRODUCTION_CHECKLIST:
            problems.require(
                checklist.get(item) is True,
                "the checklist item %s is not answered yes" % item)

    return problems.reasons


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--record", type=pathlib.Path, required=True)
    parser.add_argument("--image", type=pathlib.Path, required=True)
    arguments = parser.parse_args()

    try:
        record = json.loads(arguments.record.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        print("release record unreadable: %s" % error)
        return 1
    if not isinstance(record, dict):
        print("release record is not an object")
        return 1
    try:
        image = arguments.image.read_bytes()
    except OSError as error:
        print("image unreadable: %s" % error)
        return 1

    reasons = check_release(record, image, arguments.image.name)
    if reasons:
        for reason in reasons:
            print("release audit: %s" % reason)
        print("authenticator %s release audit: FAIL (%d reason(s))"
              % (record.get("mode", "?"), len(reasons)))
        return 1
    print("authenticator %s release audit: PASS" % record["mode"])
    return 0


if __name__ == "__main__":
    sys.exit(main())
