# Contributing

This is a fork of [trezor-firmware](https://github.com/trezor/trezor-firmware)
carrying a headless FIDO2 authenticator for the Trezor Safe 5. Changes to upstream
code that are not about the authenticator belong upstream, not here.

Upstream's general instructions still apply to the rest of the tree and are kept at
[`docs/misc/contributing.md`](docs/misc/contributing.md). What follows is particular
to this fork.

## Ground rules

**Claims are proven, not asserted.** A commit that says the device refuses something
should be accompanied by the refusal. "It built" and "the call returned success" are
not evidence that a device behaved correctly; a readback, a hash, or the error the
host actually received is.

**A failed build must not fall through to a signing step.** There is usually a
plausible-looking artifact from the previous build still sitting in the output
directory, and signing it produces a file nobody asked for.

**Do not weaken a guard to make a build work.** Two guards in this tree once required
`headless_dev` to imply `bootloader_devel`, which forced "no display" and "signed with
published keys" to travel together. If a guard is wrong, change it deliberately and
say why in the commit; do not route around it.

**No private key enters this repository**, any build output, or any artifact
directory. `headertool` can sign from a digest without ever seeing one. Use that.

**Irreversible operations are not routine.** Anything that advances the monotonic
counter, writes an option byte, changes RDP, or erases the secret area at
`0x0C000000` belongs in a separate, approved procedure with a readback of the prior
state attached. `docs/authenticator/protection-manifest.md` records that state and
deliberately contains no command that changes it.

## Before opening a pull request

- The applet suites pass: `core/tests/run_authenticator_suites.sh`.
- The vault's native tests pass, and the tool tests under
  `core/embed/projects/authenticator/tools/`.
- `audit_image.py` passes on the resulting image. It needs the build's `.map`, `.elf`
  and frozen-module inputs, so run it from the build directory rather than against a
  bare `.bin`.
- Upstream's formatting holds: `make style_check` in the repository root.
- Commit messages follow [Conventional Commits](COMMITS.md).

## Documentation that must stay true

Four documents describe what the device is, not what it is meant to become. A change
that alters any of them must update them in the same commit:

- `docs/authenticator/activation.md` -- the four irreversible steps and their state
- `docs/authenticator/recovery.md` -- what cannot be recovered, written for the person
  holding the key
- `docs/authenticator/protection-manifest.md` -- observed hardware protection state
- `docs/authenticator/release-checklist.md` -- the items a program cannot check

If a document and the code disagree, the document is a defect.
