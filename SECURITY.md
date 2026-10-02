# Security policy

## This is a fork, and reports do not go upstream

This repository is an independent fork of
[trezor-firmware](https://github.com/trezor/trezor-firmware). **Do not report issues
found in this fork to SatoshiLabs or Trezor.** They did not write this code, cannot fix
it, and have not reviewed it.

If a vulnerability is in upstream code and reproduces on unmodified upstream firmware,
it belongs to [Trezor's disclosure process](https://trezor.io/security). Anything in
the files this fork adds or changes -- the CTAP applet, the vault, the update policy,
the vendor header, the build guards -- belongs here.

## Reporting

Use GitHub's private vulnerability reporting on this repository (Security → Report a
vulnerability). That keeps the report out of public view until there is something to
say about it.

Useful in a report: the firmware's GetInfo build marker (key `0xF0`), the commit the
image was built from, and what the device actually did rather than what it should have
done.

## Known and accepted weaknesses

These are documented, deliberate, and not vulnerabilities in the sense of this policy.
Reporting them is welcome but will be closed as known.

- **User presence is assumed.** A build reporting `AUTH-DEV-NOUP` confirms every
  operation by itself, because the hardware gesture is not wired to anything a person
  can act on. Possession plus the PIN is the whole of its security.
- **Debug access is open.** RDP 0, SWD available. Flash can be read and rewritten by
  anyone holding the device. See `docs/authenticator/protection-manifest.md`.
- **No anti-rollback.** The monotonic counter sits at the model default, so older
  signed images are still accepted.
- **Development USB identity.** `1209:53c1` is pid.codes development space.
- **`uv` is reported `false` though no built-in verification method exists.** Required
  for OpenSSH to select the key; it grants nothing, because both credential commands
  stay behind a verified PIN. Reasoning is at the definition in
  `core/src/apps/authenticator/get_info.py`.
- **Nothing can be backed up.** No export, no seed, no copy to a second device. Eight
  wrong PIN attempts destroy every credential, and so does a reset. This is the design.
  See `docs/authenticator/recovery.md`.

An open defect worth naming because it is not yet fixed: the bootloader's wipe-device
workflow calls `ui_screen_wipe_confirm()` with no headless guard, so that path does not
work on a device with no display.

## What this firmware does not promise

It is not a production build and does not claim to be. There has been no independent
security review, no reproducible-build comparison by a second party, and no verified
offline backup of the signing keys. Until those exist,
`core/embed/projects/authenticator/tools/audit_release.py` refuses to pass a production
record, and the device should hold no credential whose loss would matter.
