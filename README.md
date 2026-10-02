# aylo authenticator

FIDO2 / CTAP 2.1 security-key firmware for the Trezor Safe 5 (model `T3T1`,
STM32U585 with an Optiga secure element). The device has a display and a touch
panel; this firmware uses neither. It enumerates as a single WebAuthn HID interface
and does nothing else: no wallet, no coin applications, no debug link, no serial
console, no display stack.

It is a fork of [trezor-firmware](https://github.com/trezor/trezor-firmware). See
[Relationship to upstream](#relationship-to-upstream).

> **Read [`docs/authenticator/recovery.md`](docs/authenticator/recovery.md) before
> enrolling this key anywhere.** Nothing on the device can be exported or backed up.
> Eight wrong PIN attempts destroy every credential, and the PIN cannot be changed
> without destroying them too.

## Security posture, stated plainly

This is **not a production build**, and the firmware says so in the first field a
platform reads. Before using it, understand all four of these:

- **User presence is assumed, not obtained.** The hardware gesture is not wired to
  anything a person can act on, so the build confirms every operation by itself. It
  behaves like a security key with the button held down permanently. Possession plus
  the PIN is the whole of its security. The GetInfo build marker (key `0xF0`) reports
  `AUTH-DEV-NOUP` so that no platform can miss this.
- **Debug access is open.** The device runs at RDP 0 with SWD available. Anyone with
  the hardware and a few wires can read and rewrite flash. The reasons this has not
  been closed, and what closing it would cost, are in
  [`docs/authenticator/protection-manifest.md`](docs/authenticator/protection-manifest.md).
- **The USB identity is development space.** `1209:53c1` belongs to pid.codes and is
  not an allocated product identity.
- **Anti-rollback is not engaged.** The monotonic counter is at the model's default,
  so an older signed image is still accepted.

What it does have: the boot chain is signed with keys generated for this project
rather than the development keys published in the upstream repository, every
credential operation requires a verified PIN with no bypass path, and the PIN is
backed by the Optiga secure element so a flash dump yields no offline brute force.

Suitable for test accounts and for accounts where losing access is affordable. Not
for email, cloud consoles, or anything holding money.

## What the device reports

| | |
| --- | --- |
| Version | `FIDO_2_1` |
| Transport | `usb` |
| Algorithms | `-7` (ES256), `-8` (Ed25519), in that order of preference |
| Options | `rk`, `alwaysUv`, `clientPin`, `pinUvAuthToken`, `credMgmt`, `credentialMgmtPreview` |
| Extensions | `credProtect`, honoured only as `UV_REQUIRED` |
| PIN | both pinUvAuth protocols; minimum 8 code points, at most 63 bytes of UTF-8 |
| `maxCredentialIdLength` | 704 |

Two deliberate deviations, both documented at their definitions in
`core/src/apps/authenticator/get_info.py`:

- `uv` is reported `false` rather than omitted. Strictly, `false` claims a built-in
  user-verification method exists but is unconfigured, and this device has none.
  OpenSSH will not select the key unless the field is present. Nothing follows from
  the claim: a request that genuinely asks for built-in verification still gets
  `CTAP2_ERR_PUAT_REQUIRED`, because the policy puts both credential commands behind
  a verified PIN whatever the options map says.
- `hmac-secret` is withheld. The salts arrive encrypted under the shared secret and
  nothing outside the vault can open them, so advertising the extension would promise
  an output that cannot be produced.

Verified in use: `ecdsa-sk` and `ed25519-sk` SSH keys, both non-discoverable and
discoverable (`-O resident -O verify-required`), including re-downloading a resident
handle with `ssh-keygen -K`.

## Layout

Everything below is added or changed by this fork; the rest of the tree is upstream.

| Path | What is there |
| --- | --- |
| `core/src/apps/authenticator/` | CTAP 2.1 applet: dispatcher, CBOR codec, ClientPIN, makeCredential, getAssertion, credential management, reset, policy, presence |
| `core/embed/sec/authenticator/` | The vault: credential storage, crypto, Optiga backend, power-cut-safe triple replica, and its tests |
| `core/embed/projects/authenticator/` | The firmware project, its build guards, image audit and release gate |
| `core/embed/projects/bootloader/` | Update policy: which images this device may install |
| `core/embed/models/T3T1/vendorheader/` | The project's vendor header, `fw_type 6` |
| `core/tests/test_apps.authenticator.*.py` | Applet test suites |
| `docs/authenticator/` | Activation, recovery, protection manifest, release checklist |

The vault runs in the secure world and the applet in MicroPython above it. The applet
can ask the vault to act; it cannot read a private key, and there is no code path that
exports one.

## Building

The upstream toolchain applies unchanged: a Nix shell for the ARM toolchain and `uv`
for Python. See [`docs/core/build/`](docs/core/build/).

```sh
nix-shell
cargo run -p xtask -- build boardloader   -m t3t1
cargo run -p xtask -- build bootloader    -m t3t1 --headless-dev
cargo run -p xtask -- build authenticator -m t3t1 --assumed-presence
```

Run from `core/embed/`. Artifacts land in `core/build-xtask/artifacts/T3T1/`.

- `--headless-dev` builds a bootloader that does not try to draw on a screen.
- `--assumed-presence` is what makes the build confirm operations by itself. It is
  refused together with `production`, and it is why the build marker reads
  `AUTH-DEV-NOUP`.
- `--bootloader-devel` is deliberately **not** used. That flag makes
  `core/embed/sec/image/image.c` substitute the upstream development keys, whose
  private halves are public, for the model's boardloader and bootloader keys.

The vendor header is built separately and then signed:

```sh
core/tools/build_vendorheader core/embed/models/T3T1/vendorheader/vendor_aylo.json
```

### Signing

Three Ed25519 CoSi 2-of-3 key sets, each guarding a different link. Which set signs
what is a property of what verifies the artifact, not of its name:

| Artifact | Signed by | Checked by |
| --- | --- | --- |
| bootloader image | `boardloader_keys` | the boardloader |
| vendor header | `bootloader_keys` | the bootloader |
| firmware image | `vendor_keys` | the vendor header |

`core/embed/projects/authenticator/tools/sign-chain.py` performs a signature by
taking the digest from `headertool -d`, signing it, and inserting it with
`headertool -s`, so no private key reaches a command line. For keys that outlive the
device, use the fully offline flow in
[`docs/authenticator/activation.md`](docs/authenticator/activation.md), where the
private halves never touch a networked machine.

**This repository contains no private keys and must not acquire any.** The public
halves are in `core/embed/models/T3T1/model_T3T1.h`,
`core/embed/models/T3T1/vendorheader/vendor_aylo.json`, and
`python/src/trezorlib/_modeldata/T3T1.py` -- all three must be changed together, or
`headertool` will call a correctly signed header invalid.

### Installing

The authenticator does not install bootloaders, by decision rather than omission; the
reasoning is in `docs/authenticator/activation.md`. The boardloader and bootloader are
written over SWD, and the firmware is installed through the bootloader.

## Tests

```sh
# applet suites
core/tests/run_authenticator_suites.sh

# the vault, compiled and run natively
cd core/embed/sec/authenticator/tests && python3 test_replica_store.py   # and siblings

# build guards, image audit, release gate, credential profile
cd core/embed/projects/authenticator/tools && python3 test_audit_policy.py   # and siblings
```

The applet suites pin `/usr/bin/python3`. They put `core/src` on `PYTHONPATH`, where
the firmware's own `typing` mock shadows the standard library's, and CPython 3.13's
`asyncio` imports `typing` at startup and dies on the mock. Override with `PY=`.

## Relationship to upstream

Forked from `trezor-firmware` at commit
[`61f7a5f08763dc26e794ab56d071b412c7be617e`](https://github.com/trezor/trezor-firmware/commit/61f7a5f08763dc26e794ab56d071b412c7be617e).
The first commit in this repository is that tree, unmodified, so `git diff` against it
shows exactly what this fork changes: 235 paths in total, of which 159 are added, 75
are modified, and one -- `CONTRIBUTING.md` -- stops being a symlink into
`docs/misc/` and becomes a file of its own. Nothing upstream ships is deleted, and no
upstream binary is modified.

This is an independent project. It is not produced, endorsed, reviewed, or supported
by SatoshiLabs or Trezor, and it carries its own AAGUID and attestation rather than
Trezor's. Do not report problems with it to Trezor.

## Licence

Inherited, not chosen. Upstream is a monorepo that licenses each directory
separately, and this fork keeps that arrangement: every file it adds or changes
carries the licence of the directory it sits in. In practice that means **GPLv3**,
because the authenticator lives in `core/`, with three exceptions that are upstream's
own terms rather than this project's choice:

| Where this fork touches | Licence |
| --- | --- |
| `core/`, `storage/`, `docs/`, root files | GPLv3 |
| `python/src/trezorlib/_modeldata/T3T1.py` | LGPLv3 |
| two files under `crypto/chacha20poly1305/` | MIT |

The full map is in [`LICENSE.md`](LICENSE.md); the texts are the `COPYING` files it
points at. There is no relicensing option here: the authenticator is a derivative work
of GPLv3 code, so GPLv3 is what it is, and anyone distributing a build of it owes the
corresponding source under the same terms.

GitHub reports this repository's licence as "Other" because `LICENSE.md` is a map
rather than a licence text. That is upstream's layout, left alone on purpose.

## Status

Two of the four irreversible activation steps are applied: the dedicated vendor header
and own-key signing. Anti-rollback and hardware protection are not, and the
preconditions each one needs are listed in
[`docs/authenticator/activation.md`](docs/authenticator/activation.md). Known open
defects and unproven paths are recorded there and in
[`docs/authenticator/release-checklist.md`](docs/authenticator/release-checklist.md)
rather than left implicit.
