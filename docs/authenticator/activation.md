# Activation

Four changes separate a release candidate from a device worth trusting with
credentials. None of them can be reversed. They are documented together, and in a
fixed order, because each one removes a recovery path that the others may still
need: taken out of order they can produce a device that can neither be repaired
nor wiped.

## Status

| Step | What it establishes | State |
| --- | --- | --- |
| 1. Dedicated vendor header | The update path can tell an authenticator image from ordinary firmware | Applied |
| 2. Own-key signing | Secure boot verifies keys that are not published | Applied |
| 3. Anti-rollback | Older images, including official firmware, are refused | Not applied |
| 4. Hardware protection | Debug access closed, boot chain frozen | Not applied |

Step 4 must not be applied until the key backup required by step 2 exists and has
been tested by restoring it.

## Preconditions

- [ ] The device holds no credential that cannot be replaced. Every account enrolled
      on it has a second factor and recorded recovery codes.
- [ ] Two offline backups of the root keys exist, and **one has been restored and
      used to sign a throwaway image**. An unverified backup is a file, not a backup.
- [ ] `protection-manifest.md` carries an option-byte readback taken from the device
      being changed, not a copy of an earlier one.
- [ ] An image at the *current* monotonic value is kept, signed, with its hash
      recorded, as the fallback for steps 1 and 2. Step 3 ends its usefulness.

## 1. Dedicated vendor header

Before this step the authenticator linked the model's shared `firmware` vendor
header, whose vendor string is `DEV ONLY, DO NOT USE!` -- the same header an
ordinary Trezor devel build uses. No authenticated field distinguished an
authenticator image from ordinary firmware, so `authenticator_update_policy` took a
`product_is_authenticator` input that nothing could source.

The header now carries both a product name and a product type: `vstr` is
`vinchlabs aylo authenticator` and `fw_type` is `VENDOR_FW_TYPE_AUTHENTICATOR = 6`,
against the shared header's `fw_type 0`. `product_is_authenticator` compares
`fw_type` rather than the string, because one byte at a fixed offset is a narrower
thing to get wrong than a length-prefixed string, and the signature covers both.

- [x] Vendor header naming the product, 2-of-3, `sigmask 3`.
- [x] The authenticator project links it as its default rather than through a
      `VENDOR_HEADER` override. The build fails rather than falling back to the
      shared header.
- [x] `product_is_authenticator` reads `vhdr.fw_type == VENDOR_FW_TYPE_AUTHENTICATOR`.
- [x] The device boots the new image and answers `GetInfo`.
- [x] A non-authenticator image is refused. Offering the same firmware, same model,
      same monotonic value, differing only in its vendor header's `fw_type 0`, is
      answered `ProcessError: Not an authenticator image`, and nothing is written.
      The same bootloader then accepts the `fw_type 6` image, so the refusal is
      discrimination rather than a bootloader that refuses everything.

Two limits on that test. It isolates `fw_type`, which is the strongest available
form, but the rejected image was this project's own firmware rather than an official
Trezor build. And the refusal happens before any erase: `fw_on_headers` returns while
`write_image_data` is still unreached, which is why a rejected upload leaves the
installed firmware intact.

### Installing a bootloader

**The authenticator does not install bootloaders.** The project's `main.c` contains
no call to `boot_image_check` or `boot_image_replace`. The only firmware that calls
them is `core/embed/projects/firmware/src/stm32/main.c`, and there only under
`#if PRODUCTION || FORCE_BOOTLOADER_UPGRADE`. Earlier revisions of this project
embedded a 128 kB bootloader in every image without ever installing it; that
embedding has been removed, which reduced the image from 557056 to 481792 bytes and
`FLASH` from 544.0 KB to 470.5 KB.

Self-update was considered and rejected on the basis of what `boot_image_replace()`
does on this model. T3T1 does not enable `boot_ucb`, so the function takes the branch
in `core/embed/sec/image/stm32/boot_image.c` that calls
`flash_area_erase(&BOOTLOADER_AREA)` and then streams the decompressed image in.
Power lost inside that window leaves no bootloader at all, on a device with no screen
to ask that it not be unplugged. SWD repairs that today; after step 4 it cannot, and
the only exit would be a mass erase. A safe in-field path requires `boot_ucb`, where
the boardloader performs the swap -- a boardloader change, and the boardloader is the
one component with nothing underneath it.

So the bootloader is built from this tree and installed by writing `0x0C010000` over
SWD. Verify by readback: the region must hash to the built file. The prebuilt blobs in
`models/T3T1/bootloaders/` are upstream's, are left as upstream shipped them, and are
not used by this project -- `core/embed/projects/firmware/build.rs` is their only
consumer, and that is the ordinary firmware project.

One measurement artefact, because acting on it is destructive: a dump taken after
`reset halt` returns 131072 zero bytes, because the core is stopped in the
boardloader before that region is reachable over the debug port. A dump taken while
the firmware runs returns the true contents. An all-zero readback there is not
erased flash.

### What the vendor header does not separate

A dedicated `fw_type` was initially expected to separate the authenticator's storage
derivation from ordinary firmware's, because `fw_type` is an input to
`secret_key_storage_salt`. **That does not hold on this model.**

`fw_type` reaches the salt only through `secret_key_storage_salt()`, and
`core/embed/sec/storage/stm32u5/storage_salt.c` calls it only under
`SECRET_PRIVILEGED_MASTER_KEY_SLOT`. Only `models/T3W1` and `models/T3T2` define
that; `models/T3T1/secret_layout.h` declares a single key slot and assigns it to
Optiga. T3T1 takes the other branch, where the salt is the CPUID words plus the OTP
randomness block, identical for every firmware type on a given unit. Observed
accordingly: after moving from `fw_type 0` to `6` the device accepted its existing
PIN and listed every discoverable credential it held beforehand.

The barrier against ordinary firmware reading this vault is therefore
`authenticator_update_check` refusing to install ordinary firmware -- a decision in
the bootloader, not a key the hardware withholds. On T3T1 there is no second line
behind it, and neither step 2 nor step 3 adds one. An attacker who can write flash
directly, rather than through the update path, is outside what any of this stops.

## 2. Own-key signing

The boot chain is signed by keys generated for this project. A development-signed
image that the device accepted before this step is now answered
`ProcessError: Invalid vendor header signature`, and the own-keyed image installs.
That is secure boot going from absent to present.

This is called own-key signing rather than production signing deliberately. The
repository's `production` feature means more than signing: a real presence gesture,
an approved USB identity, and no assumed presence. This board satisfies none of
those. What changed here is the keys, which is the part secure boot depends on.

Before this step the device had no secure boot at all. Under `--bootloader-devel`,
`core/embed/sec/image/image.c` substitutes three development public keys for both
`MODEL_BOOTLOADER_KEYS` and `MODEL_BOARDLOADER_KEYS`, and the private halves of those
are published in this repository.

Note what secure boot is worth *before* step 4. At RDP 0 with SWD attached, anyone
holding the device can write flash directly and never present a signature -- which is
how the bootloader described above was installed. Step 2 begins to pay only once step
4 closes the debug port, and step 4 is only safe once step 2 means something. They are
one decision in two acts, not two independent improvements.

### The three key sets

Each is Ed25519, CoSi, 2-of-3. They are not interchangeable.

| Key set | Declared in | Compiled into | Verifies |
| --- | --- | --- | --- |
| `MODEL_BOARDLOADER_KEYS` | `core/embed/models/T3T1/model_T3T1.h` | boardloader | the bootloader image header |
| `MODEL_BOOTLOADER_KEYS` | same file | bootloader | the vendor header |
| `pubkeys` | `core/embed/models/T3T1/vendorheader/vendor_aylo*.json` | the vendor header | the firmware image header |

Nothing verifies the boardloader. It is trusted because it sits at the reset vector
and can only be replaced over SWD, which is what step 4 takes away.

### Keep private keys off the build machine

`headertool.py` can sign without ever seeing a private key, and that is the only form
worth using for keys that outlive the device:

```
# on the build machine: get the digest to be signed
core/tools/trezor_core_tools/headertool.py -d <image_or_vendor_header>

# on the offline machine: sign that digest with 2 of the 3 private keys

# on the build machine: insert it, naming the 1-based key indexes used
core/tools/trezor_core_tools/headertool.py <file> -s 1:2 <signature_hex>
```

`-S INDEX:PRIVKEY_HEX` also exists and puts a private key in a shell command on a
networked machine. Do not use it for these keys.

### Order of installation

The new boardloader contains the new bootloader public keys, so the moment it is
installed the old development-signed bootloader stops being acceptable. Therefore:

- [x] Three key sets generated as 32-byte Ed25519 secrets, held outside this
      repository.
- [ ] **Two offline backups per set, one restored and used to sign a throwaway
      image.** This is the item standing between here and step 4. At RDP 0 a lost key
      file is still recoverable: a new set can be generated and the boardloader
      rewritten over SWD. After step 4 it is not, and the device becomes one that can
      never be given firmware again.
- [x] Public halves in `model_T3T1.h` (both sets) and in `vendor_aylo.json`.
- [x] Built without `--bootloader-devel`: boardloader, bootloader `--headless-dev`,
      authenticator `--assumed-presence`.
- [x] Signed: bootloader by the boardloader keys, vendor header by the bootloader
      keys, firmware header by the vendor keys. All three verify.
- [x] New boardloader and new bootloader written in one SWD session.
- [x] Firmware installed through the new bootloader.
- [x] The device boots the own-keyed chain, answers `GetInfo` unchanged, accepts its
      PIN, still holds its discoverable credentials, and completes SSH logins with
      `ecdsa-sk` and `ed25519-sk` keys. Signing keys do not reach the storage salt on
      T3T1, so nothing was lost.
- [x] A development-signed image is refused: `Invalid vendor header signature`.
- [ ] An allocated USB identity. `1209:53c1` is pid.codes development space, and
      `audit_release.py` refuses it in a production record.
- [ ] `audit_image.py --mode production`. It consumes the build's `.map` and `.elf`
      rather than a `.bin`, and production mode additionally requires the items above
      that this board does not satisfy.

### Three constraints worth stating explicitly

**Two of this project's own guards forbade this step.** `bootloader/build.rs` asserted
that `headless_dev` requires `bootloader_devel`, and `xtask/src/features.rs` bailed on
the same rule. Since `bootloader_devel` is what substitutes the published keys, the
guards made "headless" and "signed with published keys" inseparable: they enforced the
weakness they read as preventing. Both now keep only the `production` clause, which is
the one that is genuinely about the absence of a display.

**The boardloader is at `0x0C004000`, not `0x0C000000`.** `0x0C000000` is
`SECRET_START`, 8 kB, and on this device all of it is live: the hardware-derived
storage key, the Optiga slot, the monotonic counters. Writing the boardloader there
destroys every credential on the device while looking like a successful flash. Sector
bounds agree: `BOARDLOADER_SECTOR_START 0x2`, `END 0x7`.

**The C key lists and trezorlib's copy must change together.** `model_T3T1.h` decides
what the device accepts; `python/src/trezorlib/_modeldata/T3T1.py` decides what
`headertool` and `audit_image` report. With only the C side updated, `headertool`
calls a correctly signed vendor header `INVALID`, which leaves "the device accepted
it" as the only available check. `core/embed/sec/image/inc/sec/root_keys.h` documents
the same hazard for its own pair of lists.

## 3. Anti-rollback

Advancing `FIRMWARE_MONOTONIC_VERSION` is what makes the counter refuse older images,
including all official Trezor firmware. Applied before step 2 it buys nothing --
with published signing keys an attacker signs a monotonic 63 image directly -- while
costing what development depends on:

> The counter only increases and caps at 63. Once advanced, this device can never
> again run **any** image at or below the old value. Every image built in this
> project so far inherits T3T1's value of 2, so advancing past 2 discards all of them
> as fallbacks.

- [ ] Choose a value leaving headroom. 63 is the ceiling and every future release
      needs a number below it.
- [ ] Set it in the authenticator project rather than inheriting the model's.
- [ ] Prove an image at the previous value is refused and the new one boots.
- [ ] Prove an interrupted update recovers, at every commit boundary, cold-cycled.

## 4. Hardware protection

> **Precondition from step 1: this step freezes the bootloader.** The authenticator
> does not install bootloaders, and on T3T1 it should not, so SWD is the only channel.
> RDP 1 closes that channel: debug can no longer write flash, and returning to RDP 0
> mass-erases. Whatever bootloader is installed when this step is taken is the one the
> device keeps for the rest of its life, bugs included. Do not take it while any
> bootloader change is still expected.

- [ ] Write protection on the boardloader region.
- [ ] Boot lock pinned.
- [ ] RDP level 1, last. **Never level 2**, which closes debug permanently with no
      recovery from any fault.

Each of these requires the readback from the preconditions attached to the change
request.

## Recovery during activation

Before step 3, recovery is: SWD writes the boot command to retained SRAM at
`0x3002ff00`, the bootloader starts, and the fallback image is uploaded. After step 3
the counter refuses that fallback and recovery means building a new image at or above
the new value. After step 4 there may be no recovery at all, which is why step 4 is
last and why the preconditions are not optional.
