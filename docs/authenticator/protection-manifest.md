# Protection manifest -- STM32U585

This document records what the device's protection state **is**, what it **would be**
after activation, and the read-only commands used to observe it. It contains no command
that writes an option byte, sets RDP, or closes debug access, and it must not acquire
one. The commands that change this state are destructive, several are irreversible, and
they belong in a separately approved procedure with a readback of the previous state
attached.

Current state: **RDP 0 with SWD open**, by deliberate choice. Nothing in this file has
been applied.

## Why debug access is still open

The boot chain is signed with this project's own keys, so the original reason -- that a
development-signed chain has no secure boot worth protecting -- no longer applies.
Three reasons remain, and each is a concrete unmet precondition rather than a
preference.

**The root keys have no verified offline backup.** At RDP 0, a lost key set is
recoverable: generate a new set and rewrite the boardloader over SWD. At RDP 1 that
repair is gone, and a device whose signing keys are lost is a device that can never be
given firmware again. The backup must be restored and used to sign a throwaway image
before it counts.

**Entering the bootloader without SWD is unproven.** The documented path writes a boot
command to retained SRAM at `0x3002FF00` over the debug port. A test of the host-driven
path without SWD has not passed: the device was observed jumping straight to firmware
while the host request failed at the USB layer. Until a non-SWD path into the
bootloader works, RDP 1 can make the installed firmware the last the device ever runs.

**Interrupted updates are not proven to recover.** Until an update is shown to resume
or roll back from an interruption at every commit boundary, closing debug converts a
failed update into a dead device.

## Observing the current state, read-only

These commands read and do not write. The adapter interface file depends on the probe
in use; the target file does not.

    # Option bytes.
    openocd -f interface/<probe>.cfg -f target/stm32u5x.cfg \
      -c "init" -c "mdw 0x40022040 8" -c "shutdown"

    # FLASH_OPTR at 0x40022040 carries RDP in bits 7:0:
    #   0xAA  RDP level 0, debug open
    #   0xBB  RDP level 1, flash unreadable over debug, mass erase on regression
    #   0xCC  RDP level 2, debug permanently closed, no regression
    # Any value other than 0xAA means this document is out of date.

    # Secret area, which holds the monotonic counters. Read, never written here.
    openocd -f interface/<probe>.cfg -f target/stm32u5x.cfg \
      -c "init" -c "mdw 0x0C000000 4" -c "shutdown"

A dump of flash taken after `reset halt` is not trustworthy on this part: the core
stops in the boardloader before the bootloader region is reachable over the debug port,
and the dump returns zeros. Read while the firmware runs, and resume the core
afterwards.

## What activation would set, and what each costs

Recorded as a proposal. None of it is applied, and none of it should be applied from
this document.

| Setting | Now | Proposed | Cost of getting it wrong |
| --- | --- | --- | --- |
| RDP level | 0 (`0xAA`) | 1 (`0xBB`) | Level 1 makes flash unreadable over debug; returning to level 0 mass-erases, destroying every credential. Irreversible without that erase. |
| RDP level 2 | not set | **never** | Permanently closes debug. No recovery from any firmware fault, ever. Not proposed at any point. |
| Boot lock (`nBOOT0`/`SWAP_BANK`) | default | pinned to bank 1 | A wrong value boots from an unintended bank and can leave the device unable to start. |
| Write protection (`WRP`) on boardloader | none | boardloader region | Protects the root of trust from being rewritten; also prevents repairing it. |
| `TZEN` TrustZone | as built | unchanged | Changing it reorganises the memory map; an image built for the other setting will not run. |
| Secure flash boundary (`SECWM`) | as built | unchanged | Moving it can orphan the secret area, and with it the monotonic counters and the vault root. |

## Order, if it ever happens

1. Read back and record the current option bytes, with the output attached to the
   change request.
2. Two offline backups of the root keys, verified by restoring one and signing with it.
3. A non-SWD path into the bootloader, proven.
4. An interrupted update proven to recover, at every commit boundary.
5. A second authenticator enrolled on every account that matters, and recovery codes
   recorded, because step 7 can end in a device that cannot be opened.
6. Write protections and boot lock.
7. RDP 1, last, and only after 1 through 6 are signed off.

Steps 6 and 7 are not covered by any procedure in this repository and need their own
approval with this readback attached.
