# Recovery, and what there is none of

This device is a FIDO2 authenticator with no display. Read this before enrolling it
anywhere that matters, because most of the answers below are "you cannot".

## Nothing on it can be exported or backed up

Every credential is sealed under a root secret created inside the vault, which never
leaves it. There is no export command, no seed phrase, no backup file, and no way to
copy a credential to a second device. That is not an omission to be fixed later: a
credential that can be copied off the device is a credential the device can no longer
promise anything about.

The consequence is simple. **If this device is lost, broken, wiped, or its PIN is
forgotten, every account enrolled only on it becomes unreachable.** No support process,
no recovery code held by anyone else, and no amount of access to the hardware will bring
the keys back.

## Enroll a second factor first, every time

Before registering this key with any account, register something else as well: another
security key, or the account's own recovery codes kept somewhere reachable without this
device. Do that *first*, while access still exists, not after a problem.

If an account allows exactly one security key and no recovery codes, this device is the
wrong tool for that account.

## The PIN cannot be changed, only replaced along with everything else

There is no change-PIN command. `clientPin` subcommand 0x04 is refused, and
`core/src/apps/authenticator/client_pin.py` gives the reason: the vault root is wrapped
under a PIN-derived key and there is no power-safe way to re-wrap it, so a change that
appeared to succeed could leave every credential unreachable. Refusing is the honest
behaviour.

Changing the PIN therefore means resetting the device, which destroys every credential
on it. **Choose the PIN intended to be kept.** Minimum eight code points, any
characters, at most 63 bytes of UTF-8.

Resetting has a trap worth knowing before it is needed: the Reset command is accepted
only within ten seconds of the device powering up. On a host that reaches the device
through a USB bridge -- WSL with `usbipd`, for example -- the bridge can take longer
than that to attach, so the window closes before the first request arrives. An attach
time of roughly thirteen seconds against a ten-second window has been observed. Reset
from a host with native USB, where the key appears immediately.

## What destroys the credentials

- **Eight wrong PIN attempts.** The secure element counts them and the vault wipes
  itself when the count runs out. Unplugging does not reset the count.
- **A Reset command in the first ten seconds after plugging in.** This exists so a
  device can always be made usable again, and it is deliberately available without a
  PIN. Outside that window it is refused.
- **Physical failure of the board or its secure element.** There is no second copy
  anywhere.

Wiping destroys the secure element's counter before it erases storage, so a storage
replica that survives a power cut mid-wipe is cryptographically useless rather than a
recoverable remnant.

## Development builds are not for anything valuable

Ask the device what it is. The GetInfo build marker, key `0xF0`, reports one of:

| Marker | Meaning |
| --- | --- |
| `AUTH-DEV` | development feature set |
| `AUTH-DEV-NOUP` | development feature set **that confirms every operation by itself** |

Both are development builds. Neither is a release. Concretely:

- The feature set is a development one, and the image audit refuses to certify a
  production build until an allocated USB identity and a reviewed signing identity
  exist. A build may be signed with project-generated keys and still report
  `AUTH-DEV`: the marker describes the feature set, not the signature.
- Debug access over SWD is open and flash readout protection is off. Someone with the
  hardware and a few wires can inspect it. See `protection-manifest.md`.
- `AUTH-DEV-NOUP` additionally performs every operation **without asking anyone**.
  Possession plus the PIN is the whole of its security; there is no gesture to withhold.
  It exists because the confirmation line is not yet wired to anything a person can act
  on, and it says so in the one field every platform reads first.

Use these builds for test accounts and for accounts whose loss of access is affordable.
Not for email, not for cloud consoles with real resources, not for anything holding
money.

## If access has been lost

There is nothing to try on the device. Recovery happens entirely at the account: the
second security key, the recovery codes, or the provider's identity-verification
process. Then remove the lost key from the account, so that a found device cannot be
used against its owner.

## If the device is found again after being replaced

Treat it as compromised unless it never left its owner's possession. Reset it within ten
seconds of plugging it in, which destroys everything on it, before using it again.
