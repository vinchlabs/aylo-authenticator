# Release checklist

The items a program cannot check. `core/embed/projects/authenticator/tools/audit_release.py`
requires every one of them to be answered yes before it will pass a production record,
which is what makes this list more than a wish: an unanswered item fails the gate.

While any item is unanswered, the build reports a development marker, the device stays at
RDP 0 with SWD open, and it is **not suitable for credentials whose loss would matter**.

## Keys

- [ ] `two_offline_root_key_backups` -- two offline backups of the root keys exist, on
      separate media, in separate places, and **one has been restored** to prove it is a
      backup rather than a file.
- [ ] `release_key_rotation_procedure` -- a written procedure for rotating and revoking a
      release key, including what a device already in the field does when it meets an
      image signed by a revoked key.
- [ ] No private key is in this repository, in any build output, or in any artifact
      directory. Checked, not assumed.

## Recovery

- [ ] `second_authenticator_enrolled` -- every account this key is enrolled on has a
      second factor that does not depend on this device. Eight wrong PINs destroy
      everything here, by design.
- [ ] `recovery_codes_recorded` -- recovery codes recorded offline for every such
      account.
- [ ] An interrupted firmware update has been shown to recover: interrupted at each
      commit boundary, cold-cycled, and ending on either the previous or the new image.
- [ ] A path into the bootloader that does not require SWD has been shown to work.

## The artifacts

- [ ] `independent_hash_comparison` -- a second person rebuilt the release from the
      recorded commit, submodules, toolchain and build command, and got the same unsigned
      payload hash byte for byte.
- [ ] `audit_image.py --mode production` passes on the artifacts being released.
- [ ] `audit_release.py` passes on the record for those same artifacts.
- [ ] The USB identity is an allocated one, not the development `1209:53c1`.
- [ ] The security version is set, is above the value the device already holds, and is at
      most 63.

## Review

- [ ] `independent_security_review` -- someone who did not write it read the vault
      boundary, the policy, the transport and the update path.
- [ ] `option_bytes_readback_recorded` -- the current option bytes are recorded in
      `protection-manifest.md`, read back from the device, not copied from a datasheet.

## The gate

Any unanswered item above means: no production release, no option-byte changes, no RDP
change, and no credential on this device that cannot be replaced.
