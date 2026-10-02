"""Fail-closed CTAP surface for a dispatcher with nothing registered."""

# Project AAGUID. It is distinct from the official Trezor authenticator.
AAGUID = b"\x7c\x31\xd8\xc2\x8e\x60\x49\x29\x89\x76\xa8\x6f\x9c\x12\x4b\xb1"

# Canonical CBOR, and the answer only when no GetInfo handler is registered.
# It therefore claims nothing beyond a version and an identity: a dispatcher with
# no ClientPIN handler does not support ClientPIN, so `clientPin` is absent
# rather than false, which would have advertised support that is not there. `uv`
# is absent for good: false would claim a built-in user verification method that
# is merely unconfigured, and this device has none.
#
# get_info.py builds the real response, which reports what is actually wired up.
GET_INFO = (
    b"\xa4\x01\x81\x68FIDO_2_1\x03\x50"
    + AAGUID
    + b"\x04\xa1\x62rk\xf4"
    + b"\x18\xf0\x68AUTH-DEV"
)


def dispatch_cbor(request: bytes) -> bytes:
    if request == b"\x04":
        return b"\x00" + GET_INFO
    return b"\x27"  # CTAP2_ERR_OPERATION_DENIED


# authenticatorData flag bits. Only these four are defined by WebAuthn.
FLAG_USER_PRESENT = 0x01
FLAG_USER_VERIFIED = 0x04
FLAG_ATTESTED = 0x40
FLAG_EXTENSION_DATA = 0x80

# The signature counter, which is constant zero and will stay so. There is no
# mutable per-credential field in the vault's authenticated record and no
# persistent counter anywhere in the applet -- the image audit forbids the whole
# NORCOW counter subsystem from linking. WebAuthn's instruction for an
# authenticator without a counter is exactly this: leave the value at zero. A
# relying party that reads zero simply does not get counter-based clone
# detection, which is honest; a number that only looked monotonic would be worse.
SIGN_COUNT = b"\x00\x00\x00\x00"


def authenticator_data(rp_id_hash: bytes, flags: int, attested: bytes = b"",
                       extensions: bytes = b"") -> bytes:
    """Assemble authenticatorData.

    The two trailing sections are already-encoded bytes rather than structures,
    because both are defined as concatenations at fixed positions: whatever
    follows the counter is read by offset, so it cannot be re-encoded here
    without changing what the relying party verifies.
    """
    if not isinstance(rp_id_hash, bytes) or len(rp_id_hash) != 32:
        raise ValueError("invalid RP hash")
    if not 0 <= flags <= 0xFF:
        raise ValueError("invalid authenticator data flags")
    if bool(attested) != bool(flags & FLAG_ATTESTED):
        raise ValueError("attested credential data contradicts the flags")
    if bool(extensions) != bool(flags & FLAG_EXTENSION_DATA):
        raise ValueError("extension data contradicts the flags")
    return rp_id_hash + bytes((flags,)) + SIGN_COUNT + attested + extensions


def attested_credential_data(credential) -> bytes:
    """The AAGUID, the credential id, and the credential's COSE public key.

    The public key is spliced in as the vault produced it. It is already
    canonical CBOR, and re-encoding it through this application's encoder would
    put a second opinion about the bytes into a structure the relying party
    verifies by hash.
    """
    identifier = credential.id
    if not isinstance(identifier, bytes) or not 1 <= len(identifier) <= 0xFFFF:
        raise ValueError("invalid credential id")
    return (
        AAGUID
        + len(identifier).to_bytes(2, "big")
        + identifier
        + credential.public_key()
    )
