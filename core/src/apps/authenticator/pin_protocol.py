"""CTAP pinUvAuth protocol shapes. The cryptography is deliberately not here.

Everything that touches the shared secret happens in the vault: the ECDH, both
protocols' key derivations, the AES, and the MACs. That is not a layering
preference, it is the only place it can happen. The authenticator's private key
is generated inside the vault by key_agreement() and never leaves it, so this
module could not derive the shared secret even if it wanted to, and the platform
encrypts the PIN hash and the new PIN under exactly that secret.

What is left for Python is the wire shape: turning the authenticator's public key
into the COSE_Key CTAP expects, and turning the platform's COSE_Key back into the
65-byte point the vault takes. Both are public values.
"""

# Advertised newest first, which is the order CTAP asks for. GetInfo is the only
# consumer; the request decoder validates the same pair independently, because it
# must reject an unsupported protocol before anything typed reaches this module.
SUPPORTED = (2, 1)

# COSE_Key for ECDH: EC2 key type, ECDH-ES + HKDF-256, curve P-256.
_KTY_EC2 = 2
_ALG_ECDH_ES_HKDF_256 = -25
_CRV_P256 = 1

# ClientPIN response map keys.
KEY_AGREEMENT = 1
PIN_UV_AUTH_TOKEN = 2
PIN_RETRIES = 3
POWER_CYCLE_STATE = 4


def encode_key_agreement(public_key: bytes) -> dict:
    """Wrap an uncompressed P-256 point as a COSE_Key."""
    if not isinstance(public_key, bytes) or len(public_key) != 65:
        raise ValueError("invalid public key length")
    if public_key[0] != 4:
        raise ValueError("public key is not an uncompressed point")
    return {
        1: _KTY_EC2,
        3: _ALG_ECDH_ES_HKDF_256,
        -1: _CRV_P256,
        -2: public_key[1:33],
        -3: public_key[33:65],
    }


def decode_key_agreement(key) -> bytes:
    """Rebuild the uncompressed point from an already-validated CoseKey.

    The CBOR schema has checked the key type, the algorithm, the curve and both
    coordinate lengths, so nothing is re-derived here. Whether the point is on
    the curve is the vault's question, because only the vault can answer it by
    trying the multiplication.
    """
    return b"\x04" + key.x + key.y
