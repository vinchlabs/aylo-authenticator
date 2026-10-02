"""Safe cryptographic primitives; no seed or credential access."""

from trezorcrypto import hmac, random, sha256


class hashlib:
    sha256 = sha256
