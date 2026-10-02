"""Run in the dedicated authenticator MicroPython emulator."""
import trezorauth as auth
from trezorcrypto import aes, hmac, nist256p1, random, sha256

# A raw 16-byte stored value, for the bindings that take one directly.
HASH = b"\x01" + bytes(15)
OTHER = b"\x02" + bytes(15)
RP = b"r" * 32
# The P-256 base point: a well-formed peer key for the shape probes.
PEER = bytes.fromhex(
    "046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
    "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"
)
OFF_CURVE = b"\x04" + bytes(64)

# Eight code points, which is exactly this authenticator's minimum.
PIN = b"12345678"
WRONG = b"87654321"


def invalid(call):
    try:
        call()
    except (ValueError, TypeError):
        return
    raise AssertionError("invalid binding input accepted")


def stored(pin):
    """The plaintext behind CTAP's pinHashEnc, and what the vault keeps."""
    return sha256(pin).digest()[:16]


def padded(pin):
    """CTAP pads the new PIN on the right with zeros to 64 bytes."""
    return pin + bytes(64 - len(pin))


def hkdf(material, label):
    """HKDF-SHA256, 32-byte zero salt, one output block.

    Written from the construction rather than lifted from the vault: two
    independent derivations agreeing is evidence, an implementation agreeing
    with itself is not.
    """
    prk = hmac(hmac.SHA256, bytes(32), material).digest()
    return hmac(hmac.SHA256, prk, label + b"\x01").digest()


class Host:
    """The platform's half of a pinUvAuth protocol.

    The vault generates a fresh key pair on every getKeyAgreement and spends it
    on the next call, so agree() is called once per vault call, exactly as a real
    platform must.
    """

    def __init__(self, protocol):
        self.protocol = protocol
        self._secret = nist256p1.generate_secret()
        self.public = nist256p1.publickey(self._secret, False)
        assert len(self.public) == 65 and self.public[0] == 4

    def agree(self):
        result, authenticator = auth.key_agreement()
        assert result == auth.OK and len(authenticator) == 65
        assert authenticator[0] == 4
        point = nist256p1.multiply(self._secret, authenticator)
        assert point[0] == 4
        shared = point[1:33]
        if self.protocol == 1:
            # Protocol 1 authenticates and encrypts under the same key.
            self.aes_key = self.mac_key = sha256(shared).digest()
        else:
            self.aes_key = hkdf(shared, b"CTAP2 AES key")
            self.mac_key = hkdf(shared, b"CTAP2 HMAC key")
        return self

    def seal(self, plain):
        if self.protocol == 1:
            return aes(aes.CBC, self.aes_key, bytes(16)).encrypt(plain)
        iv = random.bytes(16)
        return iv + aes(aes.CBC, self.aes_key, iv).encrypt(plain)

    def unseal(self, sealed):
        if self.protocol == 1:
            return aes(aes.CBC, self.aes_key, bytes(16)).decrypt(sealed)
        return aes(aes.CBC, self.aes_key, sealed[:16]).decrypt(sealed[16:])

    def mac(self, message):
        digest = hmac(hmac.SHA256, self.mac_key, message).digest()
        return digest if self.protocol == 2 else digest[:16]

    def token_mac(self, token, message):
        digest = hmac(hmac.SHA256, token, message).digest()
        return digest if self.protocol == 2 else digest[:16]

    def set_pin(self, pin):
        self.agree()
        sealed = self.seal(padded(pin))
        return auth.set_pin(self.protocol, sealed, self.mac(sealed), self.public)

    def set_pin_raw(self, plain, param=None, peer=None):
        self.agree()
        sealed = self.seal(plain)
        return auth.set_pin(self.protocol, sealed,
                            self.mac(sealed) if param is None else param,
                            self.public if peer is None else peer)

    def issue(self, pin, permissions=2, rp=RP):
        self.agree()
        return auth.issue_token(self.seal(stored(pin)), self.protocol,
                                permissions, rp, self.public)


for forbidden in ("root", "token", "read_secret", "derive", "shared_secret", "private_key"):
    assert not hasattr(auth, forbidden)
invalid(lambda: auth.provision(bytes(15)))
invalid(lambda: auth.change_pin(HASH, bytes(17)))
invalid(lambda: auth.issue_token(HASH, 1, 2, bytes(31), PEER))
invalid(lambda: auth.issue_token(HASH, 1, 2, RP, bytes(64)))
invalid(lambda: auth.issue_token(HASH, 3, 2, RP, PEER))
invalid(lambda: auth.issue_token(HASH, 1, 256, RP, PEER))
invalid(lambda: auth.issue_token(HASH, 1 << 200, 2, RP, PEER))
# Protocol 2's pinHashEnc carries a leading IV, so the accepted length differs.
invalid(lambda: auth.issue_token(HASH, 2, 2, RP, PEER))
invalid(lambda: auth.issue_token(bytes(32), 1, 2, RP, PEER))
# setPIN: 64 bytes of ciphertext on protocol 1 and 80 on protocol 2, with a MAC
# of 16 and 32 respectively. A wrong length is the application's mistake, not
# something to forward to the vault.
invalid(lambda: auth.set_pin(1, bytes(63), bytes(16), PEER))
invalid(lambda: auth.set_pin(1, bytes(80), bytes(16), PEER))
invalid(lambda: auth.set_pin(1, bytes(64), bytes(32), PEER))
invalid(lambda: auth.set_pin(2, bytes(64), bytes(32), PEER))
invalid(lambda: auth.set_pin(2, bytes(80), bytes(16), PEER))
invalid(lambda: auth.set_pin(3, bytes(64), bytes(16), PEER))
invalid(lambda: auth.set_pin(1, bytes(64), bytes(16), bytes(64)))
invalid(lambda: auth.check_auth(1, b"m", bytes(15), 2, RP))
invalid(lambda: auth.check_auth(2, b"m", bytes(16), 2, RP))
invalid(lambda: auth.check_auth(1, bytes(1025), bytes(16), 2, RP))
# These cross the MicroPython boundary as plain integers, so the numbering is
# part of the interface and not an implementation detail: renumbering would
# silently change what the application thinks it was told. MIGRATION_REQUIRED and
# PIN_POLICY are last because they were appended, for the replica vault and for
# CTAP's PIN policy answer respectively.
assert (auth.OK, auth.UNPROVISIONED, auth.INVALID_ARGUMENT, auth.PIN_INVALID,
        auth.PIN_AUTH_BLOCKED, auth.PIN_BLOCKED, auth.DENIED, auth.ERROR,
        auth.LIMIT_EXCEEDED, auth.MIGRATION_REQUIRED,
        auth.PIN_POLICY) == tuple(range(11))
assert auth.MIN_PIN_CODE_POINTS == 8
# Changing the PIN is refused outright rather than left unimplemented. The root
# is wrapped under a PIN-derived key and there is no re-wrap path, so a change
# that appeared to succeed would strand every credential on the device.
assert auth.change_pin(HASH, OTHER) == auth.DENIED
assert auth.change_pin(OTHER, HASH) == auth.DENIED
assert auth.disconnect() == auth.OK
if getattr(auth, "TEST_BACKEND", False):
    assert auth.wipe() == auth.OK
    assert auth.status() == (auth.UNPROVISIONED, 0, 0)
    # provision() installs a stored value directly. It keeps its own coverage
    # because it is the only way in for a value no PIN string produces.
    assert auth.provision(HASH) == auth.OK
    assert auth.provision(HASH) == auth.DENIED
    assert auth.status() == (auth.OK, 8, 0)
    # Ordering: no token before a key agreement, and the ciphertext is never
    # even looked at until there is a shared secret to open it with.
    assert auth.issue_token(HASH, 1, 2, RP, PEER) == (auth.DENIED, b"")
    assert auth.wipe() == auth.OK

    # --- setPIN rejections ---------------------------------------------------
    # All of them run while the device is still unprovisioned, and each is
    # followed by a status check, so a rejection that quietly provisioned anyway
    # would be caught on the next line rather than hidden by the one after it.
    for protocol in (1, 2):
        host = Host(protocol)
        for plain, want in (
            (padded(b"1234567"), auth.PIN_POLICY),
            (padded(b"\xc3\x28" + b"abcdefgh"), auth.INVALID_ARGUMENT),
            (padded(b"\xed\xa0\x80" + b"abcdefgh"), auth.INVALID_ARGUMENT),
            (b"12345678" + bytes(8) + b"\x01" + bytes(47), auth.INVALID_ARGUMENT),
            (b"1" * 64, auth.INVALID_ARGUMENT),
        ):
            assert host.set_pin_raw(plain) == want, (protocol, want)
            assert auth.status() == (auth.UNPROVISIONED, 0, 0)
        # A MAC that does not verify is refused before anything is decrypted.
        width = 32 if protocol == 2 else 16
        assert host.set_pin_raw(padded(PIN), param=bytes(width)) == auth.DENIED
        assert auth.status() == (auth.UNPROVISIONED, 0, 0)
        # A peer key the ECDH refuses is a parameter error, not an auth failure.
        assert host.set_pin_raw(padded(PIN), peer=OFF_CURVE) == auth.INVALID_ARGUMENT
        # And with no key agreement in flight at all. The failure above spent it.
        assert auth.set_pin(protocol, host.seal(padded(PIN)),
                            host.mac(host.seal(padded(PIN))),
                            host.public) == auth.DENIED

    # --- the PIN that must be accepted --------------------------------------
    assert Host(2).set_pin(PIN) == auth.OK
    assert auth.status() == (auth.OK, 8, 0)
    # setPIN cannot replace an existing PIN, and neither can changePIN, so the
    # only supported transition is a wipe.
    assert Host(2).set_pin(b"abcdefgh") == auth.DENIED
    assert Host(1).set_pin(b"abcdefgh") == auth.DENIED
    assert auth.status() == (auth.OK, 8, 0)

    # --- the PIN set above opens the vault -----------------------------------
    # This is the only thing that proves setPIN and issue_token agree on what the
    # stored value is: one wrote LEFT(SHA-256(pin), 16) and the other looks it up.
    for protocol in (2, 1):
        host = Host(protocol)
        result, encrypted = host.issue(PIN, permissions=3)
        assert result == auth.OK, (protocol, result)
        assert len(encrypted) == (48 if protocol == 2 else 32)
        token = host.unseal(encrypted)
        assert len(token) == 32 and token != bytes(32)
        message = b"authenticator data" + bytes(32)
        # The token the platform decrypted is the one the vault authenticates
        # against, which closes the loop on both protocols' AES and HMAC.
        assert auth.check_auth(protocol, message,
                               host.token_mac(token, message), 2, RP) == auth.OK
        assert auth.check_auth(protocol, message,
                               host.token_mac(token, message), 1, RP) == auth.OK
        # Scope is enforced: an ungranted permission, then a foreign RP, then a
        # forged MAC. Each of these ends the session, so each needs its own token.
        assert auth.check_auth(protocol, message,
                               host.token_mac(token, message), 4, RP) == auth.DENIED
        assert host.issue(PIN, permissions=3)[0] == auth.OK
        assert auth.check_auth(protocol, message, host.token_mac(token, message),
                               2, b"x" * 32) == auth.DENIED
        result, encrypted = host.issue(PIN, permissions=3)
        assert result == auth.OK
        assert auth.check_auth(protocol, message,
                               bytes(len(host.token_mac(token, message))),
                               2, RP) == auth.DENIED
    # An unbound token cannot service an RP-scoped permission request.
    host = Host(2)
    assert host.issue(PIN, permissions=4, rp=None)[0] == auth.OK
    invalid(lambda: auth.issue_token(host.seal(stored(PIN)), 2, 3, None,
                                     host.public))

    # Offering P-256's base point as the platform key makes the point the vault
    # derives exactly the public key it just handed over, so a token can be had
    # without a platform private key at all. That shortcut is how
    # test_trezorauth_credentials.py reaches the credential surface, so what it
    # relies on is checked here rather than assumed there.
    result, public = auth.key_agreement()
    assert result == auth.OK
    sealed = aes(aes.CBC, sha256(public[1:33]).digest(), bytes(16)).encrypt(stored(PIN))
    assert auth.issue_token(sealed, 1, 7, RP, PEER)[0] == auth.OK

    # --- retry transitions ---------------------------------------------------
    # Eight wrong PINs destroy the root. Three in a row block the session first,
    # and power cycling is the only way out of that, so malware on the host
    # cannot burn through the eight without the user noticing.
    host = Host(1)
    for attempt in range(1, 9):
        result, ciphertext = host.issue(WRONG)
        want = auth.PIN_BLOCKED if attempt == 8 else (
            auth.PIN_AUTH_BLOCKED if attempt % 3 == 0 else auth.PIN_INVALID
        )
        assert result == want and ciphertext == b"", (attempt, result)
        if attempt % 3 == 0:
            # The right PIN is refused too, and refused without spending a try.
            assert host.issue(PIN) == (auth.PIN_AUTH_BLOCKED, b"")
            assert auth.disconnect() == auth.OK
            assert auth.status()[1] == 8 - attempt
    assert auth.status() == (auth.UNPROVISIONED, 0, 0)

    # A destroyed vault is unprovisioned, not bricked.
    assert Host(1).set_pin(b"abcdefgh") == auth.OK
    assert auth.status() == (auth.OK, 8, 0)
    assert auth.wipe() == auth.OK
    assert auth.status() == (auth.UNPROVISIONED, 0, 0)
else:
    assert auth.status()[0] == auth.ERROR
    assert auth.provision(HASH) == auth.ERROR
    assert auth.key_agreement() == (auth.ERROR, b"")
    assert auth.issue_token(HASH, 1, 2, RP, PEER) == (auth.ERROR, b"")
    assert auth.set_pin(1, bytes(64), bytes(16), PEER) == auth.ERROR
print("TREZORAUTH_BINDING_PASS")
