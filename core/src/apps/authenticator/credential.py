"""Public credential metadata. Every secret operation stays in the native vault."""

MAX_RP_ID_LENGTH = 253
MAX_CREDENTIAL_ID_LENGTH = 1024

_ID_MAX = 704


def _bytes(value, minimum, maximum):
    if not isinstance(value, bytes) or not minimum <= len(value) <= maximum:
        raise ValueError("invalid credential bytes")
    return value


def _text(value, minimum, maximum):
    if not isinstance(value, str):
        raise ValueError("invalid credential text")
    return _bytes(value.encode(), minimum, maximum)


class Credential:
    """An authenticated public view; it has no private key or derive method."""

    @classmethod
    def create(
        cls, rp_id, user_id, rp_name="", user_name="", user_display_name="",
        algorithm=-7, cred_protect=3, hmac_secret=False,
    ):
        rp = _text(rp_id, 1, 253)
        user = _bytes(user_id, 0, 64)
        names = (
            _text(rp_name, 0, 100), _text(user_name, 0, 100),
            _text(user_display_name, 0, 100),
        )
        if (
            type(algorithm) is not int or algorithm not in (-7, -8)
            or type(cred_protect) is not int or cred_protect != 3
            or type(hmac_secret) is not bool
        ):
            raise ValueError("invalid credential policy")
        metadata = bytes((1, int(hmac_secret), 3, len(rp) >> 8, len(rp) & 255,
                          len(user), len(names[0]), len(names[1]), len(names[2])))
        metadata += rp + user + names[0] + names[1] + names[2]
        from trezor.crypto import hashlib
        import trezorauth
        rp_hash = hashlib.sha256(rp).digest()
        return cls._from_public(
            trezorauth.credential_create(rp_hash, algorithm, metadata)
        )

    @classmethod
    def open(cls, identifier, rp_hash):
        _bytes(identifier, 78, _ID_MAX)
        _bytes(rp_hash, 32, 32)
        import trezorauth
        return cls._from_public(trezorauth.credential_open(identifier, rp_hash))

    @classmethod
    def _from_public(cls, result):
        status, identifier, rp_hash, algorithm, metadata, cose = result
        if status != 0:
            raise CredentialUnavailable("secure credential operation denied")
        _bytes(identifier, 78, _ID_MAX)
        _bytes(rp_hash, 32, 32)
        _bytes(metadata, 10, 640)
        if algorithm not in (-7, -8) or metadata[:3] not in (
            b"\x01\x00\x03", b"\x01\x01\x03"
        ):
            raise ValueError("invalid authenticated metadata")
        lengths = (
            (metadata[3] << 8) | metadata[4], metadata[5], metadata[6],
            metadata[7], metadata[8],
        )
        if (
            sum(lengths) + 9 != len(metadata) or not 1 <= lengths[0] <= 253
            or lengths[1] > 64 or max(lengths[2:]) > 100
        ):
            raise ValueError("invalid authenticated lengths")
        values = []
        offset = 9
        for length in lengths:
            values.append(metadata[offset:offset + length])
            offset += length
        item = cls()
        item.id, item.rp_id_hash = identifier, rp_hash
        item.algorithm, item._cose = algorithm, cose
        item.rp_id = values[0].decode()
        item.user_id = values[1]
        item.rp_name, item.user_name, item.user_display_name = (
            value.decode() for value in values[2:]
        )
        item.cred_protect, item.hmac_secret_enabled = 3, bool(metadata[1])
        return item

    def public_key(self):
        return self._cose

    def sign(self, message):
        _bytes(message, 1, 1024)
        import trezorauth
        status, signature = trezorauth.credential_sign(
            self.id, self.rp_id_hash, self.algorithm, message
        )
        if status != 0:
            raise CredentialUnavailable("secure signing denied")
        return signature

    def attest(self, message):
        """Sign a creation's own attestation statement with its own key.

        Self attestation, which is the only attestation this device can honestly
        make: the signature is by the key being registered, so it proves the
        credential came from whatever made it without saying anything about the
        device. A batch key with a certificate would say which batch, and a batch
        is a device identifier, so there is none here and there will not be one.

        Separate from sign() because the vault requires a different permission for
        each: an assertion needs ga, an attestation is authorized by the creation
        it belongs to. A platform that registers a credential holds the one and
        not always the other -- libfido2 asks for mc alone -- so conflating them
        would have made enrollment impossible for exactly the clients that need it.
        """
        _bytes(message, 1, 1024)
        import trezorauth
        status, signature = trezorauth.credential_attest(
            self.id, self.rp_id_hash, self.algorithm, message
        )
        if status != 0:
            raise CredentialUnavailable("secure attestation denied")
        return signature

    def hmac_secret(self, salt1, salt2=None):
        _bytes(salt1, 32, 32)
        salts = salt1
        if salt2 is not None:
            salts += _bytes(salt2, 32, 32)
        import trezorauth
        status, output = trezorauth.credential_hmac_secret(self.id, self.rp_id_hash, salts)
        if status != 0:
            raise CredentialUnavailable("secure hmac-secret denied")
        return output


class CredentialUnavailable(Exception):
    pass


class CredentialStoreFull(CredentialUnavailable):
    """Every resident slot holds a credential.

    Separate from CredentialLimitExceeded, which says this one record is too large
    for a slot: a smaller record would fit that, whereas nothing fits a full store.
    CTAP has distinct codes for the two because a platform acts differently on
    each -- one is worth retrying with less metadata, the other is not.
    """


class CredentialLimitExceeded(CredentialUnavailable):
    pass


def create(rp_id: bytes, client_data_hash: bytes) -> bytes:
    if not 1 <= len(rp_id) <= MAX_RP_ID_LENGTH or len(client_data_hash) != 32:
        raise ValueError("invalid credential request")
    raise CredentialUnavailable("secure credential service unavailable")


def assertion(credential_id: bytes, client_data_hash: bytes) -> bytes:
    if not 1 <= len(credential_id) <= MAX_CREDENTIAL_ID_LENGTH or len(client_data_hash) != 32:
        raise ValueError("invalid assertion request")
    raise CredentialUnavailable("secure credential service unavailable")
