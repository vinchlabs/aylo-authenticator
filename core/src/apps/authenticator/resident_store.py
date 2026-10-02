"""Exactly 100 discoverable credential slots backed by native authenticated records."""
from .credential import (
    Credential,
    CredentialLimitExceeded,
    CredentialStoreFull,
    CredentialUnavailable,
)

RESIDENT_METADATA_MAX = 448  # authenticated resident record version 1
# Native auth_result ordinals, which cross the boundary as plain integers.
NATIVE_OK = 0
NATIVE_LIMIT_EXCEEDED = 8
NATIVE_STORE_FULL = 11
# Passed as the index to say "wherever there is room". See AUTH_RESIDENT_ANY.
ANY_SLOT = 100


class ResidentStore:
    @staticmethod
    def _index(index):
        if type(index) is not int or not 0 <= index < 100:
            raise ValueError("invalid resident index")

    @staticmethod
    def get(index):
        ResidentStore._index(index)
        from storage.authenticator import get
        result = get(index)
        if result[0] == 1:
            return None
        return Credential._from_public(result)

    @staticmethod
    def set(index, credential):
        ResidentStore._index(index)
        if not isinstance(credential, Credential):
            raise ValueError("invalid credential")
        from storage.authenticator import set
        result = set(index, credential.id, credential.rp_id_hash)
        if result == 8:
            raise CredentialLimitExceeded(
                "resident metadata or storage exceeds version 1 capacity"
            )
        if result != 0:
            raise CredentialUnavailable("resident mutation denied")

    @staticmethod
    def store(credential):
        """Hand a credential to the vault and let it choose where it goes.

        Occupancy stays the vault's to know, and more completely than before. This
        used to be a search: try slot zero, and on a refusal try slot one, and so
        on. That cannot work, and the reason is worth keeping. A refusal leaves the
        vault through its fail-closed exit, which invalidates the session, so the
        second attempt has no authorization left and neither does any attempt after
        it. A device with ninety-nine free slots answered that it was full as soon
        as slot zero belonged to someone else.

        The vault is the only party that can see every slot -- a session bound to
        one relying party is deliberately told nothing about another's -- so it is
        the only party that can pick. It does not say which slot it used, because
        nothing here needs to know.

        Picking includes replacing. If this relying party already has a record for
        this account, that is the slot the vault writes, as one commit: CTAP
        requires the old record to go, and anything done in two steps from here
        would leave a moment with no record, or no record at all on a device with
        every slot occupied.
        """
        if not isinstance(credential, Credential):
            raise ValueError("invalid credential")
        from storage.authenticator import set
        result = set(ANY_SLOT, credential.id, credential.rp_id_hash)
        if result == NATIVE_LIMIT_EXCEEDED:
            raise CredentialLimitExceeded(
                "resident metadata or storage exceeds version 1 capacity"
            )
        if result == NATIVE_STORE_FULL:
            raise CredentialStoreFull("every resident slot holds a credential")
        if result != NATIVE_OK:
            raise CredentialUnavailable("resident mutation denied")

    @staticmethod
    def delete(index):
        ResidentStore._index(index)
        from storage.authenticator import delete
        if delete(index) != 0:
            raise CredentialUnavailable("resident deletion denied")

    @staticmethod
    def occupied(rp_id_hash=None):
        """The slots holding a credential, in slot order.

        One native call for the whole answer. Asking slot by slot made the vault
        authenticate its entire stored snapshot once per slot -- a hundred full
        passes over 57,664 bytes to answer one question, which on the device was
        six seconds for every command that touched the vault.

        `rp_id_hash` narrows the answer to one relying party, so a discovery never
        asks about slots it has no business knowing. The vault applies its own
        scope on top: a session bound to one party is told nothing about another
        party's slots whatever is passed here.
        """
        if rp_id_hash is not None and (
            type(rp_id_hash) is not bytes or len(rp_id_hash) != 32
        ):
            raise ValueError("invalid relying party hash")
        from storage.authenticator import scan
        status, occupancy = scan(rp_id_hash)
        if status != 0:
            raise CredentialUnavailable("resident scan denied")
        if len(occupancy) != 100:
            raise CredentialUnavailable("resident scan truncated")
        return [index for index in range(100) if occupancy[index]]

    @staticmethod
    def enumerate():
        """Every occupied slot as (index, credential), in slot order.

        Occupancy comes from one scan, and only the slots that hold something are
        read. Prefer occupied() when occupancy is the whole question: every get()
        makes the vault authenticate its snapshot again.
        """
        for index in ResidentStore.occupied():
            credential = ResidentStore.get(index)
            if credential is not None:
                yield index, credential
