"""Bounded, typed CTAP request values. No decoded CBOR map crosses this boundary."""


class _Record:
    __slots__ = ()

    def __init__(self, *values):
        if len(values) != len(self.__slots__):
            raise TypeError("incorrect record arity")
        for name, value in zip(self.__slots__, values):
            setattr(self, name, value)


class RpEntity(_Record):
    __slots__ = ("id", "name")


class UserEntity(_Record):
    __slots__ = ("id", "name", "display_name")


class CredentialDescriptor(_Record):
    __slots__ = ("id", "transports")


class CoseKey(_Record):
    __slots__ = ("x", "y")


class HmacSecretInput(_Record):
    __slots__ = ("key_agreement", "salt_enc", "salt_auth", "pin_protocol")


class CommandContext(_Record):
    __slots__ = ("connection_generation", "cid", "command")


class Request(_Record):
    __slots__ = ()


class GetInfoRequest(Request):
    __slots__ = ()


class MakeCredentialRequest(Request):
    __slots__ = (
        "client_data_hash", "rp", "user", "algorithm", "exclude_list",
        "hmac_secret", "cred_protect", "rk", "uv", "pin_uv_auth_param",
        "pin_uv_auth_protocol",
    )


class GetAssertionRequest(Request):
    __slots__ = (
        "rp_id", "client_data_hash", "allow_list", "hmac_secret", "up",
        "uv", "pin_uv_auth_param", "pin_uv_auth_protocol",
    )


class ClientPinRequest(Request):
    __slots__ = (
        "pin_uv_auth_protocol", "subcommand", "key_agreement",
        "pin_uv_auth_param", "new_pin_enc", "pin_hash_enc", "permissions",
        "rp_id",
    )


class CredentialManagementRequest(Request):
    __slots__ = (
        "subcommand", "rp_id_hash", "credential", "user",
        "pin_uv_auth_protocol", "pin_uv_auth_param", "auth_material",
    )


class ResetRequest(Request):
    __slots__ = ()


class GetNextAssertionRequest(Request):
    __slots__ = ()


class SelectionRequest(Request):
    __slots__ = ()
