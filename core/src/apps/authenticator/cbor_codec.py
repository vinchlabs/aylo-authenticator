"""Strict, bounded CTAP 2.1 canonical CBOR and request schemas.

The transport owns the 1,024-byte message limit; this module repeats it so
direct callers and future handlers cannot accidentally bypass the boundary.
"""

from .command_types import (
    ClientPinRequest, CoseKey, CredentialDescriptor,
    CredentialManagementRequest, GetAssertionRequest, GetInfoRequest,
    GetNextAssertionRequest, HmacSecretInput, MakeCredentialRequest,
    Request, ResetRequest, RpEntity, SelectionRequest, UserEntity,
)

INVALID_COMMAND = 0x01
INVALID_PARAMETER = 0x02
INVALID_LENGTH = 0x03
CBOR_UNEXPECTED_TYPE = 0x11
INVALID_CBOR = 0x12
MISSING_PARAMETER = 0x14
LIMIT_EXCEEDED = 0x15
UNSUPPORTED_ALGORITHM = 0x26
INVALID_OPTION = 0x2C
PUAT_REQUIRED = 0x36
INVALID_SUBCOMMAND = 0x3E
REQUEST_TOO_LARGE = 0x39

MAX_MESSAGE = 1024
MAX_DEPTH = 4
MAX_CREDENTIALS_IN_LIST = 10
MAX_USER_ID = 64


class CtapError(Exception):
    def __init__(self, code: int) -> None:
        super().__init__(code)
        self.code = code


class RawCbor:
    """Bytes that are already canonical CBOR, spliced into a response as they are.

    The vault hands back a COSE public key as authenticated CBOR. Parsing it only
    to encode it again would put a parser between the vault and the platform for
    no gain, and a difference in either direction would change what the platform
    is told the key is. Only handler code constructs this; a wire field can never
    become one, and the encoder still refuses it as a map key.
    """

    __slots__ = ("encoded",)

    def __init__(self, encoded: bytes) -> None:
        if type(encoded) is not bytes or not encoded:
            _fail(INVALID_PARAMETER)
        self.encoded = encoded


def _fail(code: int):
    raise CtapError(code)


class _Reader:
    def __init__(self, data: bytes, capture_top_key=None) -> None:
        self.data = data
        self.pos = 0
        self.capture_top_key = capture_top_key
        self.captured_value = None

    def take(self, count: int) -> bytes:
        end = self.pos + count
        if end > len(self.data):
            _fail(INVALID_CBOR)
        value = self.data[self.pos:end]
        self.pos = end
        return value

    def argument(self, additional: int) -> int:
        if additional < 24:
            return additional
        if additional == 24:
            value = self.take(1)[0]
            if value < 24:
                _fail(INVALID_CBOR)
            return value
        if additional == 25:
            value = int.from_bytes(self.take(2), "big")
            if value < 256:
                _fail(INVALID_CBOR)
            return value
        if additional == 26:
            value = int.from_bytes(self.take(4), "big")
            if value < 65536:
                _fail(INVALID_CBOR)
            return value
        # The CTAP2 canonical form permits integers through uint32. No
        # indefinite forms, reserved additional-info values, or uint64.
        _fail(INVALID_CBOR)

    def item(self, depth: int = 0):
        initial = self.take(1)[0]
        major, additional = initial >> 5, initial & 31
        if major == 7:
            if initial == 0xF4:
                return False
            if initial == 0xF5:
                return True
            if initial == 0xF6:
                return None
            if additional < 20 or additional == 23:
                return object()
            if additional == 24:
                if self.take(1)[0] < 32:
                    _fail(INVALID_CBOR)
                return object()
            if additional in (25, 26, 27):
                self.take({25: 2, 26: 4, 27: 8}[additional])
                return object()
            _fail(INVALID_CBOR)
        if major == 6:
            _fail(INVALID_CBOR)
        count = self.argument(additional)
        if major == 0:
            return count
        if major == 1:
            return -count - 1
        if major == 2 or major == 3:
            if count > len(self.data) - self.pos:
                _fail(INVALID_CBOR)
            raw = self.take(count)
            if major == 2:
                return raw
            try:
                return raw.decode("utf-8")
            except UnicodeError:
                _fail(INVALID_CBOR)
        if major == 4 or major == 5:
            if depth >= MAX_DEPTH or count > len(self.data) - self.pos:
                _fail(INVALID_CBOR)
            if major == 4:
                return [self.item(depth + 1) for _ in range(count)]
            result = {}
            previous = None
            for _ in range(count):
                start = self.pos
                key = self.item(depth + 1)
                key_encoding = self.data[start:self.pos]
                if key_encoding[0] >> 5 == 7:
                    # A valid but unknown simple/floating map key is still
                    # subject to canonical ordering, then ignored by schemas.
                    key = object()
                if type(key) not in (int, str, bytes, object) or (
                    previous is not None and key_encoding <= previous
                ):
                    _fail(INVALID_CBOR)
                previous = key_encoding
                value_start = self.pos
                result[key] = self.item(depth + 1)
                if depth == 0 and key == self.capture_top_key:
                    self.captured_value = self.data[value_start:self.pos]
            return result
        _fail(INVALID_CBOR)


def _decode(data: bytes, capture_top_key=None):
    if type(data) is not bytes:
        _fail(CBOR_UNEXPECTED_TYPE)
    if len(data) > MAX_MESSAGE:
        _fail(REQUEST_TOO_LARGE)
    reader = _Reader(data, capture_top_key)
    value = reader.item()
    if reader.pos != len(data):
        _fail(INVALID_CBOR)
    return (value, reader.captured_value) if capture_top_key is not None else value


def _map(value):
    if type(value) is not dict:
        _fail(CBOR_UNEXPECTED_TYPE)
    return value


def _required(mapping: dict, key, nested: bool = False):
    if key not in mapping:
        _fail(CBOR_UNEXPECTED_TYPE if nested else MISSING_PARAMETER)
    return mapping[key]


def _bytes(value, minimum: int = 0, maximum: int = MAX_MESSAGE) -> bytes:
    if type(value) is not bytes:
        _fail(CBOR_UNEXPECTED_TYPE)
    if not minimum <= len(value) <= maximum:
        _fail(INVALID_LENGTH)
    return value


def _text(value, minimum: int = 0, maximum: int = MAX_MESSAGE) -> str:
    if type(value) is not str:
        _fail(CBOR_UNEXPECTED_TYPE)
    if not minimum <= len(value.encode("utf-8")) <= maximum:
        _fail(INVALID_LENGTH)
    return value


def _uint(value) -> int:
    if type(value) is not int:
        _fail(CBOR_UNEXPECTED_TYPE)
    if value < 0:
        _fail(INVALID_PARAMETER)
    return value


def _bool(value) -> bool:
    if type(value) is not bool:
        _fail(CBOR_UNEXPECTED_TYPE)
    return value


def _pin_protocol(value):
    value = _uint(value)
    if value not in (1, 2):
        _fail(INVALID_PARAMETER)
    return value


def _pin_auth(value, protocol, allow_empty=False):
    if allow_empty and value == b"":
        return value
    return _bytes(value, 16 if protocol != 2 else 32, 16 if protocol != 2 else 32)


def _rp(value):
    value = _map(value)
    return RpEntity(
        _text(_required(value, "id", True), 1),
        _text(value["name"], 0) if "name" in value else None,
    )


def _user(value):
    value = _map(value)
    return UserEntity(
        _bytes(_required(value, "id", True), 1, MAX_USER_ID),
        _text(value["name"]) if "name" in value else None,
        _text(value["displayName"]) if "displayName" in value else None,
    )


def _descriptor(value):
    value = _map(value)
    if _text(_required(value, "type", True)) != "public-key":
        _fail(INVALID_PARAMETER)
    ident = _bytes(_required(value, "id", True), 1)
    transports = ()
    if "transports" in value:
        raw = value["transports"]
        if type(raw) is not list:
            _fail(CBOR_UNEXPECTED_TYPE)
        transports = tuple(_text(item) for item in raw)
    return CredentialDescriptor(ident, transports)


def _descriptors(value):
    if type(value) is not list:
        _fail(CBOR_UNEXPECTED_TYPE)
    if len(value) > MAX_CREDENTIALS_IN_LIST:
        _fail(LIMIT_EXCEEDED)
    return tuple(_descriptor(item) for item in value)


def _cose_key(value):
    value = _map(value)
    if set(value) != {1, 3, -1, -2, -3}:
        _fail(CBOR_UNEXPECTED_TYPE)
    if _uint(value[1]) != 2 or value[3] != -25 or _uint(value[-1]) != 1:
        _fail(INVALID_PARAMETER)
    return CoseKey(_bytes(value[-2], 32, 32), _bytes(value[-3], 32, 32))


def _hmac_input(value):
    value = _map(value)
    protocol = _pin_protocol(value[4]) if 4 in value else 1
    salt_enc = _bytes(_required(value, 2, True), 32, 80)
    if len(salt_enc) not in ((32, 64) if protocol == 1 else (48, 80)):
        _fail(INVALID_LENGTH)
    return HmacSecretInput(
        _cose_key(_required(value, 1, True)), salt_enc,
        _pin_auth(_required(value, 3, True), protocol), protocol,
    )


def _options(value, allowed):
    value = _map(value)
    result = {}
    for key in allowed:
        if key in value:
            result[key] = _bool(value[key])
    return result


def _make(value):
    value = _map(value)
    client_hash = _bytes(_required(value, 1), 32, 32)
    rp = _rp(_required(value, 2))
    user = _user(_required(value, 3))
    algorithms = _required(value, 4)
    if type(algorithms) is not list:
        _fail(CBOR_UNEXPECTED_TYPE)
    if not algorithms:
        _fail(UNSUPPORTED_ALGORITHM)
    chosen = None
    seen = set()
    for item in algorithms:
        item = _map(item)
        if _text(_required(item, "type", True)) != "public-key":
            _fail(INVALID_PARAMETER)
        algorithm = _required(item, "alg", True)
        if type(algorithm) is not int:
            _fail(CBOR_UNEXPECTED_TYPE)
        if algorithm in seen:
            _fail(INVALID_PARAMETER)
        seen.add(algorithm)
        if chosen is None and algorithm in (-7, -8):
            chosen = algorithm
    if chosen is None:
        _fail(UNSUPPORTED_ALGORITHM)
    exclude = _descriptors(value[5]) if 5 in value else ()
    extensions = _map(value[6]) if 6 in value else {}
    hmac_secret = _bool(extensions["hmac-secret"]) if "hmac-secret" in extensions else False
    cred_protect = _uint(extensions["credProtect"]) if "credProtect" in extensions else None
    if cred_protect is not None and cred_protect != 3:
        _fail(INVALID_OPTION)
    options = _options(value[7], ("rk", "uv", "up")) if 7 in value else {}
    if options.get("up") is False:
        _fail(INVALID_OPTION)
    if 10 in value:
        _uint(value[10])
        _fail(INVALID_PARAMETER)  # Enterprise attestation is not supported.
    protocol = _pin_protocol(value[9]) if 9 in value else None
    return MakeCredentialRequest(
        client_hash, rp, user, chosen, exclude, hmac_secret, cred_protect,
        options.get("rk", False), options.get("uv", False),
        _pin_auth(value[8], protocol, True) if 8 in value else None, protocol,
    )


def _get(value):
    value = _map(value)
    rp_id = _text(_required(value, 1), 1)
    client_hash = _bytes(_required(value, 2), 32, 32)
    allow = _descriptors(value[3]) if 3 in value else None
    if allow == ():
        _fail(INVALID_PARAMETER)
    extensions = _map(value[4]) if 4 in value else {}
    hmac_secret = _hmac_input(extensions["hmac-secret"]) if "hmac-secret" in extensions else None
    options = _options(value[5], ("up", "uv", "rk")) if 5 in value else {}
    if "rk" in options:
        _fail(INVALID_OPTION)
    protocol = _pin_protocol(value[7]) if 7 in value else None
    return GetAssertionRequest(
        rp_id, client_hash, allow, hmac_secret, options.get("up", True),
        options.get("uv", False),
        _pin_auth(value[6], protocol, True) if 6 in value else None, protocol,
    )


def _pin(value):
    value = _map(value)
    subcommand = _uint(_required(value, 2))
    if subcommand not in (1, 2, 3, 4, 5, 6, 7, 9):
        _fail(INVALID_SUBCOMMAND)
    protocol = _pin_protocol(value[1]) if 1 in value else None
    required = {
        2: (1,),
        3: (1, 3, 4, 5), 4: (1, 3, 4, 5, 6),
        5: (1, 3, 6), 6: (1, 3, 9), 9: (1, 3, 6, 9),
    }
    for key in required.get(subcommand, ()):
        _required(value, key)
    key = _cose_key(value[3]) if 3 in value else None
    new_pin = _bytes(value[5], 64, 80) if 5 in value else None
    if new_pin is not None and len(new_pin) != (80 if protocol == 2 else 64):
        _fail(INVALID_LENGTH)
    pin_hash = _bytes(value[6], 16 if protocol != 2 else 32, 16 if protocol != 2 else 32) if 6 in value else None
    permissions = _uint(value[9]) if 9 in value else None
    if permissions == 0 or (permissions is not None and permissions & ~0x3F):
        _fail(INVALID_PARAMETER)
    rp_id = _text(value[10], 1) if 10 in value else None
    if permissions is not None and permissions & 0x03 and rp_id is None:
        _fail(MISSING_PARAMETER)
    return ClientPinRequest(
        protocol, subcommand, key,
        _pin_auth(value[4], protocol) if 4 in value else None,
        new_pin, pin_hash, permissions, rp_id,
    )


def _management(value, encoded_params):
    value = _map(value)
    subcommand = _uint(_required(value, 1))
    if subcommand not in (1, 2, 3, 4, 5, 6, 7):
        _fail(INVALID_SUBCOMMAND)
    if subcommand in (1, 2, 4, 6, 7) and 4 not in value:
        _fail(PUAT_REQUIRED)
    params = _map(value[2]) if 2 in value else {}
    if subcommand in (4, 6, 7):
        _required(value, 2)
    rp_hash = _bytes(_required(params, 1, True), 32, 32) if subcommand == 4 else None
    credential = _descriptor(_required(params, 2, True)) if subcommand in (6, 7) else None
    user = _user(_required(params, 3, True)) if subcommand == 7 else None
    protocol = _pin_protocol(value[3]) if 3 in value else None
    if subcommand in (1, 2, 4, 6, 7):
        _required(value, 3)
    # Only parameter-bearing operations include subCommandParams in the MAC.
    # Accepted extra maps on metadata/RP enumeration do not change their auth input.
    auth_material = bytes((subcommand,))
    if subcommand in (4, 6, 7):
        auth_material += encoded_params
    return CredentialManagementRequest(
        subcommand, rp_hash, credential, user, protocol,
        _pin_auth(value[4], protocol) if 4 in value else None,
        auth_material,
    )


_NO_PARAMS = {4: GetInfoRequest, 7: ResetRequest, 8: GetNextAssertionRequest, 11: SelectionRequest}
_SCHEMAS = {1: _make, 2: _get, 6: _pin}


def decode_request(command: int, payload: bytes) -> Request:
    """Return a typed request or raise CtapError with the exact wire code."""
    if command in _NO_PARAMS:
        if payload:
            _fail(INVALID_PARAMETER)
        return _NO_PARAMS[command]()
    if command == 10 or command == 0x41:
        # The preview command number carries the same request, so it decodes the
        # same way. See dispatcher.COMMANDS for why both numbers exist.
        value, encoded_params = _decode(payload, 2)
        return _management(value, encoded_params)
    schema = _SCHEMAS.get(command)
    if schema is None:
        _fail(INVALID_COMMAND)
    return schema(_decode(payload))


def _head(major: int, number: int) -> bytes:
    if number < 24:
        return bytes(((major << 5) | number,))
    if number < 256:
        return bytes(((major << 5) | 24, number))
    if number < 65536:
        return bytes(((major << 5) | 25,)) + number.to_bytes(2, "big")
    if number <= 0xFFFFFFFF:
        return bytes(((major << 5) | 26,)) + number.to_bytes(4, "big")
    _fail(INVALID_PARAMETER)


def _encode(value, depth: int):
    if type(value) is RawCbor:
        return value.encoded
    if value is None:
        return b"\xf6"
    if value is False:
        return b"\xf4"
    if value is True:
        return b"\xf5"
    if type(value) is int:
        return _head(0, value) if value >= 0 else _head(1, -value - 1)
    if type(value) is bytes:
        return _head(2, len(value)) + value
    if type(value) is str:
        raw = value.encode("utf-8")
        return _head(3, len(raw)) + raw
    if depth >= MAX_DEPTH:
        _fail(INVALID_PARAMETER)
    if type(value) in (list, tuple):
        return _head(4, len(value)) + b"".join(_encode(item, depth + 1) for item in value)
    if type(value) is dict:
        pairs = []
        for key, item in value.items():
            if type(key) not in (int, str, bytes):
                _fail(INVALID_PARAMETER)
            pairs.append((_encode(key, depth + 1), _encode(item, depth + 1)))
        pairs.sort(key=lambda pair: pair[0])
        return _head(5, len(pairs)) + b"".join(k + v for k, v in pairs)
    _fail(CBOR_UNEXPECTED_TYPE)


def encode_response(value: object) -> bytes:
    """Encode a successful response body (the dispatcher adds status 0)."""
    result = _encode(value, 0)
    if len(result) > MAX_MESSAGE - 1:
        _fail(REQUEST_TOO_LARGE)
    return result
