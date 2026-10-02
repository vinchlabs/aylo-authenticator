"""CTAP GetInfo: what this device claims to be.

Every member here is a statement a platform will act on, so each one is present
only when the thing it describes exists and has been tested. Two of them decide
whether ClientPIN is usable at all:

  * pinUvAuthProtocols and minPINLength are mandatory once clientPin is offered.
    They were missing before, which left the response claiming PIN support
    without saying which protocol to speak or how long a PIN has to be.
  * pinUvAuthToken says getPinUvAuthTokenUsingPinWithPermissions exists. A
    platform that does not see it falls back to getPINToken, which this
    authenticator refuses, so without this member there is no way to obtain a
    token at all.

The one state-dependent member, clientPin, is read from the vault on every call
rather than cached. It decides whether the platform offers to set a PIN or to
enter one, and a stale answer sends the user down the wrong path. The cost is a
replica scan per GetInfo, which is worth paying for an answer that cannot be
wrong.
"""

from .cbor_codec import MAX_MESSAGE
from .client_pin import CREDENTIAL_MANAGEMENT, GRANTABLE
from .pin_protocol import SUPPORTED
from .presence import presence_is_assumed
from .protocol import AAGUID

COMMAND = 4

VERSIONS = 1
EXTENSIONS = 2
AAGUID_KEY = 3
OPTIONS = 4
MAX_MSG_SIZE = 5
PIN_UV_AUTH_PROTOCOLS = 6
MAX_CREDENTIAL_ID_LENGTH = 8
TRANSPORTS = 9
ALGORITHMS = 10
MIN_PIN_LENGTH = 13
# Vendor range. The image audit requires this marker in a development build and
# forbids it in a production one.
BUILD_MARKER = 0xF0

VERSION = "FIDO_2_1"
# What the vault can build, most preferred first. The request decoder picks the
# first algorithm the relying party lists that appears here, so this order is a
# statement of preference rather than a filter.
ALGORITHM_PREFERENCE = (-7, -8)
# The ceiling the vault puts on a credential identifier.
MAX_CREDENTIAL_ID = 704
DEVELOPMENT_MARKER = "AUTH-DEV"
# A build that confirms operations nobody confirmed says so here, in the one
# field a platform reads before it does anything else. AUTH-DEV stays a prefix
# because that is what the image audit looks for in a development build; the
# suffix is what no platform can miss.
ASSUMED_PRESENCE_MARKER = "AUTH-DEV-NOUP"


def response(auth=None) -> dict:
    """Build the GetInfo response for this device in its present state."""
    if auth is None:
        import trezorauth

        auth = trezorauth

    state, _retries, _consecutive = auth.status()
    # true says a PIN is set, false says one can be set, and absent would say
    # ClientPIN is not supported -- which it is, so absent is never right here.
    # A blocked session still has a PIN. A faulted or foreign-media vault has
    # none that can be used, and answering false points the platform at setPIN,
    # which fails cleanly, rather than at a PIN prompt that cannot succeed.
    pin_is_set = state == auth.OK or state == auth.PIN_AUTH_BLOCKED

    # "uv" is false, and this is the one claim in this response that is not true:
    # false says a built-in user verification method exists but is unconfigured, and
    # this device has none and will have none. It is here because OpenSSH will not
    # otherwise sign with this key.
    #
    # sk_select_by_cred() picks the device for a non-discoverable credential. With
    # one device attached it uses that device without asking it anything -- but only
    # when GetInfo carries "uv", true or false. Absent, it falls back to sk_try(),
    # which sends getAssertion with up false and no PIN and accepts only FIDO_OK.
    # Nothing here signs without a verified PIN, so that probe cannot be answered,
    # and no error code helps: sk_try() maps only libfido2's U2F
    # FIDO_ERR_USER_PRESENCE_REQUIRED to success, a different constant from the
    # CTAP2 0x3B this device returns. Same code in OpenSSH 8.9 through 10.0.
    #
    # Nothing follows from the claim. No secret is disclosed and nothing is signed;
    # a request that really asks for built-in verification -- "uv": true with no
    # pinUvAuthParam -- still gets CTAP2_ERR_PUAT_REQUIRED, because the policy puts
    # both credential commands in WAIT_PIN whatever the options map says.
    #
    # alwaysUv is true because it is: neither credential command has a path that
    # runs without a verified PIN.
    options = {
        "rk": True,
        "uv": False,
        "alwaysUv": True,
        "clientPin": pin_is_set,
        "pinUvAuthToken": True,
    }
    if GRANTABLE & CREDENTIAL_MANAGEMENT:
        options["credMgmt"] = True
        # The same feature under the name CTAP 2.1-PRE gave it. Advertised because
        # the implementation really does answer the preview command number, and a
        # client that looks for this name is a client that will send that number.
        options["credentialMgmtPreview"] = True

    return {
        VERSIONS: [VERSION],
        # credProtect is honoured, and only as UV_REQUIRED, which is the single
        # value the request decoder accepts. hmac-secret is withheld: the salts
        # arrive encrypted under the shared secret and nothing outside the vault
        # can open them, so claiming the extension would promise an output that
        # cannot be produced.
        EXTENSIONS: ["credProtect"],
        AAGUID_KEY: AAGUID,
        OPTIONS: options,
        MAX_MSG_SIZE: MAX_MESSAGE,
        PIN_UV_AUTH_PROTOCOLS: list(SUPPORTED),
        # maxCredentialCountInList is deliberately absent. How many descriptors
        # fit depends on how long their identifiers are, and an identifier runs
        # from 78 to 704 bytes, so no single number is true for every list.
        # maxMsgSize already states the constraint that actually binds.
        MAX_CREDENTIAL_ID_LENGTH: MAX_CREDENTIAL_ID,
        TRANSPORTS: ["usb"],
        ALGORITHMS: [{"alg": algorithm, "type": "public-key"}
                     for algorithm in ALGORITHM_PREFERENCE],
        MIN_PIN_LENGTH: auth.MIN_PIN_CODE_POINTS,
        BUILD_MARKER: ASSUMED_PRESENCE_MARKER
        if presence_is_assumed(auth)
        else DEVELOPMENT_MARKER,
    }


class GetInfo:
    """Holds no state; the vault is asked fresh each time."""

    def __init__(self, auth=None) -> None:
        self._auth = auth

    async def handle(self, request, context) -> dict:
        return response(self._auth)


def register(dispatcher, auth=None) -> None:
    dispatcher.register(COMMAND, GetInfo(auth).handle)
