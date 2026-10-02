"""Transaction-scoped grants. PIN verification itself belongs to the PIN service."""

from .presence import default_provider

IDLE = 0
WAIT_PIN = 1
PIN_VERIFIED = 2
WAIT_PRESENCE = 3
AUTHORIZED = 4
USED = 5
CONTINUATION = 6

# A continuation is bounded, and the bound depends on what is being continued. An
# assertion series cannot outrun the decoder's ceiling on an allow list, while
# credential management walks numbered slots and there are a hundred of them, so
# the most follow-ups an enumeration can owe is ninety-nine.
MAX_ASSERTION_FOLLOW_UPS = 9
MAX_ENUMERATION_FOLLOW_UPS = 99


class PolicyError(Exception):
    pass


class TransactionKey:
    """A caller-created fresh nonce distinguishes requests on the same channel."""

    def __init__(self, connection_generation: int, cid: int, nonce: bytes) -> None:
        if connection_generation < 0 or not 0 < cid < 0xFFFFFFFF:
            raise ValueError("invalid transaction channel")
        if not isinstance(nonce, bytes) or len(nonce) != 32:
            raise ValueError("transaction nonce must be 32 bytes")
        self._value = (connection_generation, cid, nonce)

    @property
    def connection_generation(self):
        return self._value[0]

    @property
    def cid(self):
        return self._value[1]

    @property
    def nonce(self):
        return self._value[2]

    def __eq__(self, other):
        return isinstance(other, TransactionKey) and self._value == other._value


def _wipe(buffer: bytearray) -> None:
    for i in range(len(buffer)):
        buffer[i] = 0


class Policy:
    def __init__(self, presence=None, ticks_ms=None) -> None:
        # A caller may hand in a provider; a firmware that does not gets the one
        # its image actually has, which is the hardware line on a device and the
        # fail-closed base anywhere else.
        self.presence = presence if presence is not None else default_provider()
        self.key = None
        self.rp_id_hash = None
        self.command = None
        self.state = IDLE
        self.buffers = []
        self.remaining = 0
        self.required_permissions = 0
        self._ticket = None
        self._ticks_ms = ticks_ms
        self._presence_started_ms = 0
        self._presence_timeout_ms = 0

    def _now(self) -> int:
        if self._ticks_ms is not None:
            return self._ticks_ms()
        from utime import ticks_ms

        return ticks_ms()

    def presence_remaining_ms(self):
        """Read the fixed wait deadline without advancing a secret-capable task."""
        if self.state != WAIT_PRESENCE:
            return None
        elapsed = (self._now() - self._presence_started_ms) & ((1 << 30) - 1)
        return max(0, self._presence_timeout_ms - elapsed)

    def _check(self, key, state=None) -> None:
        if self.key is None or key != self.key:
            raise PolicyError("wrong transaction")
        if state is not None and self.state != state:
            raise PolicyError("invalid policy transition")

    def begin(self, key, command: int, rp_id_hash) -> None:
        if self.state != IDLE:
            raise PolicyError("transaction busy")
        # No PIN crypto or credential operations are implemented here.
        # Permission bits match the verified PIN service's grants.
        # Reset, selection and ClientPIN require presence only. ClientPIN's one
        # presence-taking subcommand is setPIN, which by definition runs before
        # any PIN exists, so there is no grant it could be asked to carry.
        # 0x41 is credential management under its preview number, so it buys the
        # same permission as 0x0A and nothing more.
        permissions = {1: 1, 2: 2, 6: 0, 7: 0, 10: 4, 11: 0, 0x41: 4}
        if not isinstance(key, TransactionKey) or command not in permissions:
            raise PolicyError("unsupported transaction")
        if rp_id_hash is not None and (
            not isinstance(rp_id_hash, bytes) or len(rp_id_hash) != 32
        ):
            raise PolicyError("invalid RP hash")
        if command in (1, 2) and rp_id_hash is None:
            raise PolicyError("RP hash required")
        self.key = key
        self._ticket = object()
        self.command = command
        self.rp_id_hash = rp_id_hash
        self.required_permissions = permissions[command]
        self.state = WAIT_PIN if self.required_permissions else PIN_VERIFIED

    def retain(self, key, buffer: bytearray) -> None:
        """Transfer ownership of mutable secret storage until finish or abort."""
        if not isinstance(buffer, bytearray):
            raise PolicyError("secret storage must be mutable")
        try:
            self._check(key)
            if len(self.buffers) >= 16 or len(buffer) > 1024:
                raise PolicyError("transient storage limit")
            self.buffers.append(buffer)
        except BaseException:
            _wipe(buffer)
            raise

    def authorize_pin(self, key, permissions: int, rp_id_hash, token: bytearray) -> None:
        """Accept only a grant already cryptographically verified by the PIN service.

        Not a verifier, and never callable directly from wire request fields.
        Ownership of token transfers here even when the grant is rejected.
        """
        if not isinstance(token, bytearray):
            raise PolicyError("PIN token must be mutable")
        try:
            self._check(key, WAIT_PIN)
            if (
                not token
                or permissions & self.required_permissions != self.required_permissions
                or rp_id_hash != self.rp_id_hash
            ):
                raise PolicyError("PIN scope mismatch")
            self.retain(key, token)
            self.state = PIN_VERIFIED
        except BaseException:
            _wipe(token)
            raise

    async def consume_presence(self, key, timeout_ms: int = 30000) -> None:
        self._check(key, PIN_VERIFIED)
        if not 0 < timeout_ms <= 30000:
            raise PolicyError("invalid presence timeout")
        self.state = WAIT_PRESENCE
        ticket = self._ticket
        try:
            self._presence_started_ms = self._now()
            self._presence_timeout_ms = timeout_ms
            granted = await self.presence.wait_for_fresh_edge(key, timeout_ms)
            if self._ticket is not ticket:
                raise PolicyError("expired presence wait")
            self._check(key, WAIT_PRESENCE)
            if not granted or self.presence_remaining_ms() == 0:
                raise PolicyError("presence denied")
            self.state = AUTHORIZED
            self._presence_started_ms = 0
            self._presence_timeout_ms = 0
        except BaseException:
            # An old suspended waiter must not erase a newer transaction.
            if self._ticket is ticket:
                self.abort("presence-failed")
            raise

    def take_authorization(self, key) -> None:
        """Consume the grant exactly once, immediately before the secret operation."""
        self._check(key, AUTHORIZED)
        self.state = USED

    def take_authorization_without_presence(self, key) -> None:
        """Consume the grant for the one operation that has no physical edge.

        CTAP 2.1 gives getAssertion a presence-less form, options {"up": false}:
        the platform is asking what this device holds before it decides what to
        prompt for, and the answer is an assertion whose presence bit is clear.
        Nothing was confirmed, so nothing claims to have been -- and WebAuthn
        requires a relying party to reject an assertion without that bit, so the
        answer cannot be spent as a login.

        The relaxation is deliberately narrow. Only an assertion may use it, and
        only from a verified PIN, so the request still has to carry a token
        scoped to this relying party with the assertion permission on it.
        """
        self._check(key, PIN_VERIFIED)
        if self.command != 2:
            raise PolicyError("presence is required for this command")
        self.state = USED

    def _erase_buffers(self) -> None:
        for buffer in self.buffers:
            _wipe(buffer)
        self.buffers.clear()

    def continue_responses(self, key, rp_id_hash, remaining: int) -> None:
        """Reserve bounded follow-ups inside the already-authorized operation.

        Only assertions and credential management have follow-ups. Naming the two
        commands here rather than accepting whatever the caller is running keeps a
        future handler from acquiring a continuation by accident.
        """
        self._check(key, USED)
        if self.command == 2:
            limit = MAX_ASSERTION_FOLLOW_UPS
        elif self.command == 10 or self.command == 0x41:
            limit = MAX_ENUMERATION_FOLLOW_UPS
        else:
            raise PolicyError("invalid response continuation")
        if rp_id_hash != self.rp_id_hash or not 1 <= remaining <= limit:
            raise PolicyError("invalid response continuation")
        self._erase_buffers()
        self.remaining = remaining
        self.state = CONTINUATION

    def next_response(self, key, rp_id_hash) -> None:
        self._check(key, CONTINUATION)
        if rp_id_hash != self.rp_id_hash:
            raise PolicyError("wrong continuation scope")
        self.remaining -= 1
        if not self.remaining:
            self.finish(key)

    def complete_response(self, key) -> None:
        """Erase each response's secrets, preserving only continuation metadata."""
        self._check(key)
        if self.state == CONTINUATION:
            self._erase_buffers()
        else:
            self.finish(key)

    def finish(self, key) -> None:
        self._check(key)
        self.abort("finished")

    def abort(self, reason: str) -> None:
        # Erase memory before dropping any references or invoking external cleanup.
        self._erase_buffers()
        self.key = None
        self.rp_id_hash = None
        self.command = None
        self.remaining = 0
        self.required_permissions = 0
        self.state = IDLE
        self._ticket = None
        self._presence_started_ms = 0
        self._presence_timeout_ms = 0
        self.presence.clear()
