"""Small immutable payload carrier for CTAPHID events."""


class TransportEvent:
    __slots__ = ("connection_generation", "cid", "command", "payload")

    def __init__(
        self, connection_generation: int, cid: int, command: int, payload: bytes
    ) -> None:
        if len(payload) > 1024:
            raise ValueError("CTAPHID event too large")
        self.connection_generation = connection_generation
        self.cid = cid
        self.command = command
        self.payload = bytes(payload)
