"""
Plaintext framing.

X3DH gives the initiator a sending chain immediately, but the responder has
none until it receives its first message. With two people that is invisible --
the initiator always speaks first. In a group it is not: the member who
initiates nothing (the highest username) would be unable to send to anybody
until every other member had spoken to them.

The fix is a priming message the initiator sends as soon as a session is
established. It carries no text and is never displayed; its only job is to give
the far end a sending chain.

The type byte lives *inside* the encrypted payload rather than in the header,
so the relay cannot tell a priming packet from a real one, or count how many
actual messages a conversation contains.
"""

from __future__ import annotations

PRIME = 0x00
TEXT = 0x01


class FramingError(Exception):
    pass


def frame_text(text: str) -> bytes:
    return bytes([TEXT]) + text.encode("utf-8")


def frame_prime() -> bytes:
    return bytes([PRIME])


def parse(payload: bytes):
    """
    Returns (kind, text). `text` is None for anything that is not TEXT.

    Unknown type bytes are reported rather than guessed at, so a future
    message type cannot be silently rendered as text.
    """
    if not payload:
        raise FramingError("empty payload")

    kind = payload[0]
    if kind == PRIME:
        return PRIME, None
    if kind == TEXT:
        return TEXT, payload[1:].decode("utf-8", errors="replace")
    raise FramingError(f"unknown payload type 0x{kind:02x}")
