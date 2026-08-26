"""
HKDF-SHA256 (RFC 5869).

The original code called BLAKE2b on `input || salt` and labelled the result
"HKDF output". That is not HKDF: appending a salt to the message gives none of
the extract-then-expand separation, and it offers no domain separation between
different uses of the same input. Every key derivation in the protocol now goes
through the real construction with an explicit `info` label.
"""

from __future__ import annotations

import hashlib
import hmac

HASH = hashlib.sha256
HASH_LEN = 32


def extract(salt: bytes, ikm: bytes) -> bytes:
    """HKDF-Extract: compress the input keying material into a PRK."""
    if not salt:
        salt = b"\x00" * HASH_LEN
    return hmac.new(salt, ikm, HASH).digest()


def expand(prk: bytes, info: bytes, length: int = HASH_LEN) -> bytes:
    """HKDF-Expand: stretch a PRK into `length` bytes bound to `info`."""
    if length > 255 * HASH_LEN:
        raise ValueError("HKDF cannot expand to more than 255 * HashLen bytes")

    out = b""
    block = b""
    counter = 1
    while len(out) < length:
        block = hmac.new(prk, block + info + bytes([counter]), HASH).digest()
        out += block
        counter += 1
    return out[:length]


def hkdf(ikm: bytes, info: bytes, salt: bytes = b"", length: int = HASH_LEN) -> bytes:
    """Full extract-then-expand."""
    return expand(extract(salt, ikm), info, length)
