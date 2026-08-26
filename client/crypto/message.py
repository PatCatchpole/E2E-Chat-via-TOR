"""
Authenticated encryption for a single message.

The original accepted an `ad` argument and silently ignored it, leaving the
ratchet header (DH public key and counters) outside the authentication tag.
A relay could rewrite those fields freely.

XChaCha20-Poly1305 replaces SecretBox here specifically because it takes
associated data, so the header is covered by the tag. Its 24-byte nonce is also
large enough that random generation carries no practical collision risk.
"""

from __future__ import annotations

from nacl.bindings import (
    crypto_aead_xchacha20poly1305_ietf_decrypt,
    crypto_aead_xchacha20poly1305_ietf_encrypt,
    crypto_aead_xchacha20poly1305_ietf_KEYBYTES,
    crypto_aead_xchacha20poly1305_ietf_NPUBBYTES,
)
from nacl.exceptions import CryptoError
from nacl.utils import random as nacl_random

KEY_BYTES = crypto_aead_xchacha20poly1305_ietf_KEYBYTES
NONCE_BYTES = crypto_aead_xchacha20poly1305_ietf_NPUBBYTES


def encrypt(key: bytes, plaintext: bytes, associated_data: bytes) -> tuple:
    """Returns (nonce, ciphertext). `associated_data` is authenticated, not encrypted."""
    if len(key) != KEY_BYTES:
        raise ValueError(f"message key must be {KEY_BYTES} bytes, got {len(key)}")

    nonce = nacl_random(NONCE_BYTES)
    ciphertext = crypto_aead_xchacha20poly1305_ietf_encrypt(
        plaintext, associated_data, nonce, key
    )
    return nonce, ciphertext


def decrypt(key: bytes, nonce: bytes, ciphertext: bytes, associated_data: bytes) -> bytes:
    """
    Raises `nacl.exceptions.CryptoError` if the ciphertext or the associated
    data has been altered.
    """
    if len(key) != KEY_BYTES:
        raise ValueError(f"message key must be {KEY_BYTES} bytes, got {len(key)}")
    if len(nonce) != NONCE_BYTES:
        raise CryptoError("bad nonce length")

    return crypto_aead_xchacha20poly1305_ietf_decrypt(
        ciphertext, associated_data, nonce, key
    )
