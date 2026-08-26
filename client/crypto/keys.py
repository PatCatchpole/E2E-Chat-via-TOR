"""
Long-term identities, signed prekey bundles and safety numbers.

This is the fix for the MITM hole: previously the relay handed each peer the
other's raw public keys with nothing binding them to an identity, so it could
substitute its own keys for both sides and read everything.

Now a peer has one long-term Ed25519 identity key. Every other public key it
publishes is signed by that identity, and the signature covers the user name
and room, so a bundle cannot be forged, altered, or replayed into a different
conversation. The identity key itself is trusted only as far as the users
verify it out of band -- hence `safety_number`.
"""

from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass

from nacl.exceptions import BadSignatureError
from nacl.public import PrivateKey, PublicKey
from nacl.signing import SigningKey, VerifyKey

# Domain-separation tags. Signing raw key bytes with no context lets a
# signature made for one purpose be replayed as another.
SPK_CONTEXT = b"SpectreProtocol/signed-prekey/v1"
EPH_CONTEXT = b"SpectreProtocol/ephemeral/v1"


def b64e(raw: bytes) -> str:
    return base64.b64encode(raw).decode()


def b64d(text: str) -> bytes:
    return base64.b64decode(text.encode())


def _signed_payload(context: bytes, user: str, room: str, key: bytes) -> bytes:
    """
    Length-prefixed so that ("ab", "c") and ("a", "bc") cannot produce the same
    bytes -- without this, the user/room binding could be shifted around.
    """
    parts = [context, user.encode(), room.encode(), key]
    return b"".join(len(p).to_bytes(4, "big") + p for p in parts)


@dataclass(frozen=True)
class Bundle:
    """The public half of an identity, as published to a room."""

    user: str
    room: str
    identity: bytes        # Ed25519 verify key
    signed_prekey: bytes   # X25519 public
    signed_prekey_sig: bytes
    ephemeral: bytes       # X25519 public
    ephemeral_sig: bytes

    def verify(self) -> bool:
        """
        True only if every published key is signed by this bundle's identity
        key for exactly this user and room.
        """
        verify_key = VerifyKey(self.identity)
        checks = (
            (SPK_CONTEXT, self.signed_prekey, self.signed_prekey_sig),
            (EPH_CONTEXT, self.ephemeral, self.ephemeral_sig),
        )
        for context, key, signature in checks:
            payload = _signed_payload(context, self.user, self.room, key)
            try:
                verify_key.verify(payload, signature)
            except BadSignatureError:
                return False
        return True

    def identity_dh(self) -> bytes:
        """The identity key in X25519 form, for use in X3DH."""
        return VerifyKey(self.identity).to_curve25519_public_key().encode()

    def to_dict(self) -> dict:
        return {
            "user": self.user,
            "room": self.room,
            "identity": b64e(self.identity),
            "signed_prekey": b64e(self.signed_prekey),
            "signed_prekey_sig": b64e(self.signed_prekey_sig),
            "ephemeral": b64e(self.ephemeral),
            "ephemeral_sig": b64e(self.ephemeral_sig),
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Bundle":
        return cls(
            user=data["user"],
            room=data["room"],
            identity=b64d(data["identity"]),
            signed_prekey=b64d(data["signed_prekey"]),
            signed_prekey_sig=b64d(data["signed_prekey_sig"]),
            ephemeral=b64d(data["ephemeral"]),
            ephemeral_sig=b64d(data["ephemeral_sig"]),
        )


class Identity:
    """
    A user's long-term identity plus the session keys it vouches for.

    One Ed25519 seed is the only thing that needs to persist across restarts;
    the X25519 identity key used for Diffie-Hellman is derived from it, so
    there is a single value to protect and a single fingerprint to verify.
    """

    def __init__(self, user: str, signing_key: SigningKey):
        self.user = user
        self.signing_key = signing_key
        self.identity_dh_private = signing_key.to_curve25519_private_key()

        self.signed_prekey_private = PrivateKey.generate()
        self.ephemeral_private = PrivateKey.generate()

    # ---- construction -------------------------------------------------

    @classmethod
    def generate(cls, user: str) -> "Identity":
        return cls(user, SigningKey.generate())

    @classmethod
    def from_seed(cls, user: str, seed: bytes) -> "Identity":
        return cls(user, SigningKey(seed))

    def export_seed(self) -> bytes:
        """The 32-byte secret to persist. Treat as key material."""
        return self.signing_key.encode()

    # ---- public views -------------------------------------------------

    def identity_public_bytes(self) -> bytes:
        return self.signing_key.verify_key.encode()

    def identity_dh_public(self) -> PublicKey:
        return self.signing_key.verify_key.to_curve25519_public_key()

    def rotate_ephemeral(self) -> None:
        self.ephemeral_private = PrivateKey.generate()

    def public_bundle(self, room: str) -> Bundle:
        spk = self.signed_prekey_private.public_key.encode()
        eph = self.ephemeral_private.public_key.encode()
        return Bundle(
            user=self.user,
            room=room,
            identity=self.identity_public_bytes(),
            signed_prekey=spk,
            signed_prekey_sig=self._sign(SPK_CONTEXT, room, spk),
            ephemeral=eph,
            ephemeral_sig=self._sign(EPH_CONTEXT, room, eph),
        )

    def _sign(self, context: bytes, room: str, key: bytes) -> bytes:
        payload = _signed_payload(context, self.user, room, key)
        return self.signing_key.sign(payload).signature


# ---- out-of-band verification -----------------------------------------

FINGERPRINT_ITERATIONS = 5200
FINGERPRINT_DIGITS = 30


def _fingerprint_digits(identity_public: bytes) -> str:
    """
    Iterated hash of one identity key, rendered as 30 decimal digits.

    The iteration count makes an offline search for a key with a chosen
    fingerprint expensive, which is the point of the construction.
    """
    digest = identity_public
    for _ in range(FINGERPRINT_ITERATIONS):
        digest = hashlib.sha512(digest + identity_public).digest()

    digits = ""
    for i in range(FINGERPRINT_DIGITS // 5):
        chunk = int.from_bytes(digest[i * 5:(i + 1) * 5], "big")
        digits += f"{chunk % 100000:05d}"
    return digits


def safety_number(own_identity: bytes, peer_identity: bytes) -> str:
    """
    The 60-digit number both peers read aloud to confirm there is no relay in
    the middle. Sorted so that both sides render identical digits in identical
    order regardless of who is asking.
    """
    pair = sorted([_fingerprint_digits(own_identity), _fingerprint_digits(peer_identity)])
    combined = "".join(pair)
    return " ".join(combined[i:i + 5] for i in range(0, len(combined), 5))
