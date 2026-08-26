"""
X3DH key agreement.

Changes from the original:

  * The two roles now have separate functions. Previously one symmetric helper
    was called with hand-swapped arguments on the responder side, which meant
    correctness depended on the caller getting the argument order right.
  * The agreement runs against the peer's *signed* prekey rather than a bare
    unauthenticated key, so a relay cannot inject its own.
  * The shared secret comes out of real HKDF with a domain-separation label.

One-time prekeys from the full X3DH spec are omitted: both peers are online and
exchange bundles directly, so there is no offline prekey server to consume them.
"""

from __future__ import annotations

from nacl.bindings import crypto_scalarmult
from nacl.public import PrivateKey, PublicKey

from crypto.kdf import hkdf
from crypto.keys import Bundle

X3DH_INFO = b"SpectreProtocol/x3dh/v1"

# Prepended to the DH concatenation, as in the X3DH spec, to keep the input
# domain of the KDF disjoint from any raw DH output.
F = b"\xff" * 32


def dh(private: PrivateKey, public: bytes) -> bytes:
    """X25519 Diffie-Hellman returning the raw 32-byte shared secret."""
    if isinstance(public, PublicKey):
        public = public.encode()
    return crypto_scalarmult(private.encode(), public)


def _derive(dh1: bytes, dh2: bytes, dh3: bytes) -> bytes:
    return hkdf(F + dh1 + dh2 + dh3, info=X3DH_INFO)


def x3dh_initiator(identity, peer_bundle: Bundle) -> bytes:
    """
    Initiator side. `identity` is our own `Identity`; `peer_bundle` is the
    responder's verified bundle.

    Caller must have checked `peer_bundle.verify()` first.
    """
    peer_spk = peer_bundle.signed_prekey
    peer_ik = peer_bundle.identity_dh()

    dh1 = dh(identity.identity_dh_private, peer_spk)   # IK_a  x SPK_b
    dh2 = dh(identity.ephemeral_private, peer_ik)      # EK_a  x IK_b
    dh3 = dh(identity.ephemeral_private, peer_spk)     # EK_a  x SPK_b
    return _derive(dh1, dh2, dh3)


def x3dh_responder(identity, peer_bundle: Bundle) -> bytes:
    """
    Responder side, mirroring `x3dh_initiator`. `peer_bundle` is the
    initiator's verified bundle.
    """
    peer_eph = peer_bundle.ephemeral
    peer_ik = peer_bundle.identity_dh()

    dh1 = dh(identity.signed_prekey_private, peer_ik)   # SPK_b x IK_a
    dh2 = dh(identity.identity_dh_private, peer_eph)    # IK_b  x EK_a
    dh3 = dh(identity.signed_prekey_private, peer_eph)  # SPK_b x EK_a
    return _derive(dh1, dh2, dh3)
