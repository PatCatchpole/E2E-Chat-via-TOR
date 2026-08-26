from __future__ import annotations

from crypto.keys import Identity
from crypto.ratchet import DoubleRatchet
from crypto.x3dh import x3dh_initiator, x3dh_responder


def make_session(room: str = "spectre"):
    """
    Build a fully-initialised pair of ratchets the way the CLI does: two
    identities, a bundle exchange, X3DH, then the initial ratchet state.

    Returns (alice_ratchet, bob_ratchet).
    """
    alice = Identity.generate("alice")
    bob = Identity.generate("bob")

    alice_bundle = alice.public_bundle(room)
    bob_bundle = bob.public_bundle(room)

    # Each side verifies the other's signatures before touching the keys.
    assert alice_bundle.verify()
    assert bob_bundle.verify()

    sk_a = x3dh_initiator(alice, bob_bundle)
    sk_b = x3dh_responder(bob, alice_bundle)
    assert sk_a == sk_b, "X3DH must agree"

    a = DoubleRatchet.initiator(sk_a, bob_bundle.signed_prekey)
    b = DoubleRatchet.responder(sk_b, bob.signed_prekey_private)
    return a, b


def send(sender: DoubleRatchet, text: str) -> dict:
    return sender.encrypt(text.encode())


def recv(receiver: DoubleRatchet, packet: dict) -> str:
    return receiver.decrypt(packet).decode()
