"""
Tests for identity keys, signed prekey bundles and the X3DH agreement.

These cover finding #2: nothing authenticated the key bundles, so the relay
could hand each peer its own keys and read the whole conversation.
"""

from __future__ import annotations

import base64

import pytest

from crypto.keys import Bundle, Identity, safety_number
from crypto.x3dh import x3dh_initiator, x3dh_responder


def test_x3dh_agreement():
    alice, bob = Identity.generate("alice"), Identity.generate("bob")
    sk_a = x3dh_initiator(alice, bob.public_bundle("room"))
    sk_b = x3dh_responder(bob, alice.public_bundle("room"))
    assert sk_a == sk_b
    assert len(sk_a) == 32


def test_distinct_sessions_derive_distinct_secrets():
    alice, bob = Identity.generate("alice"), Identity.generate("bob")
    first = x3dh_initiator(alice, bob.public_bundle("room"))
    # A fresh ephemeral on each session must change the shared secret.
    alice.rotate_ephemeral()
    second = x3dh_initiator(alice, bob.public_bundle("room"))
    assert first != second


def test_bundle_signature_verifies():
    bundle = Identity.generate("bob").public_bundle("room")
    assert bundle.verify() is True


def test_tampered_signed_prekey_is_rejected():
    """The relay swapping in its own prekey must be detected."""
    bob = Identity.generate("bob")
    attacker = Identity.generate("mallory")

    forged = bob.public_bundle("room").to_dict()
    forged["signed_prekey"] = attacker.public_bundle("room").to_dict()["signed_prekey"]

    assert Bundle.from_dict(forged).verify() is False


def test_tampered_identity_key_is_rejected():
    bob = Identity.generate("bob")
    attacker = Identity.generate("mallory")

    forged = bob.public_bundle("room").to_dict()
    forged["identity"] = attacker.public_bundle("room").to_dict()["identity"]

    assert Bundle.from_dict(forged).verify() is False


def test_tampered_ephemeral_is_rejected():
    bob = Identity.generate("bob")
    attacker = Identity.generate("mallory")

    forged = bob.public_bundle("room").to_dict()
    forged["ephemeral"] = attacker.public_bundle("room").to_dict()["ephemeral"]

    assert Bundle.from_dict(forged).verify() is False


def test_bundle_is_bound_to_its_room_and_user():
    """
    A bundle lifted from one room or renamed to another user must not verify,
    so the relay cannot replay a genuine bundle into a different conversation.
    """
    bob = Identity.generate("bob")

    moved = bob.public_bundle("room-a").to_dict()
    moved["room"] = "room-b"
    assert Bundle.from_dict(moved).verify() is False

    renamed = bob.public_bundle("room-a").to_dict()
    renamed["user"] = "alice"
    assert Bundle.from_dict(renamed).verify() is False


def test_bundle_survives_serialisation():
    bundle = Identity.generate("bob").public_bundle("room")
    assert Bundle.from_dict(bundle.to_dict()).verify() is True


def test_identity_is_persistent_across_reload():
    alice = Identity.generate("alice")
    seed = alice.export_seed()
    reloaded = Identity.from_seed("alice", seed)
    assert reloaded.identity_public_bytes() == alice.identity_public_bytes()


def test_safety_number_is_symmetric_and_stable():
    """
    Both peers must read the same digits, in the same order, regardless of who
    computes it -- otherwise out-of-band verification is unusable.
    """
    alice, bob = Identity.generate("alice"), Identity.generate("bob")
    a_view = safety_number(alice.identity_public_bytes(), bob.identity_public_bytes())
    b_view = safety_number(bob.identity_public_bytes(), alice.identity_public_bytes())

    assert a_view == b_view
    assert a_view == safety_number(alice.identity_public_bytes(), bob.identity_public_bytes())
    assert len(a_view.replace(" ", "")) == 60
    assert a_view.replace(" ", "").isdigit()


def test_safety_number_changes_if_a_key_changes():
    alice, bob, mallory = (Identity.generate(n) for n in ("alice", "bob", "mallory"))
    genuine = safety_number(alice.identity_public_bytes(), bob.identity_public_bytes())
    mitm = safety_number(alice.identity_public_bytes(), mallory.identity_public_bytes())
    assert genuine != mitm


def test_full_mitm_attempt_is_detected():
    """
    End to end: the relay substitutes its own bundle for bob's. Signature
    verification passes (mallory signs her own bundle correctly), so the
    safety number is what actually catches it.
    """
    alice, bob, mallory = (Identity.generate(n) for n in ("alice", "bob", "mallory"))

    forged = mallory.public_bundle("room").to_dict()
    forged["user"] = "bob"
    # Mallory cannot re-sign as bob, so the impersonation fails outright.
    assert Bundle.from_dict(forged).verify() is False

    # Even if she serves a validly-signed bundle under her own name, alice's
    # safety number no longer matches what bob reads out.
    served = mallory.public_bundle("room")
    assert served.verify() is True
    assert safety_number(
        alice.identity_public_bytes(), served.identity
    ) != safety_number(
        alice.identity_public_bytes(), bob.identity_public_bytes()
    )
