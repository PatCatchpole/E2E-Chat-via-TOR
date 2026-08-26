"""
Session-level checks on how incoming key bundles are trusted.

These exercise `SpectreSession._handle_bundle` directly. The session builds its
Socket.IO client lazily and does not connect in the constructor, so it can be
driven offline.
"""

from __future__ import annotations

import pytest

import storage
from crypto.keys import Identity
from session import PeerIdentityChanged, SessionError, SpectreSession

ROOM = "testroom"


@pytest.fixture(autouse=True)
def isolated_storage(tmp_path, monkeypatch):
    """Keep tests out of the real ~/.spectre."""
    monkeypatch.setattr(storage, "SPECTRE_DIR", tmp_path)
    monkeypatch.setattr(storage, "STATE_DIR", tmp_path / "state")
    monkeypatch.setattr(storage, "PEERS_DIR", tmp_path / "peers")
    storage.ensure_dirs()
    yield


def make_session(user="alice", is_initiator=True):
    events = []
    session = SpectreSession(
        url="http://127.0.0.1:1", room=ROOM, user=user, password="pw",
        is_initiator=is_initiator, use_tor=False,
        on_event=lambda kind, payload: events.append((kind, payload)),
    )
    return session, events


def bundle_of(identity: Identity) -> dict:
    return identity.public_bundle(ROOM).to_dict()


def test_valid_bundle_establishes_a_session():
    session, _ = make_session()
    session._handle_bundle(bundle_of(Identity.generate("bob")))
    assert session.ready
    assert session.peer_user == "bob"
    assert session.safety_number


def test_bundle_signed_by_another_identity_is_rejected():
    session, _ = make_session()
    forged = bundle_of(Identity.generate("mallory"))
    forged["user"] = "bob"                      # claim to be bob

    with pytest.raises(SessionError, match="signature"):
        session._handle_bundle(forged)
    assert not session.ready


def test_bundle_for_a_different_room_is_rejected():
    session, _ = make_session()
    other = Identity.generate("bob").public_bundle("some-other-room").to_dict()

    with pytest.raises(SessionError, match="room"):
        session._handle_bundle(other)
    assert not session.ready


def test_our_own_bundle_reflected_back_is_rejected():
    session, _ = make_session(user="alice")
    mirrored = bundle_of(Identity.generate("alice"))

    with pytest.raises(SessionError, match="own bundle"):
        session._handle_bundle(mirrored)


def test_changed_peer_identity_is_detected_on_first_contact_of_a_new_key():
    session, _ = make_session()
    session._handle_bundle(bundle_of(Identity.generate("bob")))
    assert session.ready

    # A different long-term key arriving for the same peer in the same room.
    impostor = bundle_of(Identity.generate("mallory"))
    impostor["user"] = "bob"
    with pytest.raises(SessionError):
        session._handle_bundle(impostor)


def test_changed_peer_identity_is_detected_even_with_a_live_session():
    """
    The regression this file exists for: `_handle_bundle` used to return early
    whenever a ratchet already existed, so a peer's identity key could change
    without the check ever running -- silently, in exactly the situation where
    an interception would be most valuable to an attacker.
    """
    bob = Identity.generate("bob")
    session, _ = make_session()
    session._handle_bundle(bundle_of(bob))
    assert session.ready

    # Bob reappears with a validly-signed bundle under a *different* identity,
    # as happens on a reinstall, a second machine, or an interception.
    new_bob = Identity.generate("bob")
    with pytest.raises(PeerIdentityChanged) as caught:
        session._handle_bundle(bundle_of(new_bob))

    assert caught.value.peer_user == "bob"
    assert caught.value.old_identity != caught.value.new_identity


def test_unchanged_identity_does_not_renegotiate_an_existing_session():
    """A reconnect re-sends the same bundle; it must not reset the ratchet."""
    bob = Identity.generate("bob")
    session, _ = make_session()
    session._handle_bundle(bundle_of(bob))

    ratchet = session._ratchet
    session._handle_bundle(bundle_of(bob))      # same identity, fresh bundle

    assert session._ratchet is ratchet, "existing ratchet was replaced"


def test_trusting_a_new_identity_clears_the_stale_session():
    bob = Identity.generate("bob")
    session, _ = make_session()
    session._handle_bundle(bundle_of(bob))

    new_bob = Identity.generate("bob")
    try:
        session._handle_bundle(bundle_of(new_bob))
    except PeerIdentityChanged as e:
        session._pending_identity_change = e

    assert session.trust_new_identity() is True

    from crypto.keys import b64e
    recorded = storage.load_known_peer("alice", ROOM)
    assert recorded["identity"] == b64e(new_bob.identity_public_bytes()), \
        "the new key was not recorded"
    assert storage.load_state("alice", ROOM) is None, "stale ratchet state kept"
    assert session.peer_verified is False, "trust must not imply verification"
