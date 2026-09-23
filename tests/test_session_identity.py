"""
Session-level checks on how incoming key bundles are trusted.

These exercise `SpectreSession._handle_bundle` directly. The session builds its
Socket.IO client lazily and does not connect in the constructor, so it can be
driven offline.
"""

from __future__ import annotations

import pytest

import storage
from crypto.keys import Identity, b64e
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


def make_session(user="alice"):
    events = []
    session = SpectreSession(
        url="http://127.0.0.1:1", room=ROOM, user=user, password="pw",
        use_tor=False,
        on_event=lambda kind, payload: events.append((kind, payload)),
    )
    return session, events


def bundle_of(identity: Identity) -> dict:
    return identity.public_bundle(ROOM).to_dict()


def test_valid_bundle_establishes_a_session():
    session, _ = make_session()
    session._handle_bundle(bundle_of(Identity.generate("bob")))

    assert session.ready
    assert session.member_names == ["bob"]
    assert session.safety_number_for("bob")


def test_multiple_peers_each_get_their_own_session():
    session, _ = make_session(user="alice")
    for name in ("bob", "carol", "dave"):
        session._handle_bundle(bundle_of(Identity.generate(name)))

    assert session.member_names == ["bob", "carol", "dave"]
    ratchets = [p.ratchet for p in session.peers.values()]
    assert len(set(id(r) for r in ratchets)) == 3, "peers must not share a ratchet"


def test_each_peer_has_a_distinct_safety_number():
    session, _ = make_session(user="alice")
    for name in ("bob", "carol"):
        session._handle_bundle(bundle_of(Identity.generate(name)))

    numbers = {session.safety_number_for(n) for n in session.member_names}
    assert len(numbers) == 2
    assert all(numbers)


def test_role_follows_username_order_not_a_prompt():
    """
    'mallory' sorts after 'alice' and before 'zoe', so alice initiates towards
    mallory and mallory initiates towards zoe -- with no negotiation.
    """
    alice, _ = make_session(user="alice")
    alice._handle_bundle(bundle_of(Identity.generate("mallory")))
    # The initiator has a sending chain straight away.
    assert alice.peers["mallory"].can_send is True

    zoe, _ = make_session(user="zoe")
    zoe._handle_bundle(bundle_of(Identity.generate("mallory")))
    # zoe sorts last, so she responds and has no sending chain yet.
    assert zoe.peers["mallory"].can_send is False


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


def test_changed_peer_identity_is_detected_even_with_a_live_session():
    """
    `_handle_bundle` used to return early whenever a ratchet already existed,
    so a peer's identity key could change without the check ever running --
    silently, in exactly the situation where an interception would be most
    valuable to an attacker.
    """
    bob = Identity.generate("bob")
    session, _ = make_session()
    session._handle_bundle(bundle_of(bob))
    assert session.ready

    new_bob = Identity.generate("bob")
    with pytest.raises(PeerIdentityChanged) as caught:
        session._handle_bundle(bundle_of(new_bob))

    assert caught.value.peer_user == "bob"
    assert caught.value.old_identity != caught.value.new_identity


def test_an_identity_change_for_one_peer_does_not_disturb_the_others():
    session, _ = make_session(user="alice")
    session._handle_bundle(bundle_of(Identity.generate("bob")))
    carol = Identity.generate("carol")
    session._handle_bundle(bundle_of(carol))

    carol_number = session.safety_number_for("carol")

    with pytest.raises(PeerIdentityChanged):
        session._handle_bundle(bundle_of(Identity.generate("bob")))

    assert session.safety_number_for("carol") == carol_number
    assert session.peers["carol"].ratchet is not None


def test_unchanged_identity_does_not_renegotiate_an_existing_session():
    """A reconnect re-sends the same bundle; it must not reset the ratchet."""
    bob = Identity.generate("bob")
    session, _ = make_session()
    session._handle_bundle(bundle_of(bob))

    ratchet = session.peers["bob"].ratchet
    session._handle_bundle(bundle_of(bob))      # same identity, fresh bundle

    assert session.peers["bob"].ratchet is ratchet, "existing ratchet was replaced"


def test_trusting_a_new_identity_clears_only_that_peers_session():
    session, _ = make_session(user="alice")
    session._handle_bundle(bundle_of(Identity.generate("carol")))
    bob = Identity.generate("bob")
    session._handle_bundle(bundle_of(bob))

    new_bob = Identity.generate("bob")
    try:
        session._handle_bundle(bundle_of(new_bob))
    except PeerIdentityChanged as e:
        session._identity_changes[e.peer_user] = e

    assert session.trust_new_identity("bob") is True

    recorded = storage.load_known_peer("alice", ROOM, "bob")
    assert recorded["identity"] == b64e(new_bob.identity_public_bytes())
    assert storage.load_state("alice", ROOM, "bob") is None, "stale state kept"

    # Carol is untouched.
    assert "carol" in session.peers
    assert storage.load_state("alice", ROOM, "carol") is not None


def test_trusting_an_unflagged_peer_does_nothing():
    session, _ = make_session()
    session._handle_bundle(bundle_of(Identity.generate("bob")))
    assert session.trust_new_identity("bob") is False


# ---- reconnecting ------------------------------------------------------


def _fire(session, event):
    session.sio.handlers["/"][event]()


def test_a_reconnect_signs_in_and_rejoins_the_room(monkeypatch):
    # socketio reconnects on its own after a dropped connection, but the
    # relay treats the new socket as a stranger. Without a fresh sign-in and
    # join, everything typed afterwards stayed queued for good.
    import threading
    session, events = make_session()
    rejoined = threading.Event()
    calls = []
    monkeypatch.setattr(session, "authenticate", lambda: calls.append("authenticate"))
    monkeypatch.setattr(session.sio, "emit", lambda name, data=None: (
        calls.append(name), rejoined.set() if name == "join" else None))

    session.join()
    calls.clear()
    rejoined.clear()
    _fire(session, "disconnect")
    assert session.joined is False
    _fire(session, "connect")

    assert rejoined.wait(5), "the session never rejoined after reconnecting"
    assert calls == ["authenticate", "join"]


def test_the_first_connect_does_not_rejoin(monkeypatch):
    session, _ = make_session()
    monkeypatch.setattr(session, "authenticate",
                        lambda: pytest.fail("signed in before being asked to"))
    _fire(session, "connect")


def test_leaving_stops_rejoining(monkeypatch):
    session, _ = make_session()
    monkeypatch.setattr(session.sio, "emit", lambda *a, **k: None)
    monkeypatch.setattr(session.sio, "disconnect", lambda *a, **k: None)
    session.join()
    session.close()
    monkeypatch.setattr(session, "authenticate",
                        lambda: pytest.fail("rejoined a room we had left"))
    _fire(session, "connect")
