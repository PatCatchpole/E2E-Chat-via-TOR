"""
Inbound packet handling around the backend's message ids.

The ids are not a dependable global sequence -- the in-memory backend restarts
them at 1 on every launch -- so a watermark persisted from an earlier run can
sit above ids that are genuinely new. Gating delivery on it silently discarded
real messages: no error, no log, the text simply never appeared.
"""

from __future__ import annotations

import pytest

import storage
from crypto.framing import frame_prime, frame_text
from crypto.keys import Identity
from session import SpectreSession

ROOM = "testroom"


@pytest.fixture(autouse=True)
def isolated_storage(tmp_path, monkeypatch):
    monkeypatch.setattr(storage, "SPECTRE_DIR", tmp_path)
    monkeypatch.setattr(storage, "STATE_DIR", tmp_path / "state")
    monkeypatch.setattr(storage, "PEERS_DIR", tmp_path / "peers")
    storage.ensure_dirs()
    yield


def make_session(user):
    events = []
    session = SpectreSession(
        url="http://127.0.0.1:1", room=ROOM, user=user, password="pw",
        use_tor=False, on_event=lambda kind, payload: events.append((kind, payload)),
    )
    session.sio.emit = lambda *a, **k: None      # never touch the network
    return session, events


def linked_pair():
    """alice and bob with a live pairwise ratchet each, primed both ways."""
    alice, _ = make_session("alice")
    bob, bob_events = make_session("bob")

    alice._handle_bundle(bob._identity.public_bundle(ROOM).to_dict())
    bob._handle_bundle(alice._identity.public_bundle(ROOM).to_dict())

    # alice initiates (lower username), so she primes bob's sending chain.
    bob._handle_packet({"type": "msg", "user": "alice",
                        **alice.peers["bob"].ratchet.encrypt(frame_prime())})
    bob_events.clear()
    return alice, bob, bob_events


def texts(events):
    return [p["text"] for kind, p in events if kind == "message"]


def test_a_new_message_below_a_stale_watermark_is_still_delivered():
    alice, bob, events = linked_pair()
    packet = {"type": "msg", "user": "alice", "id": 3,
              **alice.peers["bob"].ratchet.encrypt(frame_text("hello"))}

    # A previous run in this room reached id 5; the backend then restarted and
    # began counting from 1 again.
    bob._last_message_id = 5
    bob._handle_packet(packet)

    assert texts(events) == ["hello"], "a genuinely new message was dropped"


def test_a_replayed_message_is_not_delivered_twice():
    alice, bob, events = linked_pair()
    packet = {"type": "msg", "user": "alice", "id": 1,
              **alice.peers["bob"].ratchet.encrypt(frame_text("once"))}

    bob._handle_packet(packet)
    bob._handle_packet(packet)

    assert texts(events) == ["once"]


def test_a_replay_below_the_watermark_is_rejected_quietly():
    alice, bob, events = linked_pair()
    packet = {"type": "msg", "user": "alice", "id": 1,
              **alice.peers["bob"].ratchet.encrypt(frame_text("once"))}

    bob._handle_packet(packet)
    bob._last_message_id = 10       # the backlog is being replayed to us
    events.clear()
    bob._handle_packet(packet)

    assert texts(events) == []
    assert [k for k, _ in events if k == "error"] == [], \
        "a known duplicate should not be reported as an error"


def test_an_undecryptable_packet_above_the_watermark_is_still_reported():
    alice, bob, events = linked_pair()
    packet = alice.peers["bob"].ratchet.encrypt(frame_text("tampered"))
    packet["body"]["ct"] = "AAAA" + packet["body"]["ct"][4:]

    bob._handle_packet({"type": "msg", "user": "alice", "id": 99, **packet})

    assert [k for k, _ in events if k == "error"], "a forged packet went unreported"


def test_packets_from_an_unknown_sender_are_queued_within_bounds():
    """
    The relay chooses what to deliver and what name to put on it, so an
    unbounded hold queue is a remote memory exhaustion.
    """
    from session import MAX_PENDING_PEERS, MAX_PENDING_PER_PEER

    bob, _ = make_session("bob")

    for i in range(MAX_PENDING_PER_PEER + 50):
        bob._handle_packet({"type": "msg", "user": "stranger", "id": i,
                            "hdr": {}, "body": {}})

    assert len(bob._pending["stranger"]) == MAX_PENDING_PER_PEER

    for n in range(MAX_PENDING_PEERS + 10):
        bob._handle_packet({"type": "msg", "user": f"peer{n}", "id": n,
                            "hdr": {}, "body": {}})

    assert len(bob._pending) <= MAX_PENDING_PEERS
