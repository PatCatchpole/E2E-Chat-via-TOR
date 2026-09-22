"""
Relay authentication and routing.

Every check here was a live vulnerability in the original: `packet` had no
session check, no room membership check, and took the sender name from the
client payload, so any connected socket could inject a message into any room
as any user. Nothing exercised the relay at all, which left the two invariants
with the shortest path to a silent regression as the only untested ones.

The backend is stubbed. These are tests of the relay's own decisions, not of
the HTTP contract, which `tools/dev_backend.py` covers.
"""

from __future__ import annotations

import subprocess
import sys

import pytest

import app as relay


# ---- a stand-in backend ------------------------------------------------


class FakeBackend:
    """Records what the relay asked for and answers plausibly."""

    def __init__(self):
        self.calls = []
        self.next_message_id = 1
        self.reject_users = set()

    def post(self, path, body):
        self.calls.append((path, body))

        if path == "/internal/auth/login":
            if body["username"] in self.reject_users:
                return {"valid": False, "code": "BAD_CREDENTIALS"}
            return {"valid": True, "code": "OK", "userId": 1, "role": "initiator"}
        if path == "/internal/auth/register":
            return {"valid": True, "code": "OK"}
        if path == "/internal/rooms/join":
            return {"roomId": 1, "lastSeenMessageId": None}
        if path.endswith("/messages"):
            message_id = self.next_message_id
            self.next_message_id += 1
            return {"id": message_id}
        return {}

    def get(self, path, params=None):
        self.calls.append((path, params))
        return []


@pytest.fixture
def backend(monkeypatch):
    fake = FakeBackend()
    monkeypatch.setattr(relay, "backend_post", fake.post)
    monkeypatch.setattr(relay, "backend_get", fake.get)
    return fake


@pytest.fixture(autouse=True)
def clean_relay_state():
    """The relay keeps module-level state; tests must not inherit it."""
    relay.sessions.clear()
    relay.rooms.clear()
    relay._room_locks.clear()
    for limiter in (relay.auth_limit_by_user,
                    relay.auth_limit_by_socket,
                    relay.packet_limit):
        limiter._buckets.clear()
    yield
    relay.sessions.clear()
    relay.rooms.clear()


# ---- helpers -----------------------------------------------------------


def connect():
    return relay.socketio.test_client(relay.app)


def sign_in(client, user):
    client.emit("login", {"user": user, "verifier": "v"})
    result = events(client, "login_result")
    assert result and result[0]["success"], f"could not sign {user} in"


def join(client, user, room="spectre"):
    sign_in(client, user)
    client.emit("join", {"room": room, "bundle": {"user": user}})
    client.get_received()


def events(client, name):
    return [e["args"][0] for e in client.get_received() if e["name"] == name]


def packet(**overrides):
    body = {
        "type": "msg", "room": "spectre", "to": "bob",
        "hdr": {"dh": "AA", "n": 0, "pn": 0},
        "body": {"nonce": "AA", "ct": "AA"},
    }
    body.update(overrides)
    return body


# ---- the invariants ----------------------------------------------------


def test_sender_is_taken_from_the_session_not_the_payload(backend):
    alice, bob = connect(), connect()
    join(alice, "alice")
    join(bob, "bob")

    # alice claims to be carol; the relay must ignore it.
    alice.emit("packet", packet(user="carol"))

    delivered = events(bob, "packet")
    assert len(delivered) == 1
    assert delivered[0]["user"] == "alice", "the payload's sender name was trusted"


def test_packet_from_a_non_member_is_refused(backend):
    alice, bob = connect(), connect()
    join(bob, "bob")
    sign_in(alice, "alice")          # signed in, never joined the room

    alice.emit("packet", packet())

    assert events(bob, "packet") == [], "a non-member injected into the room"
    assert events(alice, "error_msg"), "the sender was not told why"


def test_packet_without_a_session_is_refused(backend):
    stranger, bob = connect(), connect()
    join(bob, "bob")

    stranger.emit("packet", packet())

    assert events(bob, "packet") == []
    assert events(stranger, "error_msg")


def test_join_without_a_session_is_refused(backend):
    stranger = connect()
    stranger.emit("join", {"room": "spectre", "bundle": {}})

    assert events(stranger, "error_msg")
    assert relay.rooms.get("spectre") in (None, {})


def test_a_departed_member_receives_no_more_packets(backend):
    alice, bob = connect(), connect()
    join(alice, "alice")
    join(bob, "bob")

    bob.emit("leave", {"room": "spectre"})
    bob.get_received()
    alice.emit("packet", packet())

    assert events(bob, "packet") == [], "a departed client kept receiving traffic"


def test_a_departed_member_leaves_the_broadcast_room(backend):
    """
    `leave` used to drop the bookkeeping entry without calling leave_room, so a
    departed client stayed subscribed and went on receiving everything the
    relay broadcast to the room.

    Packets are addressed to a single member and routed from the relay's own
    membership table, so they do not exercise this -- the room-wide broadcasts
    are what a lingering subscription leaks.
    """
    alice, bob, carol = connect(), connect(), connect()
    join(alice, "alice")
    join(bob, "bob")
    join(carol, "carol")

    bob.emit("leave", {"room": "spectre"})
    bob.get_received()

    carol.emit("leave", {"room": "spectre"})

    assert events(bob, "peer_left") == [], \
        "a departed client is still subscribed to the room"
    assert events(alice, "peer_left"), "a present member missed the departure"


def test_a_packet_reaches_only_its_addressee(backend):
    alice, bob, carol = connect(), connect(), connect()
    join(alice, "alice")
    join(bob, "bob")
    join(carol, "carol")

    alice.emit("packet", packet(to="bob"))

    assert len(events(bob, "packet")) == 1
    assert events(carol, "packet") == [], "a copy went to the wrong member"


def test_a_second_session_under_one_name_is_refused(backend):
    first, second = connect(), connect()
    join(first, "alice")
    sign_in(second, "alice")
    second.emit("join", {"room": "spectre", "bundle": {}})

    assert events(second, "error_msg")


def test_room_capacity_is_enforced(backend, monkeypatch):
    monkeypatch.setattr(relay, "ROOM_CAPACITY", 2)
    a, b, c = connect(), connect(), connect()
    join(a, "alice")
    join(b, "bob")

    sign_in(c, "carol")
    c.emit("join", {"room": "spectre", "bundle": {}})

    assert events(c, "error_msg")


def test_an_oversized_packet_is_refused(backend):
    alice, bob = connect(), connect()
    join(alice, "alice")
    join(bob, "bob")

    alice.emit("packet", packet(body={"nonce": "AA", "ct": "A" * (relay.MAX_PACKET_BYTES + 1)}))

    assert events(bob, "packet") == []
    assert events(alice, "error_msg")


def test_cors_is_empty_unless_configured():
    assert relay.CORS_ORIGINS == [], "a default CORS origin would let any page drive the relay"


def test_the_relay_refuses_to_start_without_a_token():
    result = subprocess.run(
        [sys.executable, "server/app.py"],
        capture_output=True, text=True, timeout=30,
        env={"PATH": "/usr/bin:/bin", "SPECTRE_INTERNAL_TOKEN": ""},
    )
    assert result.returncode != 0
    assert "SPECTRE_INTERNAL_TOKEN" in (result.stdout + result.stderr)


# ---- rate limiting -----------------------------------------------------


def test_login_attempts_are_rate_limited(backend):
    backend.reject_users.add("alice")
    client = connect()

    outcomes = []
    for _ in range(relay.AUTH_ATTEMPTS_PER_USER + 5):
        client.emit("login", {"user": "alice", "verifier": "guess"})
        outcomes.extend(events(client, "login_result"))

    codes = [o["code"] for o in outcomes]
    assert "RATE_LIMITED" in codes, "verifier guessing was unmetered"
    attempts = [c for c, _ in backend.calls if c == "/internal/auth/login"]
    assert len(attempts) <= relay.AUTH_ATTEMPTS_PER_USER, \
        "rate-limited attempts still reached the backend"


def test_a_correct_password_does_not_leave_the_account_locked(backend):
    client = connect()
    for _ in range(relay.AUTH_ATTEMPTS_PER_USER - 1):
        client.emit("login", {"user": "alice", "verifier": "v"})
        client.get_received()

    # A success refills the user's bucket, so the next sign-in is not refused.
    later = connect()
    sign_in(later, "alice")


def test_packet_flooding_is_rate_limited(backend):
    alice, bob = connect(), connect()
    join(alice, "alice")
    join(bob, "bob")

    for _ in range(relay.PACKETS_PER_SOCKET + 20):
        alice.emit("packet", packet())

    assert len(events(bob, "packet")) <= relay.PACKETS_PER_SOCKET
    assert events(alice, "error_msg"), "the flood was never refused"
