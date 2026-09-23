"""
Spectre relay.

The relay routes ciphertext between two peers in a room and persists it via the
backend. It never holds a session key and never sees plaintext.

Security changes from the original:

  * `packet` had no authentication at all. There was no session check, no room
    membership check, and the sender name was taken from the client payload, so
    any connected socket could inject messages into any room as any user. The
    sender is now taken from the server-side session and membership is required.
  * `cors_allowed_origins` was "*", so any web page the user visited could
    drive the relay. It is now opt-in via configuration and empty by default.
  * The internal token was a literal in the source, and every request logged
    both the token and the full ciphertext. Configuration comes from the
    environment and message contents are never logged.
  * `leave` removed the bookkeeping entry but never called `leave_room`, so a
    departed client kept receiving everything in the room.
"""

from __future__ import annotations

import json
import logging
import os
import sys
import threading
import time

import requests
from flask import Flask, request
from flask_socketio import SocketIO, emit, join_room, leave_room

# ============================================================
# Configuration
# ============================================================


def _required_env(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        sys.exit(
            f"[fatal] {name} is not set.\n"
            f"        Generate one with:  python -c \"import secrets; print(secrets.token_urlsafe(32))\"\n"
            f"        and set the same value here and for the backend."
        )
    return value


BACKEND_BASE_URL = os.environ.get("SPECTRE_BACKEND_URL", "http://127.0.0.1:8090")
INTERNAL_TOKEN = _required_env("SPECTRE_INTERNAL_TOKEN")

RELAY_HOST = os.environ.get("SPECTRE_RELAY_HOST", "127.0.0.1")
RELAY_PORT = int(os.environ.get("SPECTRE_RELAY_PORT", "5000"))

# Empty by default: the CLI client is not a browser and sends no Origin, so it
# is unaffected. Set explicitly only if you build a web client.
CORS_ORIGINS = [o for o in os.environ.get("SPECTRE_CORS_ORIGINS", "").split(",") if o]

# A room is a mesh of pairwise sessions, so traffic grows with the square of
# the member count: each message is encrypted and relayed once per recipient.
# The cap keeps that from getting out of hand rather than being a protocol
# limit.
ROOM_CAPACITY = int(os.environ.get("SPECTRE_ROOM_CAPACITY", "8"))

# Generous for a text message, small enough that a peer cannot exhaust the
# database with one packet.
MAX_PACKET_BYTES = 64 * 1024

BACKEND_TIMEOUT = 5

# Credential guessing was unmetered: the relay forwarded every login straight
# to the backend, so an attacker could grind verifiers as fast as the network
# allowed, and each attempt costs the backend a bcrypt(12).
#
# The buckets are keyed by username and by socket, never by IP. Behind a Tor
# hidden service every connection arrives from 127.0.0.1, so an IP bucket
# would put every user in the world in one bucket and let one attacker lock
# the room out for everybody.
AUTH_ATTEMPTS_PER_USER = int(os.environ.get("SPECTRE_AUTH_RATE", "10"))
AUTH_ATTEMPTS_PER_SOCKET = int(os.environ.get("SPECTRE_AUTH_RATE_SOCKET", "20"))
AUTH_WINDOW_SECONDS = 300

# A mesh room sends one packet per recipient, so a single message from a
# member of a full room is already 7 packets. This is a flood ceiling, not a
# pacing mechanism.
PACKETS_PER_SOCKET = int(os.environ.get("SPECTRE_PACKET_RATE", "240"))
PACKET_WINDOW_SECONDS = 10

logging.basicConfig(
    level=os.environ.get("SPECTRE_LOG_LEVEL", "INFO"),
    format="%(asctime)s %(levelname)-7s %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("spectre.relay")

app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins=CORS_ORIGINS or [])

# sid -> {"user": str, "userId": int, "role": str, "room": str | None}
sessions = {}

# room -> {sid -> {"user": str, "role": str, "bundle": dict}}
rooms = {}

# One lock per room, held across "persist then broadcast". Each socket event is
# handled on its own thread, so without this two messages sent in quick
# succession can be relayed in whichever order their backend write finishes,
# and arrive reordered. Ordering is a property the transport should preserve.
_room_locks = {}
_room_locks_guard = threading.Lock()


def room_lock(room: str) -> threading.Lock:
    with _room_locks_guard:
        return _room_locks.setdefault(room, threading.Lock())


class RateLimiter:
    """
    Token bucket per key, with a ceiling on how many keys are tracked.

    The bound matters as much as the limiting does: the keys are attacker-
    chosen (a username, a socket id), so an unbounded table would just move
    the exhaustion from the backend into the relay. The least recently
    refilled bucket is evicted, which is the one closest to full anyway.
    """

    def __init__(self, limit: int, window: float, max_keys: int = 4096):
        self.limit = float(limit)
        self.window = float(window)
        self.max_keys = max_keys
        self._buckets = {}
        self._guard = threading.Lock()

    def allow(self, key) -> bool:
        if key is None:
            return True
        now = time.monotonic()
        with self._guard:
            tokens, last = self._buckets.get(key, (self.limit, now))
            tokens = min(self.limit, tokens + (now - last) * self.limit / self.window)
            if tokens < 1.0:
                self._buckets[key] = (tokens, now)
                return False
            self._buckets[key] = (tokens - 1.0, now)
            if len(self._buckets) > self.max_keys:
                oldest = min(self._buckets, key=lambda k: self._buckets[k][1])
                self._buckets.pop(oldest, None)
            return True

    def forget(self, key) -> None:
        with self._guard:
            self._buckets.pop(key, None)


auth_limit_by_user = RateLimiter(AUTH_ATTEMPTS_PER_USER, AUTH_WINDOW_SECONDS)
auth_limit_by_socket = RateLimiter(AUTH_ATTEMPTS_PER_SOCKET, AUTH_WINDOW_SECONDS)
packet_limit = RateLimiter(PACKETS_PER_SOCKET, PACKET_WINDOW_SECONDS)


def _auth_allowed(user: str, event: str) -> bool:
    """
    True if this attempt may go to the backend.

    Both buckets are consumed on every attempt: the per-user one stops a
    single account being ground down from many sockets, the per-socket one
    stops a single socket enumerating many accounts.
    """
    ok_user = auth_limit_by_user.allow(user)
    ok_socket = auth_limit_by_socket.allow(request.sid)
    if ok_user and ok_socket:
        return True
    # The username is logged; the verifier never is.
    log.warning("rate limited %s for %r", event, user)
    return False


# ============================================================
# Backend calls
# ============================================================


class BackendError(Exception):
    pass


def _backend(method: str, path: str, **kwargs):
    url = f"{BACKEND_BASE_URL}{path}"
    headers = {"X-Internal-Token": INTERNAL_TOKEN}

    # Path and method only. The token and the request body (which carries
    # ciphertext) are deliberately absent from the log.
    log.debug("backend %s %s", method, path)

    try:
        resp = requests.request(
            method, url, headers=headers, timeout=BACKEND_TIMEOUT, **kwargs
        )
    except requests.RequestException as e:
        raise BackendError(f"backend unreachable: {e.__class__.__name__}") from e

    if resp.status_code == 401:
        raise BackendError(
            "backend rejected the internal token; SPECTRE_INTERNAL_TOKEN must "
            "match on the relay and the backend"
        )
    if resp.status_code >= 400:
        raise BackendError(f"backend returned {resp.status_code} for {path}")

    if resp.content:
        try:
            return resp.json()
        except ValueError as e:
            raise BackendError("backend returned a non-JSON body") from e
    return None


def backend_post(path: str, json_body: dict):
    return _backend("POST", path, json=json_body)


def backend_get(path: str, params: dict = None):
    return _backend("GET", path, params=params or {})


# ============================================================
# Session helpers
# ============================================================


def current_session():
    """The authenticated session for this socket, or None."""
    return sessions.get(request.sid)


def require_session():
    """
    Returns the session or None, emitting an error to the caller if absent.
    Every event that touches a room goes through this.
    """
    session = current_session()
    if session is None:
        emit("error_msg", {"message": "Not authenticated. Log in first."})
        return None
    return session


def room_members(room: str) -> dict:
    return rooms.setdefault(room, {})


# ============================================================
# HTTP
# ============================================================


@app.route("/")
def index():
    return "Spectre relay is running"


@app.route("/healthz")
def healthz():
    return {"status": "ok", "rooms": len(rooms), "sessions": len(sessions)}


# ============================================================
# Connection lifecycle
# ============================================================


@socketio.on("connect")
def handle_connect():
    log.info("socket connected: %s", request.sid)


@socketio.on("disconnect")
def handle_disconnect():
    sid = request.sid
    session = sessions.pop(sid, None)
    user = session["user"] if session else None

    for room, members in list(rooms.items()):
        if sid in members:
            user = user or members[sid]["user"]
            del members[sid]
            leave_room(room, sid=sid)
            socketio.emit("peer_left", {"user": user}, room=room)
            log.info("%s left room %s (disconnect)", user, room)
        if not members:
            rooms.pop(room, None)

    auth_limit_by_socket.forget(sid)
    packet_limit.forget(sid)
    log.info("socket disconnected: %s", sid)


# ============================================================
# Auth
# ============================================================


@socketio.on("register")
def handle_register(data):
    user = (data or {}).get("user")
    verifier = (data or {}).get("verifier")
    role = (data or {}).get("role")

    if not user or not verifier:
        emit("register_result", {"success": False, "code": "INVALID_REQUEST",
                                 "message": "user and verifier are required"})
        return

    if not _auth_allowed(user, "register"):
        emit("register_result", {"success": False, "code": "RATE_LIMITED",
                                 "message": "Too many attempts. Wait a few minutes."})
        return

    try:
        resp = backend_post("/internal/auth/register", {
            "username": user,
            "verifier": verifier,
            "role": role,
        }) or {}
    except BackendError as e:
        log.warning("register failed for %s: %s", user, e)
        emit("register_result", {"success": False, "code": "BACKEND_ERROR",
                                 "message": str(e)})
        return

    emit("register_result", {
        "success": bool(resp.get("valid")),
        "code": resp.get("code", "UNKNOWN"),
        "message": resp.get("message", ""),
    })


@socketio.on("login")
def handle_login(data):
    user = (data or {}).get("user")
    verifier = (data or {}).get("verifier")
    role = (data or {}).get("role")

    if not user or not verifier:
        emit("login_result", {"success": False, "code": "INVALID_REQUEST",
                              "message": "user and verifier are required"})
        return

    if not _auth_allowed(user, "login"):
        emit("login_result", {"success": False, "code": "RATE_LIMITED",
                              "message": "Too many attempts. Wait a few minutes."})
        return

    try:
        resp = backend_post("/internal/auth/login", {
            "username": user,
            "verifier": verifier,
            "role": role,
        }) or {}
    except BackendError as e:
        log.warning("login failed for %s: %s", user, e)
        emit("login_result", {"success": False, "code": "BACKEND_ERROR",
                              "message": str(e)})
        return

    if not resp.get("valid"):
        emit("login_result", {
            "success": False,
            "code": resp.get("code", "BAD_CREDENTIALS"),
            "message": resp.get("message", "Login failed"),
        })
        return

    sessions[request.sid] = {
        "user": user,
        "userId": resp.get("userId"),
        "role": resp.get("role"),
        "room": None,
    }
    # A correct password is not an attack, so it does not leave the account
    # half-locked for whoever signs in next.
    auth_limit_by_user.forget(user)
    log.info("login ok: %s", user)
    emit("login_result", {"success": True, "code": "OK", "message": "OK"})


# ============================================================
# Rooms
# ============================================================


@socketio.on("join")
def handle_join(data):
    session = require_session()
    if session is None:
        return

    data = data or {}
    room = data.get("room")
    bundle = data.get("bundle")
    user = session["user"]  # from the session, never from the payload

    if not room or not isinstance(bundle, dict):
        emit("error_msg", {"message": "room and bundle are required"})
        return

    members = room_members(room)

    # A connection that dropped -- routine over Tor -- stays listed until its
    # ping times out, which can be most of a minute. The client reconnects
    # and signs in again well before that, and used to be refused here as
    # "already connected", leaving it outside its own room with every
    # message it sent queued. Having just proved the password, the new
    # connection takes the seat over instead; there is still only ever one
    # socket per name in a room.
    others = {sid: info for sid, info in members.items() if sid != request.sid}
    stale = [sid for sid, info in others.items() if info["user"] == user]
    for sid in stale:
        del others[sid]

    if len(others) >= ROOM_CAPACITY:
        emit("error_msg", {
            "message": f"Room '{room}' already has {ROOM_CAPACITY} participants."
        })
        log.info("rejected %s from full room %s", user, room)
        return

    try:
        join_resp = backend_post("/internal/rooms/join", {
            "room": room, "user": user,
        }) or {}
    except BackendError as e:
        log.warning("join failed for %s in %s: %s", user, room, e)
        emit("error_msg", {"message": f"Could not join room: {e}"})
        return

    for sid in stale:
        # Out of the room and signed out, so the old socket can neither send
        # nor receive if it turns out to be alive after all. Its eventual
        # disconnect finds nothing left to clean up and announces nothing.
        members.pop(sid, None)
        leave_room(room, sid=sid)
        sessions.pop(sid, None)
        socketio.emit("error_msg", {
            "message": "Signed in again from another connection; this one was closed."
        }, room=sid)
        log.info("%s rejoined %s from a new connection", user, room)

    join_room(room)
    session["room"] = room
    members[request.sid] = {"user": user, "role": session.get("role"), "bundle": bundle}

    try:
        backend_post(f"/internal/rooms/{room}/bundles", {"user": user, "bundle": bundle})
    except BackendError as e:
        log.warning("could not persist bundle for %s: %s", user, e)

    log.info("%s joined room %s (%d present)", user, room, len(members))
    emit("joined", {
        "room": room,
        "user": user,
        "members": sorted(info["user"] for info in members.values()),
    })

    # Swap bundles with every member already here, so the joiner ends up with a
    # pairwise session against each of them. The relay does not inspect or
    # validate bundles; the clients verify each other's signatures.
    for peer_sid, peer in others.items():
        socketio.emit("bundle", {"from": user, "bundle": bundle}, room=peer_sid)
        socketio.emit("bundle", {"from": peer["user"], "bundle": peer["bundle"]},
                      room=request.sid)
        socketio.emit("peer_joined", {"user": user}, room=peer_sid)
        log.info("exchanged bundles between %s and %s", user, peer["user"])

    _replay_backlog(room, user, join_resp.get("lastSeenMessageId"))


def _replay_backlog(room: str, user: str, last_seen) -> None:
    """Deliver messages this user has not acknowledged yet."""
    try:
        params = {"recipient": user}
        if last_seen is not None:
            params["sinceId"] = last_seen
        messages = backend_get(f"/internal/rooms/{room}/messages", params=params) or []
    except BackendError as e:
        log.warning("could not fetch backlog for %s in %s: %s", user, room, e)
        return

    delivered = 0
    for message in messages:
        if message.get("sender") == user:
            continue
        # Each copy is encrypted for exactly one recipient; delivering somebody
        # else's copy would just fail to decrypt.
        recipient = message.get("recipient")
        if recipient is not None and recipient != user:
            continue
        try:
            header = json.loads(message["headerJson"])
            body = json.loads(message["bodyJson"])
        except (KeyError, ValueError):
            log.warning("skipping malformed stored message %s", message.get("id"))
            continue

        socketio.emit("packet", {
            "type": "msg",
            "room": room,
            "user": message.get("sender"),
            "hdr": header,
            "body": body,
            "id": message["id"],
            "to": message.get("recipient"),
        }, room=request.sid)
        delivered += 1

    if delivered:
        log.info("replayed %d backlog messages to %s", delivered, user)


@socketio.on("leave")
def handle_leave(data):
    session = current_session()
    if session is None:
        return

    room = (data or {}).get("room") or session.get("room")
    if not room:
        return

    members = rooms.get(room, {})
    if request.sid in members:
        del members[request.sid]

    # The original omitted this, so a "departed" client kept receiving
    # everything broadcast to the room.
    leave_room(room)
    session["room"] = None

    socketio.emit("peer_left", {"user": session["user"]}, room=room)
    log.info("%s left room %s", session["user"], room)

    if not members:
        rooms.pop(room, None)
        with _room_locks_guard:
            _room_locks.pop(room, None)


# ============================================================
# Messages
# ============================================================


@socketio.on("packet")
def handle_packet(data):
    session = require_session()
    if session is None:
        return

    data = data or {}
    if data.get("type") != "msg":
        return

    if not packet_limit.allow(request.sid):
        emit("error_msg", {"message": "Sending too fast."})
        return

    room = data.get("room")
    user = session["user"]  # authoritative; the payload's own "user" is ignored

    if not room or request.sid not in rooms.get(room, {}):
        emit("error_msg", {"message": "You are not a participant of that room."})
        log.warning("rejected packet from %s for room %r (not a member)", user, room)
        return

    header = data.get("hdr")
    body = data.get("body")
    if not isinstance(header, dict) or not isinstance(body, dict):
        emit("error_msg", {"message": "Malformed packet."})
        return

    # Each packet is encrypted for one member, so it is addressed to one
    # member. Delivering it to the whole room would leak nothing (they could
    # not decrypt it) but would waste bandwidth and confuse the receivers.
    recipient = data.get("to")
    if not isinstance(recipient, str) or not recipient:
        emit("error_msg", {"message": "Packet has no recipient."})
        return

    # A recipient who is offline is normal, not an error: their copy is
    # persisted and delivered from the backlog when they next join. So the
    # recipient is not validated against the connected members here -- the
    # sender's own membership, checked above, is what matters.
    members = rooms.get(room, {})
    recipient_sids = [sid for sid, info in members.items() if info["user"] == recipient]

    size = len(json.dumps({"hdr": header, "body": body}))
    if size > MAX_PACKET_BYTES:
        emit("error_msg", {"message": f"Packet too large ({size} bytes)."})
        return

    with room_lock(room):
        message_id = None
        try:
            saved = backend_post(f"/internal/rooms/{room}/messages", {
                "user": user, "recipient": recipient, "header": header, "body": body,
            }) or {}
            message_id = saved.get("id")
        except BackendError as e:
            # Deliver anyway: a live peer should still get the message even if
            # persistence is down. It just will not be in the backlog.
            log.warning("could not persist message from %s: %s", user, e)

        outgoing = {
            "type": "msg",
            "room": room,
            "user": user,
            "to": recipient,
            "hdr": header,
            "body": body,
        }
        if message_id is not None:
            outgoing["id"] = message_id

        for sid in recipient_sids:
            socketio.emit("packet", outgoing, room=sid)
        log.debug("relayed message %s in %s to %s", message_id, room, recipient)


@socketio.on("seen")
def handle_seen(data):
    session = require_session()
    if session is None:
        return

    data = data or {}
    room = data.get("room")
    last_seen_id = data.get("lastSeenMessageId")

    if not room or not isinstance(last_seen_id, int):
        return
    if request.sid not in rooms.get(room, {}):
        return

    try:
        backend_post(f"/internal/rooms/{room}/last-seen", {
            "user": session["user"], "lastSeenMessageId": last_seen_id,
        })
    except BackendError as e:
        log.warning("could not record last-seen for %s: %s", session["user"], e)


# ============================================================
# Entry point
# ============================================================


def main():
    # flask-socketio refuses to start the Werkzeug dev server when stdin is not
    # a TTY, which is exactly how this runs behind a Tor hidden service
    # (systemd, docker, nohup). Opting in explicitly keeps that deployment
    # working without silently pretending Werkzeug is a production server.
    allow_unsafe = os.environ.get("SPECTRE_ALLOW_DEV_SERVER", "").lower() in ("1", "true", "yes")

    log.info("relay listening on %s:%s", RELAY_HOST, RELAY_PORT)
    log.info("backend at %s", BACKEND_BASE_URL)
    if CORS_ORIGINS:
        log.info("CORS origins allowed: %s", ", ".join(CORS_ORIGINS))
    if not sys.stdin or not sys.stdin.isatty():
        if allow_unsafe:
            log.warning(
                "running the Werkzeug development server non-interactively. "
                "Put a real WSGI server in front of this for anything beyond testing."
            )
        else:
            sys.exit(
                "[fatal] Refusing to start non-interactively without "
                "SPECTRE_ALLOW_DEV_SERVER=1.\n"
                "        This is the Werkzeug development server. Set that "
                "variable to run it anyway."
            )

    socketio.run(
        app,
        host=RELAY_HOST,
        port=RELAY_PORT,
        debug=False,
        allow_unsafe_werkzeug=allow_unsafe,
    )


if __name__ == "__main__":
    main()
