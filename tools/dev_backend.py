"""
Development stand-in for the Spring Boot backend.

Implements the same /internal/** HTTP contract, in memory, so the client and
relay can be run and exercised without a JVM or a Postgres instance. This is
what the end-to-end tests run against.

NOT FOR REAL USE:
  * everything is lost when the process exits
  * no migrations, no constraints, no concurrency control
  * password verifiers are hashed with PBKDF2 rather than bcrypt (same shape --
    random per-user salt, constant-time compare -- but the real backend is the
    authority on how credentials are stored)

Run the real backend for anything beyond trying the client out.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
import sys
import threading

from flask import Flask, jsonify, request

TOKEN = os.environ.get("SPECTRE_INTERNAL_TOKEN", "").strip()
if not TOKEN:
    sys.exit("[fatal] SPECTRE_INTERNAL_TOKEN is not set (must match the relay).")

PORT = int(os.environ.get("SPECTRE_BACKEND_PORT", "8090"))

app = Flask(__name__)
lock = threading.Lock()

users = {}      # username -> {"id", "salt", "hash", "role"}
rooms = {}      # room -> {"participants": {user: last_seen}, "bundles": {user: bundle}}
messages = []   # [{"id", "room", "sender", "headerJson", "bodyJson"}]


# Mirrors the @Pattern on AuthRegisterRequest in the real backend. Without it a
# name that works locally would be rejected once the Spring service is running.
USERNAME_RE = re.compile(r"^[A-Za-z0-9._-]{1,100}$")


def hash_verifier(verifier: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", verifier.encode(), salt, 100_000)


@app.before_request
def require_token():
    if request.path.startswith("/internal/"):
        provided = request.headers.get("X-Internal-Token", "")
        if not hmac.compare_digest(provided, TOKEN):
            return jsonify({"error": "unauthorized"}), 401


def room_state(name):
    return rooms.setdefault(name, {"participants": {}, "bundles": {}})


@app.post("/internal/auth/register")
def register():
    body = request.get_json(silent=True) or {}
    username, verifier = body.get("username"), body.get("verifier")
    if not username or not verifier:
        return jsonify({"valid": False, "code": "INVALID_REQUEST",
                        "message": "username and verifier are required"})
    if not USERNAME_RE.match(username):
        return jsonify({"valid": False, "code": "INVALID_REQUEST",
                        "message": "username may contain letters, digits, dot, "
                                   "underscore and hyphen only"})

    with lock:
        if username in users:
            return jsonify({"valid": False, "code": "USER_ALREADY_EXISTS",
                            "message": "Username is already taken"})
        salt = secrets.token_bytes(16)
        users[username] = {
            "id": len(users) + 1,
            "salt": salt,
            "hash": hash_verifier(verifier, salt),
            "role": body.get("role") or "initiator",
        }
        record = users[username]

    return jsonify({"valid": True, "code": "OK", "userId": record["id"],
                    "role": record["role"], "message": "Registered"})


@app.post("/internal/auth/login")
def login():
    body = request.get_json(silent=True) or {}
    username, verifier = body.get("username"), body.get("verifier")
    if not username or not verifier:
        return jsonify({"valid": False, "code": "INVALID_REQUEST",
                        "message": "username and verifier are required"})

    with lock:
        record = users.get(username)

    if record is None:
        return jsonify({"valid": False, "code": "USER_NOT_FOUND",
                        "message": "No such user"})
    if not hmac.compare_digest(hash_verifier(verifier, record["salt"]), record["hash"]):
        return jsonify({"valid": False, "code": "BAD_CREDENTIALS",
                        "message": "Incorrect password"})

    return jsonify({"valid": True, "code": "OK", "userId": record["id"],
                    "role": record["role"], "message": "Login OK"})


@app.post("/internal/rooms/join")
def join_room():
    body = request.get_json(silent=True) or {}
    room, user = body.get("room"), body.get("user")
    with lock:
        state = room_state(room)
        if user not in state["participants"]:
            # A new participant starts from the current head, not from the
            # beginning of history, matching the real backend.
            highest = max((m["id"] for m in messages if m["room"] == room), default=None)
            state["participants"][user] = highest
        last_seen = state["participants"][user]
    return jsonify({"roomId": 1, "lastSeenMessageId": last_seen})


@app.post("/internal/rooms/<room>/bundles")
def save_bundle(room):
    body = request.get_json(silent=True) or {}
    with lock:
        room_state(room)["bundles"][body.get("user")] = body.get("bundle")
    return "", 201


@app.post("/internal/rooms/<room>/messages")
def save_message(room):
    body = request.get_json(silent=True) or {}
    with lock:
        record = {
            "id": len(messages) + 1,
            "room": room,
            "sender": body.get("user"),
            # Which member this copy is encrypted for. Without it every member
            # is handed every copy, and the ones they cannot decrypt look like
            # a brand new DH key -- which ratchets the session into oblivion.
            "recipient": body.get("recipient"),
            "headerJson": json.dumps(body.get("header")),
            "bodyJson": json.dumps(body.get("body")),
        }
        messages.append(record)
    return jsonify({"id": record["id"], "sender": record["sender"],
                    "recipient": record["recipient"],
                    "headerJson": record["headerJson"],
                    "bodyJson": record["bodyJson"]}), 201


@app.get("/internal/rooms/<room>/messages")
def list_messages(room):
    since = request.args.get("sinceId", type=int)
    recipient = request.args.get("recipient")
    with lock:
        out = [
            m for m in messages
            if m["room"] == room
            and (since is None or m["id"] > since)
            # A null recipient predates group support and goes to everyone.
            and (recipient is None or m.get("recipient") in (None, recipient))
        ]
    return jsonify(out)


@app.post("/internal/rooms/<room>/last-seen")
def update_last_seen(room):
    body = request.get_json(silent=True) or {}
    with lock:
        room_state(room)["participants"][body.get("user")] = body.get("lastSeenMessageId")
    return "", 200


if __name__ == "__main__":
    print(f"[dev backend] in-memory, listening on 127.0.0.1:{PORT}")
    print("[dev backend] data is discarded on exit; not for real use")
    app.run(host="127.0.0.1", port=PORT, threaded=True)
