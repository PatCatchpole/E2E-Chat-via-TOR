"""
Local persistence for identity, ratchet state and known peer keys.

Everything written here is key material. The original wrote all of it with the
default umask, leaving private keys and live chain keys world-readable, and
kept no record of a peer's identity key between sessions -- so a relay that
swapped a peer's keys after the first conversation went unnoticed.

Files are created 0600 and directories 0700, and writes are atomic so an
interrupted save cannot leave a truncated state file behind.
"""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path

# Windows does not implement POSIX mode bits: os.chmod only toggles the
# read-only flag, and os.stat reports 0o666 for every ordinary file. Confidence
# there comes from the ACL on the user profile directory instead, so the
# permission assertions below are POSIX-only rather than silently misleading.
POSIX_PERMISSIONS = os.name == "posix"

SPECTRE_DIR = Path.home() / ".spectre"
STATE_DIR = SPECTRE_DIR / "state"
PEERS_DIR = SPECTRE_DIR / "peers"


def _safe_name(value: str) -> str:
    """Keep user- and room-supplied names from escaping the storage directory."""
    cleaned = "".join(c if c.isalnum() or c in "-_." else "_" for c in value)
    return cleaned.strip("._") or "unnamed"


def ensure_dirs() -> None:
    for directory in (SPECTRE_DIR, STATE_DIR, PEERS_DIR):
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        # mkdir's mode is subject to umask, and the directory may predate this
        # code, so set the permissions explicitly.
        if POSIX_PERMISSIONS:
            try:
                os.chmod(directory, 0o700)
            except OSError:
                pass


def _write_private(path: Path, payload: bytes) -> None:
    """Atomic 0600 write: create private, fill, then rename into place."""
    ensure_dirs()
    tmp = path.with_suffix(path.suffix + f".tmp.{os.getpid()}")
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    fd = os.open(tmp, flags, stat.S_IRUSR | stat.S_IWUSR)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
    except Exception:
        tmp.unlink(missing_ok=True)
        raise
    os.replace(tmp, path)
    if POSIX_PERMISSIONS:
        os.chmod(path, 0o600)


def _read_json(path: Path):
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def check_permissions(path: Path) -> bool:
    """
    True if the file is not readable by group or others.

    Always true on Windows, where the mode bits carry no such meaning; the
    file is protected by the profile directory's ACL, not by its mode.
    """
    if not POSIX_PERMISSIONS:
        return True
    try:
        mode = path.stat().st_mode
    except OSError:
        return True
    return not (mode & (stat.S_IRWXG | stat.S_IRWXO))


# ---- identity ---------------------------------------------------------


def identity_path(user: str) -> Path:
    return SPECTRE_DIR / f"{_safe_name(user)}.identity"


def load_identity_seed(user: str):
    path = identity_path(user)
    if not path.exists():
        return None
    return path.read_bytes()


def save_identity_seed(user: str, seed: bytes) -> None:
    _write_private(identity_path(user), seed)


# ---- ratchet state ----------------------------------------------------


def state_path(user: str, room: str, peer: str) -> Path:
    # One ratchet per (room, peer): a group is a mesh of pairwise sessions, so
    # state cannot be keyed by room alone.
    return STATE_DIR / f"{_safe_name(user)}__{_safe_name(room)}__{_safe_name(peer)}.json"


def load_state(user: str, room: str, peer: str):
    return _read_json(state_path(user, room, peer))


def save_state(user: str, room: str, peer: str, snapshot: dict) -> None:
    # Room, user and peer are recorded inside the file as well as in its name,
    # because _safe_name is lossy -- the originals cannot be recovered from the
    # filename, and the room list needs them.
    payload = dict(snapshot)
    payload.setdefault("room", room)
    payload.setdefault("user", user)
    payload.setdefault("peer", peer)
    _write_private(state_path(user, room, peer), json.dumps(payload).encode("utf-8"))


def clear_state(user: str, room: str, peer: str = None) -> None:
    """Drop one peer's session, or every session in the room when peer is None."""
    if peer is not None:
        state_path(user, room, peer).unlink(missing_ok=True)
        peer_path(user, room, peer).unlink(missing_ok=True)
        return

    prefix = f"{_safe_name(user)}__{_safe_name(room)}__"
    for directory in (STATE_DIR, PEERS_DIR):
        for path in directory.glob(f"{prefix}*.json"):
            path.unlink(missing_ok=True)


# ---- known peer identities (trust on first use) ------------------------


def peer_path(user: str, room: str, peer: str) -> Path:
    return PEERS_DIR / f"{_safe_name(user)}__{_safe_name(room)}__{_safe_name(peer)}.json"


def load_known_peer(user: str, room: str, peer: str):
    """The identity recorded for this peer in this room, or None on first contact."""
    return _read_json(peer_path(user, room, peer))


def save_known_peer(user: str, room: str, peer_user: str, identity_b64: str) -> None:
    _write_private(
        peer_path(user, room, peer_user),
        json.dumps({
            "user": peer_user,
            "identity": identity_b64,
            "room": room,
            "owner": user,
        }).encode("utf-8"),
    )


def progress_path(user: str, room: str) -> Path:
    return STATE_DIR / f"{_safe_name(user)}__{_safe_name(room)}.progress.json"


def load_progress(user: str, room: str) -> dict:
    """Backend delivery progress for a room, shared across all its peers."""
    return _read_json(progress_path(user, room)) or {}


def save_progress(user: str, room: str, progress: dict) -> None:
    payload = dict(progress)
    payload.setdefault("room", room)
    payload.setdefault("user", user)
    _write_private(progress_path(user, room), json.dumps(payload).encode("utf-8"))


def list_peers(user: str, room: str) -> list:
    """Peers this user has an established session with in this room."""
    prefix = f"{_safe_name(user)}__{_safe_name(room)}__"
    peers = []
    for path in PEERS_DIR.glob(f"{prefix}*.json"):
        data = _read_json(path)
        if isinstance(data, dict) and data.get("user"):
            peers.append(data["user"])
    return sorted(set(peers))


def list_rooms(user: str) -> list:
    """
    Rooms this user has an established session for, newest first.

    Derived from local state, so it needs no backend support and reveals
    nothing to the relay. Returns dicts of {room, peers, peer, last_used},
    where `peers` is every peer seen in that room and `peer` is set only when
    there is exactly one.
    """
    ensure_dirs()
    prefix = _safe_name(user) + "__"
    found = {}

    for directory in (PEERS_DIR, STATE_DIR):
        for path in directory.glob(f"{prefix}*.json"):
            data = _read_json(path)
            if not isinstance(data, dict):
                continue
            room = data.get("room")
            if not room:
                # Written before the room was recorded inside the file; recover
                # what we can from the filename.
                stem = path.name[len(prefix):]
                room = stem[:-5] if stem.endswith(".json") else stem
            if not room:
                continue

            entry = found.setdefault(
                room, {"room": room, "peers": set(), "last_used": 0.0}
            )
            if data.get("user") and directory is PEERS_DIR:
                entry["peers"].add(data["user"])
            try:
                entry["last_used"] = max(entry["last_used"], path.stat().st_mtime)
            except OSError:
                pass

    rooms = []
    for entry in found.values():
        entry["peers"] = sorted(entry["peers"])
        # Kept for callers that only care about the two-party case.
        entry["peer"] = entry["peers"][0] if len(entry["peers"]) == 1 else None
        rooms.append(entry)
    return sorted(rooms, key=lambda e: e["last_used"], reverse=True)
