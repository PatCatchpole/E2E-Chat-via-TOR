"""
Persisting and restoring ratchet state.

The bug this replaces: the old loader rebuilt state by calling the ratchet
constructor, which performs a full DH ratchet step. That advanced the root key
one step past the peer's on every restart. The chains were then overwritten
with the saved ones, so the session looked healthy right up until the next DH
rotation, at which point it broke permanently.

Restoring state is not the same operation as starting a session, so it does not
go through the constructor. Every field is written back exactly as saved,
skipped message keys included -- without those, a straggler that arrives after
a restart is unreadable.
"""

from __future__ import annotations

import base64

from nacl.public import PrivateKey

from crypto.ratchet import DoubleRatchet

STATE_VERSION = 2


def _e(raw):
    return base64.b64encode(raw).decode() if raw is not None else None


def _d(text):
    return base64.b64decode(text.encode()) if text is not None else None


def snapshot_ratchet(ratchet: DoubleRatchet) -> dict:
    """Serialise to a JSON-compatible dict. Output is key material."""
    return {
        "version": STATE_VERSION,
        "root_key": _e(ratchet.root_key),
        "dh_private": _e(ratchet.dh_pair.encode()),
        "peer_dh_public": _e(ratchet.peer_dh_public),
        "sending_chain": _e(ratchet.sending_chain),
        "receiving_chain": _e(ratchet.receiving_chain),
        "send_count": ratchet.send_count,
        "recv_count": ratchet.recv_count,
        "previous_chain_length": ratchet.previous_chain_length,
        "skipped": [
            {"dh": _e(peer_dh), "n": n, "mk": _e(message_key)}
            for (peer_dh, n), message_key in ratchet.skipped.items()
        ],
        # Without these, a restart forgets which chains are spent and a
        # replayed backlog message would trigger a ratchet against a stale key.
        "retired_dh": [_e(key) for key in ratchet.retired_dh],
    }


def restore_ratchet(data: dict) -> DoubleRatchet:
    """Rebuild a ratchet from `snapshot_ratchet` output, byte for byte."""
    version = data.get("version")
    if version != STATE_VERSION:
        raise ValueError(
            f"unsupported ratchet state version {version!r}; expected {STATE_VERSION}"
        )

    ratchet = DoubleRatchet.__new__(DoubleRatchet)
    ratchet.root_key = _d(data["root_key"])
    ratchet.dh_pair = PrivateKey(_d(data["dh_private"]))
    ratchet.peer_dh_public = _d(data["peer_dh_public"])
    ratchet.sending_chain = _d(data["sending_chain"])
    ratchet.receiving_chain = _d(data["receiving_chain"])
    ratchet.send_count = data["send_count"]
    ratchet.recv_count = data["recv_count"]
    ratchet.previous_chain_length = data["previous_chain_length"]
    ratchet.skipped = {
        (_d(entry["dh"]), entry["n"]): _d(entry["mk"])
        for entry in data.get("skipped", [])
    }
    ratchet.retired_dh = {_d(key) for key in data.get("retired_dh", [])}
    return ratchet
