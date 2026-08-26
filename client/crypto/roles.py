"""
Deciding who initiates a pairwise session.

With two people a user could be asked whether they are the initiator or the
responder. In a group that question has no answer: every member is the
initiator of some pairs and the responder of others, and the two ends must
agree without exchanging anything to negotiate it.

The rule is a total order on usernames. For any pair, the lexicographically
smaller name initiates. It is deterministic, symmetric, needs no round trip,
and gives the same answer on both sides.
"""

from __future__ import annotations


def is_initiator(own_user: str, peer_user: str) -> bool:
    """
    True if we take the initiator role against this peer.

    Raises if the names are equal: X3DH would degenerate, and the relay
    already refuses two sessions under one name in a room.
    """
    if own_user == peer_user:
        raise ValueError(
            f"cannot open a session with ourselves ({own_user!r}); "
            "usernames must be distinct within a room"
        )
    return own_user < peer_user
