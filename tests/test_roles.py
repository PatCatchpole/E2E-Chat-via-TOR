"""Role assignment must be deterministic and agreed by both ends."""

from __future__ import annotations

import itertools

import pytest

from crypto.roles import is_initiator


def test_exactly_one_side_initiates():
    for a, b in itertools.permutations(["alice", "bob", "carol", "dave"], 2):
        assert is_initiator(a, b) != is_initiator(b, a)


def test_agreement_is_symmetric():
    assert is_initiator("alice", "bob") is True
    assert is_initiator("bob", "alice") is False


def test_ordering_is_stable_regardless_of_join_order():
    """Whoever connects first must not change who initiates."""
    members = ["zoe", "adam", "mia"]
    for ordering in itertools.permutations(members):
        roles = {
            (a, b): is_initiator(a, b)
            for a, b in itertools.permutations(ordering, 2)
        }
        assert roles[("adam", "mia")] is True
        assert roles[("mia", "zoe")] is True
        assert roles[("adam", "zoe")] is True


def test_same_username_is_rejected():
    with pytest.raises(ValueError, match="ourselves"):
        is_initiator("alice", "alice")


def test_every_pair_in_a_group_has_one_initiator():
    group = ["alice", "bob", "carol", "dave", "erin"]
    for a, b in itertools.combinations(group, 2):
        assert sum([is_initiator(a, b), is_initiator(b, a)]) == 1
