"""
Protocol-level tests for the Double Ratchet.

Each test here corresponds to a defect found in the original implementation;
the docstrings name the finding so a regression is easy to trace back.
"""

from __future__ import annotations

import pytest

from crypto.ratchet import DoubleRatchet, MAX_SKIP, RatchetError
from crypto.state import restore_ratchet, snapshot_ratchet
from helpers import make_session, recv, send


def test_basic_alternating_conversation():
    a, b = make_session()
    assert recv(b, send(a, "hello")) == "hello"
    assert recv(a, send(b, "hi back")) == "hi back"
    assert recv(b, send(a, "how are you")) == "how are you"


def test_many_messages_in_one_direction():
    """A long unanswered run must stay in sync (symmetric chain only)."""
    a, b = make_session()
    for i in range(50):
        assert recv(b, send(a, f"msg {i}")) == f"msg {i}"


def test_dh_key_rotates_automatically():
    """
    Finding #10: the DH ratchet must advance on its own, with no manual
    /rotate command, or there is no post-compromise security.
    """
    a, b = make_session()
    first = a.sending_public_bytes()
    recv(b, send(a, "one"))
    recv(a, send(b, "reply"))  # b's reply carries a new DH key -> a ratchets
    recv(b, send(a, "two"))
    assert a.sending_public_bytes() != first, "DH key never rotated"


def test_out_of_order_delivery():
    """
    Finding #9: a reordered message must not break the session, and the
    delayed message must still decrypt when it arrives.
    """
    a, b = make_session()
    m1, m2, m3 = send(a, "first"), send(a, "second"), send(a, "third")

    assert recv(b, m3) == "third"
    assert recv(b, m1) == "first"
    assert recv(b, m2) == "second"
    assert recv(b, send(a, "fourth")) == "fourth"


def test_dropped_message_does_not_break_chain():
    """Finding #9: a permanently lost message must not poison what follows."""
    a, b = make_session()
    send(a, "this one is lost in transit")
    assert recv(b, send(a, "but this one still works")) == "but this one still works"


def test_out_of_order_across_a_dh_ratchet():
    """
    The hard case: messages from the previous sending chain arriving after the
    peer has already ratcheted. This is what the `pn` header field is for.
    """
    a, b = make_session()
    recv(b, send(a, "establish both directions"))
    recv(a, send(b, "now a has b's key"))

    old1 = send(a, "old chain 1")
    old2 = send(a, "old chain 2")
    recv(b, old1)                    # b ratchets onto a's current chain
    reply = send(b, "b replies")
    recv(a, reply)                   # a ratchets -> new sending chain
    new1 = send(a, "new chain 1")

    assert recv(b, new1) == "new chain 1"
    assert recv(b, old2) == "old chain 2", "straggler from the previous chain"


def test_simultaneous_ratchet_both_directions():
    """
    Finding #8: both peers producing messages before either receives (crossing
    in flight) must not desynchronise the session.
    """
    a, b = make_session()
    recv(b, send(a, "open the channel"))
    recv(a, send(b, "both directions live"))

    from_a = send(a, "sent by a")
    from_b = send(b, "sent by b")

    assert recv(b, from_a) == "sent by a"
    assert recv(a, from_b) == "sent by b"
    assert recv(b, send(a, "still fine")) == "still fine"


def test_state_survives_save_and_restore():
    """
    Finding #7: a save/restore round trip must preserve the root key exactly.
    The original re-ran a full DH ratchet step on load, silently advancing the
    root key and breaking the session at the next rotation.
    """
    a, b = make_session()
    recv(b, send(a, "before restart"))
    recv(a, send(b, "reply"))

    a = restore_ratchet(snapshot_ratchet(a))

    assert recv(b, send(a, "after restart")) == "after restart"
    assert recv(a, send(b, "peer still reaches us")) == "peer still reaches us"
    # The next DH ratchet is where a corrupted root key would surface.
    assert recv(b, send(a, "and past the next ratchet")) == "and past the next ratchet"


def test_restore_preserves_skipped_keys():
    """Skipped message keys must survive a restart or the straggler is lost."""
    a, b = make_session()
    m1, m2 = send(a, "one"), send(a, "two")
    recv(b, m2)
    b = restore_ratchet(snapshot_ratchet(b))
    assert recv(b, m1) == "one"


def test_forged_header_counter_is_bounded():
    """
    Finding #11: `n` is attacker-controlled. An absurd value must be rejected
    immediately rather than driving an unbounded key-derivation loop.
    """
    a, b = make_session()
    packet = send(a, "hello")
    packet["hdr"]["n"] = 10**12

    with pytest.raises(RatchetError):
        b.decrypt(packet)


def test_skip_limit_is_enforced_exactly():
    a, b = make_session()
    packet = send(a, "hello")
    packet["hdr"]["n"] = MAX_SKIP + 1
    with pytest.raises(RatchetError):
        b.decrypt(packet)


def test_tampered_header_is_rejected():
    """
    Finding #11: the header is bound into the AEAD as associated data, so
    flipping any header field must fail authentication instead of being
    silently accepted.
    """
    a, b = make_session()

    packet = send(a, "hello")
    packet["hdr"]["n"] = 3
    with pytest.raises(RatchetError):
        b.decrypt(packet)

    packet = send(a, "hello again")
    packet["hdr"]["pn"] = 99
    with pytest.raises(RatchetError):
        b.decrypt(packet)


def test_tampered_ciphertext_is_rejected():
    a, b = make_session()
    packet = send(a, "hello")
    ct = bytearray(packet["body"]["ct"].encode())
    ct[5] = ct[5] ^ 0x01 if ct[5] != 0x01 else 0x02
    packet["body"]["ct"] = ct.decode()
    with pytest.raises(RatchetError):
        b.decrypt(packet)


def test_replayed_message_is_rejected():
    """A message key is one-time use; replaying must not decrypt twice."""
    a, b = make_session()
    packet = send(a, "only once")
    assert recv(b, packet) == "only once"
    with pytest.raises(RatchetError):
        b.decrypt(packet)


def test_every_message_uses_a_distinct_key():
    a, b = make_session()
    seen = set()
    for i in range(20):
        packet = send(a, f"m{i}")
        assert packet["body"]["ct"] not in seen
        seen.add(packet["body"]["ct"])
        recv(b, packet)


def test_responder_cannot_send_before_receiving():
    """
    Per the spec the responder has no sending chain until the first inbound
    message establishes one. Failing loudly beats emitting an undecryptable
    packet.
    """
    _, b = make_session()
    with pytest.raises(RatchetError):
        b.encrypt(b"too early")


def test_stale_chain_message_does_not_reset_the_ratchet():
    """
    A message from a DH chain the peer has already moved past -- a backlog
    replay, or a relay re-sending an old packet -- must be rejected outright.

    If it is instead treated as a new DH key it triggers a ratchet step against
    a superseded key, which rebuilds both chains from a stale root and breaks
    every subsequent message in the conversation.
    """
    a, b = make_session()

    recv(b, send(a, "one"))
    old_reply = send(b, "reply from the first chain")
    recv(a, old_reply)
    recv(b, send(a, "two"))
    recv(a, send(b, "reply from the second chain"))

    with pytest.raises(RatchetError):
        a.decrypt(old_reply)

    # The session must be unharmed by the rejected replay.
    assert recv(b, send(a, "still working")) == "still working"
    assert recv(a, send(b, "both ways")) == "both ways"
