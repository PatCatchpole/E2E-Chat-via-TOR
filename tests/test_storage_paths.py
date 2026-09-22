"""
Storage path construction.

`_safe_name` is lossy and the components are joined with "__", which the
components themselves may contain. Without the `_key` digest, two distinct
pairwise sessions name the same state file -- and two ratchets sharing one
file is a key-reuse bug, not a cosmetic one.
"""

from __future__ import annotations

import pytest

import storage


@pytest.fixture(autouse=True)
def isolated_storage(tmp_path, monkeypatch):
    monkeypatch.setattr(storage, "SPECTRE_DIR", tmp_path)
    monkeypatch.setattr(storage, "STATE_DIR", tmp_path / "state")
    monkeypatch.setattr(storage, "PEERS_DIR", tmp_path / "peers")
    storage.ensure_dirs()
    yield


def test_separator_in_a_room_name_cannot_collide_with_a_peer_name():
    # ("x__y", "z") and ("x", "y__z") both clean to alice__x__y__z.
    a = storage.state_path("alice", "x__y", "z")
    b = storage.state_path("alice", "x", "y__z")
    assert a != b


def test_lossy_characters_cannot_collide():
    # Both clean to the same string; only the digest separates them.
    a = storage.state_path("alice", "room one", "bob")
    b = storage.state_path("alice", "room/one", "bob")
    assert a != b


def test_colliding_rooms_keep_independent_state():
    storage.save_state("alice", "x__y", "z", {"ratchet": {"marker": "first"}})
    storage.save_state("alice", "x", "y__z", {"ratchet": {"marker": "second"}})

    assert storage.load_state("alice", "x__y", "z")["ratchet"]["marker"] == "first"
    assert storage.load_state("alice", "x", "y__z")["ratchet"]["marker"] == "second"


def test_reset_clears_the_delivery_watermark_too():
    # The progress file used to be named "user__room.progress.json", which sits
    # outside clear_state's "user__room__*" glob. --reset therefore dropped the
    # ratchets and kept the watermark that suppresses the backlog.
    storage.save_progress("alice", "spectre", {"last_message_id": 99})
    storage.save_state("alice", "spectre", "bob", {"ratchet": {}})

    storage.clear_state("alice", "spectre")

    assert storage.load_state("alice", "spectre", "bob") is None
    assert storage.load_progress("alice", "spectre").get("last_message_id") is None


def test_a_session_saved_under_the_old_name_is_still_found():
    legacy = storage.STATE_DIR / "alice__spectre__bob.json"
    legacy.write_text('{"ratchet": {"marker": "legacy"}}', encoding="utf-8")

    restored = storage.load_state("alice", "spectre", "bob")

    assert restored is not None, "a session saved by an older build was lost"
    assert restored["ratchet"]["marker"] == "legacy"


def test_peers_and_rooms_are_listed_under_the_new_names():
    storage.save_known_peer("alice", "spectre", "bob", "identity-b64")
    storage.save_state("alice", "spectre", "bob", {"ratchet": {}})

    assert storage.list_peers("alice", "spectre") == ["bob"]
    assert [r["room"] for r in storage.list_rooms("alice")] == ["spectre"]


# ---- file permissions --------------------------------------------------

@pytest.mark.skipif(not storage.POSIX_PERMISSIONS,
                    reason="Windows has no POSIX mode bits")
def test_everything_written_is_private_to_the_owner():
    """
    The original wrote all of this with the default umask, leaving private
    keys and live chain keys world-readable.
    """
    storage.save_identity_seed("alice", b"\x01" * 32)
    storage.save_state("alice", "spectre", "bob", {"ratchet": {}})
    storage.save_known_peer("alice", "spectre", "bob", "identity-b64")
    storage.save_progress("alice", "spectre", {"last_message_id": 1})
    storage.save_relay_token("a-token")
    storage.save_launcher_prefs({"relay": "127.0.0.1:5055"})

    written = [
        storage.identity_path("alice"),
        storage.state_path("alice", "spectre", "bob"),
        storage.peer_path("alice", "spectre", "bob"),
        storage.progress_path("alice", "spectre"),
        storage.relay_token_path(),
        storage.launcher_prefs_path(),
    ]
    for path in written:
        assert path.exists(), f"{path.name} was not written"
        assert path.stat().st_mode & 0o077 == 0, f"{path.name} is readable by others"
        assert storage.check_permissions(path)


@pytest.mark.skipif(not storage.POSIX_PERMISSIONS,
                    reason="Windows has no POSIX mode bits")
def test_the_storage_directories_are_private():
    for directory in (storage.SPECTRE_DIR, storage.STATE_DIR, storage.PEERS_DIR):
        assert directory.stat().st_mode & 0o077 == 0


@pytest.mark.skipif(not storage.POSIX_PERMISSIONS,
                    reason="Windows has no POSIX mode bits")
def test_a_loosened_file_is_reported_not_silently_accepted():
    storage.save_identity_seed("alice", b"\x01" * 32)
    path = storage.identity_path("alice")
    path.chmod(0o644)

    assert not storage.check_permissions(path)


def test_a_write_leaves_no_temporary_file_behind():
    storage.save_state("alice", "spectre", "bob", {"ratchet": {}})
    leftovers = list(storage.STATE_DIR.glob("*.tmp.*"))
    assert leftovers == [], f"atomic write left {leftovers}"
