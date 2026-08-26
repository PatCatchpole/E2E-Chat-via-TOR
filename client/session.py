"""
Protocol session: transport, handshakes and message handling.

A room is a mesh of pairwise Double Ratchet sessions, one per peer. Nothing
about the cryptography is group-aware: sending to a room means encrypting the
message separately for every member and emitting one packet each. That costs
O(n^2) traffic across the room, which is the price of every member keeping the
same forward secrecy and post-compromise guarantees they had one-to-one.

Deliberately free of user-interface code -- everything is reported through an
`on_event` callback so the terminal UI and the tests drive the same object.
"""

from __future__ import annotations

import base64
import threading
import time

import requests
import socketio

from crypto.framing import PRIME, TEXT, FramingError, frame_prime, frame_text, parse
from crypto.keys import Bundle, Identity, b64e, safety_number
from crypto.password import derive_verifier
from crypto.ratchet import DoubleRatchet, RatchetError
from crypto.roles import is_initiator
from crypto.state import restore_ratchet, snapshot_ratchet
from crypto.x3dh import x3dh_initiator, x3dh_responder
import storage

TOR_SOCKS_PORT = 9150  # Tor Browser. A standalone tor daemon uses 9050.
REQUEST_TIMEOUT = 30


class SessionError(Exception):
    pass


class PeerIdentityChanged(Exception):
    """
    A peer's long-term identity key differs from the one recorded for this
    room. Either they reinstalled, or something is sitting in the middle.
    """

    def __init__(self, peer_user, old_identity, new_identity):
        super().__init__(f"identity key for '{peer_user}' has changed")
        self.peer_user = peer_user
        self.old_identity = old_identity
        self.new_identity = new_identity


class Peer:
    """One pairwise session inside a room."""

    def __init__(self, user: str, identity_b64: str, ratchet: DoubleRatchet):
        self.user = user
        self.identity_b64 = identity_b64
        self.ratchet = ratchet
        self.safety_number = None
        self.verified = False
        self.online = False
        self.sent = 0
        self.received = 0

    @property
    def can_send(self) -> bool:
        return self.ratchet is not None and self.ratchet.can_send()


class SpectreSession:
    """
    One room: many peers, one ratchet each.

    Events emitted through `on_event(kind, payload)`:
        status      transport/handshake progress          {"text"}
        error       something the user must see           {"text"}
        message     decrypted inbound message             {"user", "text", "ts"}
        sent        our own message, for echoing          {"user", "text", "ts"}
        peer        a peer joined or left                 {"user", "joined"}
        ready       a pairwise session was established    {"peer", "safety_number"}
        warning     security-relevant, needs attention    {"text"}
        state       counters or flags changed             {}
    """

    def __init__(self, url, room, user, password, use_tor, on_event, is_initiator=None):
        self.url = url
        self.room = room
        self.user = user
        self.use_tor = use_tor
        self.on_event = on_event

        # Roles are derived per peer from the username ordering, so the caller
        # no longer chooses one. Accepted and ignored for compatibility.
        self._legacy_role = is_initiator

        self.connected = False
        self.peers = {}                 # username -> Peer
        self._pending = {}              # username -> [packet]
        self._outbox = []               # text queued before anyone is reachable
        self._identity_changes = {}     # username -> PeerIdentityChanged

        self._verifier = derive_verifier(user, password)
        self._identity = self._load_or_create_identity()
        self._joined = False
        self._lock = threading.RLock()

        progress = storage.load_progress(user, room)
        self._last_message_id = progress.get("last_message_id", 0)

        self._login_event = threading.Event()
        self._login_result = {}
        self._register_event = threading.Event()
        self._register_result = {}

        self.sio = self._build_client()
        self._wire_handlers()
        self._restore_sessions()

    # ---- setup --------------------------------------------------------

    def _load_or_create_identity(self) -> Identity:
        seed = storage.load_identity_seed(self.user)
        if seed is not None:
            if not storage.check_permissions(storage.identity_path(self.user)):
                self._emit("warning",
                           text=f"{storage.identity_path(self.user)} is readable by "
                                f"other users on this machine.")
            return Identity.from_seed(self.user, seed)

        identity = Identity.generate(self.user)
        storage.save_identity_seed(self.user, identity.export_seed())
        return identity

    def _build_client(self):
        if not self.use_tor:
            return socketio.Client(reconnection=True, reconnection_attempts=0)

        http_session = requests.Session()
        proxy = f"socks5h://127.0.0.1:{TOR_SOCKS_PORT}"
        # socks5h keeps hostname resolution inside Tor; plain socks5 would leak
        # the .onion lookup to the local resolver.
        http_session.proxies = {"http": proxy, "https": proxy}
        return socketio.Client(
            http_session=http_session, reconnection=True, reconnection_attempts=0
        )

    def _restore_sessions(self):
        """Reload every pairwise session saved for this room."""
        restored = 0
        for peer_user in storage.list_peers(self.user, self.room):
            known = storage.load_known_peer(self.user, self.room, peer_user)
            saved = storage.load_state(self.user, self.room, peer_user)
            if not known or not saved:
                continue
            try:
                ratchet = restore_ratchet(saved["ratchet"])
            except (KeyError, TypeError, ValueError) as e:
                self._emit("warning",
                           text=f"Could not restore the session with {peer_user} "
                                f"({e}). It will be renegotiated.")
                storage.clear_state(self.user, self.room, peer_user)
                continue

            peer = Peer(peer_user, known.get("identity"), ratchet)
            peer.safety_number = self._safety_number(known.get("identity"))
            self.peers[peer_user] = peer
            restored += 1

        if restored:
            self._emit("status",
                       text=f"Resumed {restored} saved "
                            f"session{'s' if restored != 1 else ''} in this room.")

    def _emit(self, kind, **payload):
        try:
            self.on_event(kind, payload)
        except Exception:
            pass  # the UI must never take the session down

    def _safety_number(self, peer_identity_b64):
        if not peer_identity_b64:
            return None
        return safety_number(
            self._identity.identity_public_bytes(),
            base64.b64decode(peer_identity_b64),
        )

    # ---- socket handlers ----------------------------------------------

    def _wire_handlers(self):
        sio = self.sio

        @sio.event
        def connect():
            self.connected = True
            self._emit("status", text="Connected to the relay.")
            self._emit("state")

        @sio.event
        def disconnect():
            self.connected = False
            self._joined = False
            self._emit("status", text="Disconnected from the relay.")
            self._emit("state")

        @sio.on("login_result")
        def on_login(data):
            self._login_result = data or {}
            self._login_event.set()

        @sio.on("register_result")
        def on_register(data):
            self._register_result = data or {}
            self._register_event.set()

        @sio.on("error_msg")
        def on_error(data):
            self._emit("error", text=(data or {}).get("message", "Unknown error"))

        @sio.on("joined")
        def on_joined(data):
            self._joined = True
            self._emit("status", text=f"Joined #{(data or {}).get('room')}.")
            for name in (data or {}).get("members", []):
                if name != self.user and name in self.peers:
                    self.peers[name].online = True
            self._flush_outbox()
            self._emit("state")

        @sio.on("peer_joined")
        def on_peer_joined(data):
            name = (data or {}).get("user")
            if name and name in self.peers:
                self.peers[name].online = True
            self._emit("peer", user=name, joined=True)

        @sio.on("peer_left")
        def on_peer_left(data):
            name = (data or {}).get("user")
            if name and name in self.peers:
                self.peers[name].online = False
            self._emit("peer", user=name, joined=False)

        @sio.on("bundle")
        def on_bundle(data):
            try:
                self._handle_bundle((data or {}).get("bundle") or {})
            except PeerIdentityChanged as e:
                self._identity_changes[e.peer_user] = e
                self._emit("warning",
                           text=f"WARNING: the identity key for '{e.peer_user}' has "
                                f"changed since you last spoke. If they did not "
                                f"reinstall, someone may be intercepting this "
                                f"conversation. Run /trust {e.peer_user} to accept it.")
            except Exception as e:
                self._emit("error", text=f"Rejected a key bundle: {e}")

        @sio.on("packet")
        def on_packet(data):
            self._handle_packet(data or {})

    # ---- handshake ----------------------------------------------------

    def _handle_bundle(self, raw_bundle: dict):
        with self._lock:
            # Validation runs before the "already established" check on
            # purpose. Returning early would skip the identity comparison for
            # exactly the case that matters most: a peer whose long-term key
            # changes partway through a relationship.
            try:
                bundle = Bundle.from_dict(raw_bundle)
            except (KeyError, ValueError, TypeError) as e:
                raise SessionError(f"malformed bundle: {e}") from e

            if not bundle.verify():
                raise SessionError(
                    "signature check failed -- the bundle was not signed by the "
                    "identity it claims, or was altered in transit"
                )
            if bundle.room != self.room:
                raise SessionError(
                    f"bundle is for room '{bundle.room}', not '{self.room}'"
                )
            if bundle.user == self.user:
                raise SessionError("received our own bundle back from the relay")

            identity_b64 = b64e(bundle.identity)
            known = storage.load_known_peer(self.user, self.room, bundle.user)
            if known and known.get("identity") != identity_b64:
                raise PeerIdentityChanged(
                    bundle.user, known.get("identity"), identity_b64
                )

            existing = self.peers.get(bundle.user)
            if existing is not None and existing.ratchet is not None:
                # Same peer, same identity, session already up. Renegotiating
                # would discard the ratchet and reuse message keys.
                existing.online = True
                return

            initiator = is_initiator(self.user, bundle.user)
            if initiator:
                shared = x3dh_initiator(self._identity, bundle)
                ratchet = DoubleRatchet.initiator(shared, bundle.signed_prekey)
            else:
                shared = x3dh_responder(self._identity, bundle)
                ratchet = DoubleRatchet.responder(
                    shared, self._identity.signed_prekey_private
                )

            peer = Peer(bundle.user, identity_b64, ratchet)
            peer.safety_number = self._safety_number(identity_b64)
            peer.online = True
            self.peers[bundle.user] = peer

            storage.save_known_peer(self.user, self.room, bundle.user, identity_b64)
            self._save_state(bundle.user)

        self._emit("ready", peer=bundle.user, safety_number=peer.safety_number)

        # The initiator opens the reverse direction immediately. Without this
        # the peer has no sending chain and cannot reply until we send real
        # text -- which in a group would leave the last member mute.
        if initiator:
            self._send_to(bundle.user, frame_prime())

        self._drain_pending(bundle.user)
        self._flush_outbox()
        self._emit("state")

    def _drain_pending(self, peer_user: str):
        queued = self._pending.pop(peer_user, [])
        for packet in queued:
            self._handle_packet(packet, queued=True)

    # ---- receiving ----------------------------------------------------

    def _handle_packet(self, data: dict, queued: bool = False):
        if data.get("type") != "msg":
            return

        sender = data.get("user")
        if not sender or sender == self.user:
            return

        message_id = data.get("id")
        if isinstance(message_id, int) and message_id <= self._last_message_id:
            # Already processed in an earlier run; re-feeding it to the ratchet
            # would be rejected as a stale replay and log a spurious error.
            self._ack(message_id)
            return

        with self._lock:
            peer = self.peers.get(sender)
            if peer is None or peer.ratchet is None:
                if not queued:
                    self._pending.setdefault(sender, []).append(data)
                return

            try:
                payload = peer.ratchet.decrypt(data)
            except RatchetError as e:
                self._emit("error",
                           text=f"Could not decrypt a message from {sender}: {e}")
                return
            except Exception as e:
                self._emit("error",
                           text=f"Unexpected error decrypting from {sender}: {e}")
                return

            try:
                kind, text = parse(payload)
            except FramingError as e:
                self._emit("error", text=f"Unreadable message from {sender}: {e}")
                return

            if isinstance(message_id, int):
                self._last_message_id = max(self._last_message_id, message_id)
                self._save_progress()
            self._save_state(sender)

            if kind == TEXT:
                peer.received += 1

        if isinstance(message_id, int):
            self._ack(message_id)

        if kind == PRIME:
            # Silent: its only purpose was to give us a sending chain.
            self._flush_outbox()
            self._emit("state")
            return

        self._emit("message", user=sender, text=text, ts=time.time())
        self._emit("state")
        self._flush_outbox()

    def _ack(self, message_id: int) -> None:
        try:
            self.sio.emit("seen", {"room": self.room, "lastSeenMessageId": message_id})
        except Exception:
            pass  # best effort; the client-side id check is the real guard

    # ---- sending ------------------------------------------------------

    def send_message(self, text: str) -> bool:
        """
        Encrypt `text` once per peer and send each copy.

        Returns True if it reached at least one peer, or was queued for later.
        """
        with self._lock:
            reachable = [p for p in self.peers.values() if p.can_send]
            if not self._joined or not reachable:
                self._outbox.append(text)
                if not self.peers:
                    self._emit("status", text="Queued -- waiting for someone to join.")
                else:
                    self._emit("status", text="Queued -- no peer is reachable yet.")
                return True
            targets = [p.user for p in reachable]

        delivered = 0
        for peer_user in targets:
            if self._send_to(peer_user, frame_text(text)):
                delivered += 1

        if delivered:
            self._emit("sent", user=self.user, text=text, ts=time.time())
            self._emit("state")
        return delivered > 0

    def _send_to(self, peer_user: str, payload: bytes) -> bool:
        """Encrypt one already-framed payload for one peer and emit it."""
        with self._lock:
            peer = self.peers.get(peer_user)
            if peer is None or not peer.can_send:
                return False
            try:
                packet = peer.ratchet.encrypt(payload)
            except RatchetError as e:
                self._emit("error", text=f"Encryption failed for {peer_user}: {e}")
                return False
            if payload and payload[0] == TEXT:
                peer.sent += 1
            self._save_state(peer_user)

        packet["type"] = "msg"
        packet["room"] = self.room
        packet["to"] = peer_user
        try:
            self.sio.emit("packet", packet)
        except Exception as e:
            self._emit("error", text=f"Could not reach the relay: {e}")
            return False
        return True

    def _flush_outbox(self):
        with self._lock:
            if not self._joined or not self._outbox:
                return
            if not any(p.can_send for p in self.peers.values()):
                return
            pending, self._outbox = self._outbox, []
        for text in pending:
            self.send_message(text)

    # ---- persistence --------------------------------------------------

    def _save_state(self, peer_user: str):
        peer = self.peers.get(peer_user)
        if peer is None or peer.ratchet is None:
            return
        try:
            storage.save_state(self.user, self.room, peer_user, {
                "ratchet": snapshot_ratchet(peer.ratchet),
            })
        except OSError as e:
            self._emit("error", text=f"Could not persist session state: {e}")

    def _save_progress(self):
        try:
            storage.save_progress(self.user, self.room,
                                  {"last_message_id": self._last_message_id})
        except OSError:
            pass

    # ---- lifecycle ----------------------------------------------------

    def connect(self):
        self.sio.connect(self.url, wait=True, wait_timeout=REQUEST_TIMEOUT,
                         transports=["polling"])

    def authenticate(self) -> None:
        """Log in, registering first if the account does not exist yet."""
        result = self._login()
        if result.get("success"):
            self._emit("status", text=f"Signed in as {self.user}.")
            return

        if result.get("code") != "USER_NOT_FOUND":
            raise SessionError(result.get("message") or "Login failed")

        self._emit("status", text="No such account yet -- registering.")
        registered = self._register()
        if not registered.get("success"):
            raise SessionError(registered.get("message") or "Registration failed")

        result = self._login()
        if not result.get("success"):
            raise SessionError(result.get("message") or "Login failed after registering")
        self._emit("status", text=f"Registered and signed in as {self.user}.")

    def _login(self):
        self._login_event.clear()
        self.sio.emit("login", {"user": self.user, "verifier": self._verifier})
        if not self._login_event.wait(timeout=REQUEST_TIMEOUT):
            raise SessionError("the relay did not answer the login request")
        return self._login_result

    def _register(self):
        self._register_event.clear()
        self.sio.emit("register", {"user": self.user, "verifier": self._verifier})
        if not self._register_event.wait(timeout=REQUEST_TIMEOUT):
            raise SessionError("the relay did not answer the registration request")
        return self._register_result

    def join(self):
        self.sio.emit("join", {
            "room": self.room,
            "bundle": self._identity.public_bundle(self.room).to_dict(),
        })

    def start(self):
        threading.Thread(target=self.sio.wait, daemon=True).start()

    def close(self):
        try:
            self.sio.emit("leave", {"room": self.room})
        except Exception:
            pass
        for peer_user in list(self.peers):
            try:
                self._save_state(peer_user)
            except Exception:
                pass
        try:
            self.sio.disconnect()
        except Exception:
            pass

    # ---- user actions -------------------------------------------------

    def mark_verified(self, peer_user: str) -> bool:
        peer = self.peers.get(peer_user)
        if peer is None:
            return False
        peer.verified = True
        self._emit("state")
        return True

    def trust_new_identity(self, peer_user: str) -> bool:
        """Accept a changed peer identity after the user has re-verified."""
        pending = self._identity_changes.pop(peer_user, None)
        if pending is None:
            return False
        storage.clear_state(self.user, self.room, peer_user)
        storage.save_known_peer(self.user, self.room, peer_user, pending.new_identity)
        self.peers.pop(peer_user, None)
        self._emit("status",
                   text=f"New identity for {peer_user} accepted. "
                        f"Restart the client to handshake again.")
        self._emit("state")
        return True

    # ---- views --------------------------------------------------------

    @property
    def ready(self) -> bool:
        return any(p.ratchet is not None for p in self.peers.values())

    @property
    def can_send(self) -> bool:
        return any(p.can_send for p in self.peers.values())

    @property
    def member_names(self) -> list:
        return sorted(self.peers)

    @property
    def sent_count(self) -> int:
        return sum(p.sent for p in self.peers.values())

    @property
    def recv_count(self) -> int:
        return sum(p.received for p in self.peers.values())

    @property
    def pending_identity_changes(self) -> list:
        return sorted(self._identity_changes)

    def safety_number_for(self, peer_user: str):
        peer = self.peers.get(peer_user)
        return peer.safety_number if peer else None
