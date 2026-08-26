"""
Protocol session: transport, handshake and message handling.

Deliberately free of user-interface code -- it reports everything through an
`on_event` callback so the terminal UI and the tests drive the same object.
"""

from __future__ import annotations

import threading
import time

import requests
import socketio

from crypto.keys import Bundle, Identity, b64e, safety_number
from crypto.password import derive_verifier
from crypto.ratchet import DoubleRatchet, RatchetError
from crypto.state import restore_ratchet, snapshot_ratchet
from crypto.x3dh import x3dh_initiator, x3dh_responder
import storage

TOR_SOCKS_PORT = 9150  # Tor Browser. A standalone tor daemon uses 9050.
REQUEST_TIMEOUT = 30


class SessionError(Exception):
    pass


class PeerIdentityChanged(Exception):
    """
    The peer's long-term identity key differs from the one recorded for this
    room. Either they reinstalled, or something is sitting in the middle.
    """

    def __init__(self, peer_user, old_identity, new_identity):
        super().__init__(f"identity key for '{peer_user}' has changed")
        self.peer_user = peer_user
        self.old_identity = old_identity
        self.new_identity = new_identity


class SpectreSession:
    """
    One conversation: one room, one peer, one ratchet.

    Events emitted through `on_event(kind, payload)`:
        status      transport/handshake progress          {"text": str}
        error       something the user must see            {"text": str}
        message     decrypted inbound message              {"user", "text", "ts"}
        sent        our own message, for echoing           {"user", "text", "ts"}
        peer        peer joined or left                    {"user", "joined": bool}
        ready       ratchet established                    {"safety_number", "peer"}
        warning     security-relevant, needs attention     {"text": str}
        state       connection/ratchet flags changed       {}
    """

    def __init__(self, url, room, user, password, is_initiator, use_tor, on_event):
        self.url = url
        self.room = room
        self.user = user
        self.is_initiator = is_initiator
        self.use_tor = use_tor
        self.on_event = on_event

        self.connected = False
        self.peer_user = None
        self.peer_identity_b64 = None
        self.safety_number = None
        self.peer_verified = False
        self.sent_count = 0
        self.recv_count = 0

        self._verifier = derive_verifier(user, password)
        self._identity = self._load_or_create_identity()
        self._ratchet = None
        self._pending = []
        # Highest backend message id already decrypted. The relay replays
        # anything past a peer's last acknowledged id on join, and an
        # acknowledgement can be lost, so the client must not depend on the
        # relay to avoid re-delivering a message it has already processed.
        self._last_message_id = 0
        self._lock = threading.RLock()

        # `join` is a round trip. Anything typed before the relay confirms it
        # would be rejected as "not a participant" and lost, so outbound text
        # waits here and is encrypted in order once the room is live.
        self._joined = False
        self._outbox = []

        self._login_event = threading.Event()
        self._login_result = {}
        self._register_event = threading.Event()
        self._register_result = {}

        self.sio = self._build_client()
        self._wire_handlers()
        self._restore_ratchet()

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

    def _restore_ratchet(self):
        saved = storage.load_state(self.user, self.room)
        if saved is None:
            return
        try:
            self._ratchet = restore_ratchet(saved["ratchet"])
            self._last_message_id = saved.get("last_message_id", 0)
        except (KeyError, TypeError, ValueError) as e:
            self._emit("warning",
                       text=f"Could not restore the saved session ({e}). "
                            f"Starting a fresh handshake.")
            storage.clear_state(self.user, self.room)
            return

        known = storage.load_known_peer(self.user, self.room)
        if known:
            self.peer_user = known.get("user")
            self.peer_identity_b64 = known.get("identity")
            self._recompute_safety_number()
        self._emit("status", text="Resumed the saved session for this room.")

    def _emit(self, kind, **payload):
        try:
            self.on_event(kind, payload)
        except Exception:
            pass  # the UI must never take the session down

    def _recompute_safety_number(self):
        if not self.peer_identity_b64:
            return
        import base64
        self.safety_number = safety_number(
            self._identity.identity_public_bytes(),
            base64.b64decode(self.peer_identity_b64),
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
            self._flush_outbox()

        @sio.on("peer_joined")
        def on_peer_joined(data):
            self._emit("peer", user=(data or {}).get("user"), joined=True)

        @sio.on("peer_left")
        def on_peer_left(data):
            self._emit("peer", user=(data or {}).get("user"), joined=False)

        @sio.on("bundle")
        def on_bundle(data):
            try:
                self._handle_bundle((data or {}).get("bundle") or {})
            except PeerIdentityChanged as e:
                self._emit("warning",
                           text=f"WARNING: the identity key for '{e.peer_user}' has "
                                f"changed since you last spoke. If they did not "
                                f"reinstall, someone may be intercepting this "
                                f"conversation. Run /trust to accept the new key.")
                self._pending_identity_change = e
            except Exception as e:
                self._emit("error", text=f"Rejected the peer's key bundle: {e}")

        @sio.on("packet")
        def on_packet(data):
            self._handle_packet(data or {})

    # ---- handshake ----------------------------------------------------

    def _handle_bundle(self, raw_bundle: dict):
        with self._lock:
            # Validation runs before the "already established" check on
            # purpose. Returning early here would skip the identity comparison
            # for exactly the case that matters most: a peer whose long-term
            # key changes partway through a relationship.
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
            known = storage.load_known_peer(self.user, self.room)
            if known and known.get("identity") != identity_b64:
                raise PeerIdentityChanged(
                    bundle.user, known.get("identity"), identity_b64
                )

            if self._ratchet is not None:
                # Same peer, same identity, session already up. Renegotiating
                # would discard the ratchet and reuse message keys, so the
                # bundle is acknowledged and otherwise ignored.
                return

            self.peer_user = bundle.user
            self.peer_identity_b64 = identity_b64

            if self.is_initiator:
                shared = x3dh_initiator(self._identity, bundle)
                self._ratchet = DoubleRatchet.initiator(shared, bundle.signed_prekey)
            else:
                shared = x3dh_responder(self._identity, bundle)
                self._ratchet = DoubleRatchet.responder(
                    shared, self._identity.signed_prekey_private
                )

            storage.save_known_peer(self.user, self.room, bundle.user, identity_b64)
            self._recompute_safety_number()
            self._save_state()

            self._emit("ready", safety_number=self.safety_number, peer=bundle.user)
            self._flush_outbox()
            if not self._ratchet.can_send():
                self._emit("status",
                           text=f"Waiting for {bundle.user} to send the first "
                                f"message before this side can reply.")
            self._drain_pending()

    def _drain_pending(self):
        queued, self._pending = self._pending, []
        for packet in queued:
            self._handle_packet(packet, queued=True)

    # ---- messaging ----------------------------------------------------

    def _handle_packet(self, data: dict, queued: bool = False):
        if data.get("type") != "msg":
            return
        if data.get("user") == self.user:
            return

        message_id = data.get("id")
        if isinstance(message_id, int) and message_id <= self._last_message_id:
            # Already decrypted in an earlier run; re-feeding it to the ratchet
            # would be rejected as a stale replay and log a spurious error.
            self._ack(message_id)
            return

        with self._lock:
            if self._ratchet is None:
                if not queued:
                    self._pending.append(data)
                return

            try:
                plaintext = self._ratchet.decrypt(data)
            except RatchetError as e:
                self._emit("error", text=f"Could not decrypt a message: {e}")
                return
            except Exception as e:
                self._emit("error", text=f"Unexpected error decrypting: {e}")
                return

            self.recv_count += 1
            if isinstance(message_id, int):
                self._last_message_id = max(self._last_message_id, message_id)
            self._save_state()

        text = plaintext.decode("utf-8", errors="replace")
        self._emit("message", user=data.get("user") or self.peer_user or "peer",
                   text=text, ts=time.time())
        self._emit("state")
        self._flush_outbox()

        if isinstance(message_id, int):
            self._ack(message_id)

    def _ack(self, message_id: int) -> None:
        try:
            self.sio.emit("seen", {"room": self.room, "lastSeenMessageId": message_id})
        except Exception:
            pass  # best effort; the client-side id check is the real guard

    def send_message(self, text: str) -> bool:
        with self._lock:
            if not self._joined or self._ratchet is None or not self._ratchet.can_send():
                # Not ready to encrypt yet. Hold the plaintext and send it in
                # order once the handshake and the join have both completed.
                if self._ratchet is None or not self._ratchet.can_send():
                    if self._ratchet is not None and not self._ratchet.can_send():
                        self._emit("status",
                                   text="Queued -- waiting for the peer's first message.")
                    else:
                        self._emit("status", text="Queued -- session not ready yet.")
                self._outbox.append(text)
                return True

        return self._encrypt_and_send(text)

    def _flush_outbox(self):
        with self._lock:
            if self._ratchet is None or not self._ratchet.can_send() or not self._joined:
                return
            pending, self._outbox = self._outbox, []
        for text in pending:
            self._encrypt_and_send(text)

    def _encrypt_and_send(self, text: str) -> bool:
        with self._lock:
            if self._ratchet is None:
                self._emit("error", text="No secure session yet -- waiting for the peer.")
                return False
            if not self._ratchet.can_send():
                self._emit("error",
                           text="Cannot send yet: this side is the responder and must "
                                "receive one message first.")
                return False

            try:
                packet = self._ratchet.encrypt(text.encode("utf-8"))
            except RatchetError as e:
                self._emit("error", text=f"Encryption failed: {e}")
                return False

            self.sent_count += 1
            self._save_state()

        packet["type"] = "msg"
        packet["room"] = self.room
        try:
            self.sio.emit("packet", packet)
        except Exception as e:
            self._emit("error", text=f"Could not reach the relay: {e}")
            return False

        self._emit("sent", user=self.user, text=text, ts=time.time())
        self._emit("state")
        return True

    def _save_state(self):
        if self._ratchet is None:
            return
        try:
            storage.save_state(self.user, self.room, {
                "ratchet": snapshot_ratchet(self._ratchet),
                "last_message_id": self._last_message_id,
            })
        except OSError as e:
            self._emit("error", text=f"Could not persist session state: {e}")

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
        self.sio.emit("login", {
            "user": self.user,
            "verifier": self._verifier,
            "role": "initiator" if self.is_initiator else "responder",
        })
        if not self._login_event.wait(timeout=REQUEST_TIMEOUT):
            raise SessionError("the relay did not answer the login request")
        return self._login_result

    def _register(self):
        self._register_event.clear()
        self.sio.emit("register", {
            "user": self.user,
            "verifier": self._verifier,
            "role": "initiator" if self.is_initiator else "responder",
        })
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
        try:
            self._save_state()
        except Exception:
            pass
        try:
            self.sio.disconnect()
        except Exception:
            pass

    # ---- user actions -------------------------------------------------

    def mark_verified(self):
        self.peer_verified = True
        self._emit("state")

    def trust_new_identity(self):
        """Accept a changed peer identity after the user has re-verified."""
        pending = getattr(self, "_pending_identity_change", None)
        if pending is None:
            return False
        storage.save_known_peer(self.user, self.room, pending.peer_user,
                                pending.new_identity)
        storage.clear_state(self.user, self.room)
        self._pending_identity_change = None
        self.peer_verified = False
        self._emit("status",
                   text="New identity accepted. Restart the client to handshake again.")
        return True

    @property
    def ready(self):
        return self._ratchet is not None

    @property
    def can_send(self):
        return self._ratchet is not None and self._ratchet.can_send()
