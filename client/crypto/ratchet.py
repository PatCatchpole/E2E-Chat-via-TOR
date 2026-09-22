"""
Double Ratchet.

This follows the published algorithm rather than the bespoke variant that was
here before. The previous version derived a "base seed" per root step and split
it into SEND/RECV chains by role, kept no skipped-message keys, and exposed a
manual rotate operation that the algorithm does not have. That last one was the
source of the desync: rotating twice without sending in between left the peer
unable to reach the new root key.

Structure per the spec:

  RK          root key
  DHs / DHr   our current DH key pair / the peer's latest DH public key
  CKs / CKr   sending and receiving chain keys
  Ns / Nr     message counters within the current chains
  PN          length of the previous sending chain
  skipped     message keys for messages that have not arrived yet

The DH ratchet advances by itself: every message carries the sender's current
DH public key, and seeing a new one triggers a rotation on the receiver. There
is deliberately no public rotate method.
"""

from __future__ import annotations

import base64
import hmac
import json

from nacl.exceptions import CryptoError
from nacl.public import PrivateKey

from crypto.kdf import hkdf
from crypto.message import decrypt as aead_decrypt
from crypto.message import encrypt as aead_encrypt
from crypto.x3dh import dh

ROOT_INFO = b"SpectreProtocol/root/v1"
HEADER_AD = b"SpectreProtocol/header/v1"

CHAIN_STEP = b"\x01"
MESSAGE_KEY_STEP = b"\x02"

# An out-of-order or lost message is normal; a header claiming a counter far
# ahead of the current one is not. Without this bound a forged header drives an
# unbounded key-derivation loop on the receiver.
MAX_SKIP = 1000

# Total skipped keys retained across all chains, so a peer that keeps opening
# gaps cannot grow our state without limit.
MAX_SKIPPED_KEYS = 2000

# Retired peer DH keys kept for the stale-replay check below. One entry is
# added per DH rotation, so an unbounded set grows for the whole life of a
# conversation -- and it is re-serialised on every message save, which turns a
# long session into hundreds of kilobytes written per message. Evicting the
# oldest is safe: the check is a clearer error, not the actual guard. A stale
# packet that slips past it still fails the AEAD tag and is rolled back whole
# by `decrypt`.
MAX_RETIRED_DH = 128


class RatchetError(Exception):
    """Raised for any message this ratchet refuses to accept."""


def _kdf_rk(root_key: bytes, dh_output: bytes) -> tuple:
    """Root KDF: returns (new_root_key, chain_key)."""
    derived = hkdf(dh_output, info=ROOT_INFO, salt=root_key, length=64)
    return derived[:32], derived[32:]


def _kdf_ck(chain_key: bytes) -> tuple:
    """Chain KDF: returns (next_chain_key, message_key)."""
    next_ck = hmac.new(chain_key, CHAIN_STEP, "sha256").digest()
    message_key = hmac.new(chain_key, MESSAGE_KEY_STEP, "sha256").digest()
    return next_ck, message_key


def _header_bytes(header: dict) -> bytes:
    """
    Canonical encoding of the header, used as AEAD associated data. Sorted keys
    and no whitespace so both peers derive byte-identical input.
    """
    encoded = json.dumps(header, sort_keys=True, separators=(",", ":")).encode()
    return HEADER_AD + encoded


class DoubleRatchet:
    def __init__(self, root_key, dh_pair, peer_dh_public, sending_chain, receiving_chain):
        self.root_key = root_key
        self.dh_pair = dh_pair
        self.peer_dh_public = peer_dh_public
        self.sending_chain = sending_chain
        self.receiving_chain = receiving_chain
        self.send_count = 0
        self.recv_count = 0
        self.previous_chain_length = 0
        self.skipped = {}  # (peer_dh_public, n) -> message key
        # Peer DH keys we have already ratcheted past. A packet carrying one of
        # these is stale -- a backlog replay or a relay re-sending an old
        # message -- and must never be mistaken for a new key. A dict rather
        # than a set so the oldest can be evicted first; the values are unused.
        self.retired_dh = {}

    # ---- initial state ------------------------------------------------

    @classmethod
    def initiator(cls, shared_secret: bytes, peer_signed_prekey: bytes) -> "DoubleRatchet":
        """
        The initiator can send immediately: it performs the first root step
        against the responder's signed prekey.
        """
        dh_pair = PrivateKey.generate()
        root_key, sending_chain = _kdf_rk(shared_secret, dh(dh_pair, peer_signed_prekey))
        return cls(root_key, dh_pair, peer_signed_prekey, sending_chain, None)

    @classmethod
    def responder(cls, shared_secret: bytes, signed_prekey_private: PrivateKey) -> "DoubleRatchet":
        """
        The responder starts with no chains at all. Its first inbound message
        establishes both, which is why `encrypt` refuses to run before then.
        """
        return cls(shared_secret, signed_prekey_private, None, None, None)

    # ---- introspection ------------------------------------------------

    def sending_public_bytes(self) -> bytes:
        return self.dh_pair.public_key.encode()

    def can_send(self) -> bool:
        return self.sending_chain is not None

    # ---- sending ------------------------------------------------------

    def encrypt(self, plaintext: bytes) -> dict:
        if self.sending_chain is None:
            raise RatchetError(
                "no sending chain yet; the responder must receive one message "
                "before it can send"
            )

        self.sending_chain, message_key = _kdf_ck(self.sending_chain)
        header = {
            "dh": base64.b64encode(self.sending_public_bytes()).decode(),
            "pn": self.previous_chain_length,
            "n": self.send_count,
        }
        self.send_count += 1

        nonce, ciphertext = aead_encrypt(message_key, plaintext, _header_bytes(header))
        return {
            "hdr": header,
            "body": {
                "nonce": base64.b64encode(nonce).decode(),
                "ct": base64.b64encode(ciphertext).decode(),
            },
        }

    # ---- receiving ----------------------------------------------------

    def decrypt(self, packet: dict) -> bytes:
        """
        Decrypt one packet, or leave the ratchet exactly as it was.

        The DH ratchet step and the skipped-key derivation both run before the
        AEAD tag can be checked, so a packet that fails to authenticate would
        otherwise leave the chains advanced against a key the peer never used.
        One forged packet carrying a random DH public key would be enough to
        destroy a session permanently -- and the damage would be persisted.
        So the mutable state is captured first and rolled back on any failure.
        """
        snapshot = self._capture_state()
        try:
            return self._decrypt(packet)
        except Exception:
            self._restore_state(snapshot)
            raise

    def _capture_state(self) -> tuple:
        # Byte strings and PrivateKey are immutable; the containers are copied.
        return (
            self.root_key, self.dh_pair, self.peer_dh_public,
            self.sending_chain, self.receiving_chain,
            self.send_count, self.recv_count, self.previous_chain_length,
            dict(self.skipped), dict(self.retired_dh),
        )

    def _restore_state(self, snapshot: tuple) -> None:
        (self.root_key, self.dh_pair, self.peer_dh_public,
         self.sending_chain, self.receiving_chain,
         self.send_count, self.recv_count, self.previous_chain_length,
         self.skipped, self.retired_dh) = snapshot

    def _decrypt(self, packet: dict) -> bytes:
        header, nonce, ciphertext = self._parse(packet)
        peer_dh = base64.b64decode(header["dh"])
        n = header["n"]
        associated_data = _header_bytes(header)

        # A message we had already skipped past and stored a key for.
        stored = self.skipped.pop((peer_dh, n), None)
        if stored is not None:
            return self._open(stored, nonce, ciphertext, associated_data)

        if peer_dh in self.retired_dh:
            # We already ratcheted past this chain and have no stored key for
            # this counter, so the message is a duplicate of one consumed
            # earlier. Rejecting here is essential: falling through would
            # ratchet against a superseded key and rebuild both chains from a
            # stale root, breaking everything that follows.
            raise RatchetError(
                "message belongs to a previous DH chain and was already "
                "processed (stale replay)"
            )

        if peer_dh != self.peer_dh_public:
            self._skip_to(header["pn"])
            self._dh_ratchet(peer_dh)
        elif n < self.recv_count:
            raise RatchetError(
                f"message {n} on this chain was already processed (replay or duplicate)"
            )

        self._skip_to(n)

        if self.receiving_chain is None:
            raise RatchetError("no receiving chain established")

        self.receiving_chain, message_key = _kdf_ck(self.receiving_chain)
        self.recv_count += 1
        return self._open(message_key, nonce, ciphertext, associated_data)

    # ---- internals ----------------------------------------------------

    @staticmethod
    def _parse(packet: dict) -> tuple:
        try:
            header = packet["hdr"]
            body = packet["body"]
            nonce = base64.b64decode(body["nonce"].encode())
            ciphertext = base64.b64decode(body["ct"].encode())
            if not isinstance(header["n"], int) or not isinstance(header["pn"], int):
                raise RatchetError("header counters must be integers")
            if header["n"] < 0 or header["pn"] < 0:
                raise RatchetError("header counters must not be negative")
            base64.b64decode(header["dh"])
        except RatchetError:
            raise
        except Exception as exc:
            raise RatchetError(f"malformed packet: {exc}") from exc
        return header, nonce, ciphertext

    @staticmethod
    def _open(message_key, nonce, ciphertext, associated_data) -> bytes:
        try:
            return aead_decrypt(message_key, nonce, ciphertext, associated_data)
        except CryptoError as exc:
            raise RatchetError(
                "authentication failed: the message or its header was altered"
            ) from exc

    def _skip_to(self, until: int) -> None:
        """
        Derive and retain the message keys for everything between the current
        counter and `until`, so those messages can still be read when they
        arrive. Bounded to keep a forged counter from becoming a denial of
        service.
        """
        if until <= self.recv_count:
            return
        if until - self.recv_count > MAX_SKIP:
            raise RatchetError(
                f"header claims {until - self.recv_count} skipped messages, "
                f"limit is {MAX_SKIP}"
            )
        if self.receiving_chain is None:
            raise RatchetError("cannot skip messages without a receiving chain")

        while self.recv_count < until:
            self.receiving_chain, message_key = _kdf_ck(self.receiving_chain)
            self.skipped[(self.peer_dh_public, self.recv_count)] = message_key
            self.recv_count += 1

        self._trim_skipped()

    def _trim_skipped(self) -> None:
        # dicts preserve insertion order, so this drops the oldest first.
        while len(self.skipped) > MAX_SKIPPED_KEYS:
            self.skipped.pop(next(iter(self.skipped)))

    def _trim_retired(self) -> None:
        while len(self.retired_dh) > MAX_RETIRED_DH:
            self.retired_dh.pop(next(iter(self.retired_dh)))

    def _dh_ratchet(self, peer_dh: bytes) -> None:
        """One full DH ratchet step: new receiving chain, then new sending chain."""
        self.previous_chain_length = self.send_count
        self.send_count = 0
        self.recv_count = 0
        if self.peer_dh_public is not None:
            self.retired_dh[self.peer_dh_public] = None
            self._trim_retired()
        self.peer_dh_public = peer_dh

        self.root_key, self.receiving_chain = _kdf_rk(self.root_key, dh(self.dh_pair, peer_dh))
        self.dh_pair = PrivateKey.generate()
        self.root_key, self.sending_chain = _kdf_rk(self.root_key, dh(self.dh_pair, peer_dh))
