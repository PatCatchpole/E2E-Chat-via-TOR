from nacl.public import PrivateKey, PublicKey
from nacl.bindings import crypto_scalarmult
from nacl.hash import blake2b
from nacl.encoding import RawEncoder
import hmac
import hashlib

def dh(private_key: PrivateKey, public_key: PublicKey) -> bytes:
    """X25519 DH => 32-byte shared secret."""
    return crypto_scalarmult(private_key.encode(), public_key.encode())

def kdf_chain(chain_key: bytes) -> (bytes, bytes):
    """
    Symmetric-chain ratchet:
    Returns (next_chain_key, one_time_message_key)
    """
    next_chain_key = hmac.new(chain_key, b"chain", hashlib.sha256).digest()
    message_key    = hmac.new(chain_key, b"msg",   hashlib.sha256).digest()
    return next_chain_key, message_key

def kdf_root(root_key: bytes, dh_output: bytes) -> (bytes, bytes):
    """
    Root-key KDF:
    Returns (new_root_key, base_chain_key_seed)
    """
    combined = root_key + dh_output
    new_root_key  = blake2b(combined + b"root",  encoder=RawEncoder)
    base_chain    = blake2b(combined + b"base",  encoder=RawEncoder)
    return new_root_key, base_chain

def kdf_direction(seed: bytes, label: bytes) -> bytes:
    """
    Split base chain into directional send/recv chain keys deterministically.
    """
    return blake2b(seed + label, encoder=RawEncoder)

class ChainState:
    def __init__(self, chain_key: bytes):
        self.chain_key = chain_key
        self.index = 0

    def next_message_key(self) -> bytes:
        self.chain_key, message_key = kdf_chain(self.chain_key)
        self.index += 1
        return message_key

class RatchetState:
    """
    Holds:
      - root_key
      - our current DH keypair
      - their current DH public key (last seen)
      - sending_chain / receiving_chain
      - is_initiator: assigns who starts with which direction
    """
    def __init__(self, root_key: bytes, dh_keypair: PrivateKey, their_dh_pub: PublicKey, *, is_initiator: bool):
        self.root_key = root_key
        self.dh_keypair = dh_keypair
        self.their_dh_pub = their_dh_pub
        self.is_initiator = is_initiator

        dh_out = dh(self.dh_keypair, self.their_dh_pub)
        self.root_key, base_seed = kdf_root(self.root_key, dh_out)

        if self.is_initiator:
            send_ck = kdf_direction(base_seed, b"SEND")
            recv_ck = kdf_direction(base_seed, b"RECV")
        else:
            send_ck = kdf_direction(base_seed, b"RECV")
            recv_ck = kdf_direction(base_seed, b"SEND")

        self.sending_chain   = ChainState(send_ck)
        self.receiving_chain = ChainState(recv_ck)

    def receive_header_and_ratchet_if_needed(self, peer_dh_pub: PublicKey):
        """
        On receiving a packet, check if peer rotated DH.
        If so, perform RECEIVE-SIDE DH ratchet:
          1) Derive receiving chain using OLD local priv + NEW remote pub
          2) Update their_dh_pub to the new one
          3) Rotate our local DH and derive a fresh SENDING chain
        """
        if peer_dh_pub.encode() == self.their_dh_pub.encode():
            return  # no DH change; keep current chains

        # 1) New receiving chain from old local priv and new peer pub
        dh_out_recv = dh(self.dh_keypair, peer_dh_pub)
        self.root_key, base_seed = kdf_root(self.root_key, dh_out_recv)

        # Directional split for receiving chain after peer’s rotation:
        # The direction labels remain consistent with our role.
        recv_ck = kdf_direction(base_seed, b"RECV" if self.is_initiator else b"SEND")
        self.receiving_chain = ChainState(recv_ck)

        # Update stored peer pub now
        self.their_dh_pub = peer_dh_pub

        # 2) Rotate our local DH and prepare a NEW sending chain
        self.dh_keypair = PrivateKey.generate()
        dh_out_send = dh(self.dh_keypair, self.their_dh_pub)
        self.root_key, base_seed2 = kdf_root(self.root_key, dh_out_send)
        send_ck = kdf_direction(base_seed2, b"SEND" if self.is_initiator else b"RECV")
        self.sending_chain = ChainState(send_ck)

    def initiate_sending_ratchet(self) -> PublicKey:
        """
        When WE decide to rotate before sending:
          - Generate new local DH
          - Derive a new SENDING chain against current peer DH pub
          - Return our new pub for the message header
        """
        self.dh_keypair = PrivateKey.generate()
        dh_out = dh(self.dh_keypair, self.their_dh_pub)
        self.root_key, base_seed = kdf_root(self.root_key, dh_out)
        send_ck = kdf_direction(base_seed, b"SEND" if self.is_initiator else b"RECV")
        self.sending_chain = ChainState(send_ck)
        return self.dh_keypair.public_key
