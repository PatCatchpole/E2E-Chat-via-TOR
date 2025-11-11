# test_dh_ratchet_flow_ok.py
from nacl.public import PrivateKey, PublicKey
from nacl.encoding import Base64Encoder
from crypto.ratchet import RatchetState
from crypto.message import encrypt_with_message_key, decrypt_with_message_key

def b64_pubkey(pk: PublicKey) -> str:
    return Base64Encoder.encode(pk.encode()).decode()

def decode_pubkey(b64: str) -> PublicKey:
    return PublicKey(Base64Encoder.decode(b64))

def demo():
    root_key = b"\x00" * 32  # stand-in for X3DH output
    alice_dh = PrivateKey.generate()
    bob_dh   = PrivateKey.generate()

    alice = RatchetState(root_key, alice_dh, bob_dh.public_key, is_initiator=True)
    bob   = RatchetState(root_key, bob_dh, alice_dh.public_key, is_initiator=False)

    # ---- Alice -> Bob (m1)
    print("== Alice sends m1 ==")
    mk_a1 = alice.sending_chain.next_message_key()
    pkt_a1 = {
        "hdr": {"dh_pub_b64": b64_pubkey(alice.dh_keypair.public_key), "n": alice.sending_chain.index},
        "body": encrypt_with_message_key(mk_a1, b"hi bob!")
    }
    # Receive path: same DH, so no ratchet; just advance RECEIVING chain
    bob.receive_header_and_ratchet_if_needed(decode_pubkey(pkt_a1["hdr"]["dh_pub_b64"]))
    mk_b_recv1 = bob.receiving_chain.next_message_key()
    pt1 = decrypt_with_message_key(mk_b_recv1, pkt_a1["body"]["nonce_b64"], pkt_a1["body"]["ct_b64"])
    print("Bob got:", pt1.decode())

    # ---- Bob rotates DH and replies (initiate send ratchet)
    print("== Bob ratchets (new DH) and replies ==")
    bob_new_pub = bob.initiate_sending_ratchet()
    mk_b_send = bob.sending_chain.next_message_key()
    pkt_b = {
        "hdr": {"dh_pub_b64": b64_pubkey(bob_new_pub), "n": bob.sending_chain.index},
        "body": encrypt_with_message_key(mk_b_send, b"hey alice, got you")
    }

    # Alice sees new DH in header -> RECEIVE-SIDE ratchet THEN advance RECEIVING chain
    alice.receive_header_and_ratchet_if_needed(decode_pubkey(pkt_b["hdr"]["dh_pub_b64"]))
    mk_a_recv = alice.receiving_chain.next_message_key()
    pt2 = decrypt_with_message_key(mk_a_recv, pkt_b["body"]["nonce_b64"], pkt_b["body"]["ct_b64"])
    print("Alice got:", pt2.decode())

if __name__ == "__main__":
    demo()
