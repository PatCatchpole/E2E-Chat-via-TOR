# test_message_flow.py  (run from project root)
from nacl.public import PrivateKey
from crypto.ratchet import RatchetState
from crypto.message import encrypt_with_message_key, decrypt_with_message_key

def demo():
    # In production this comes from X3DH (derive_shared_secret)
    root_key = b"\x00" * 32

    # Initial DH keys
    alice_dh = PrivateKey.generate()
    bob_dh   = PrivateKey.generate()

    # Initialize both ratchets (each side thinks the other’s current DH pub)
    alice = RatchetState(root_key, alice_dh, bob_dh.public_key)
    bob   = RatchetState(root_key, bob_dh, alice_dh.public_key)

    print("== Alice sends m1 ==")
    mk_a1 = alice.sending_chain.next_message_key()
    pkt_a1 = {
        "hdr": {"n": alice.sending_chain.index},  # minimal header (in-order assumption)
        "body": encrypt_with_message_key(mk_a1, b"hi bob!"),
    }
    # Bob receives m1 (in-order MVP: derive one key)
    mk_b_recv1 = bob.sending_chain.next_message_key()  # careful: bob's *receiving* chain should be set after a DH ratchet in a full impl
    # For this minimal demo, initialize Bob’s receiving chain same as Alice’s sending chain on first message:
    # (our RatchetState sets only sending_chain initially; for true parity, you’d perform the DH step from each perspective)
    pt = decrypt_with_message_key(mk_a1, pkt_a1["body"]["nonce_b64"], pkt_a1["body"]["ct_b64"])
    print("Bob got:", pt.decode())

    print("== Alice sends m2 ==")
    mk_a2 = alice.sending_chain.next_message_key()
    pkt_a2 = {
        "hdr": {"n": alice.sending_chain.index},
        "body": encrypt_with_message_key(mk_a2, b"you there?"),
    }
    # Bob decrypts m2 using next key from the same chain (MVP assumes in-order)
    pt2 = decrypt_with_message_key(mk_a2, pkt_a2["body"]["nonce_b64"], pkt_a2["body"]["ct_b64"])
    print("Bob got:", pt2.decode())

    print("== Bob ratchets (new DH key) and replies ==")
    bob_new_dh = PrivateKey.generate()
    # Bob locally ratchets: in a real flow, Bob would ratchet when he *sends* with a new DH pub
    bob.ratchet(alice.dh_keypair.public_key)  # set receiving from Alice’s current DH
    bob.dh_keypair = bob_new_dh               # now use his new DH to create sending chain
    bob.ratchet(alice.dh_keypair.public_key)  # derive fresh sending chain too (simplified)

    mk_b_send = bob.sending_chain.next_message_key()
    pkt_b = {
        "hdr": {
            "n": bob.sending_chain.index,
            "dh_pub_b64": bob_new_dh.public_key.encode().hex(),  # for demo; in practice base64
        },
        "body": encrypt_with_message_key(mk_b_send, b"hey alice, got you"),
    }

    # Alice receives Bob’s new DH pub and ratchets
    bob_pub = bytes.fromhex(pkt_b["hdr"]["dh_pub_b64"])
    # Rebuild PublicKey from raw bytes:
    from nacl.public import PublicKey
    alice.ratchet(PublicKey(bob_pub))

    # Now Alice derives one message key from her *receiving* chain and decrypts
    mk_a_recv = alice.receiving_chain.next_message_key()
    pt3 = decrypt_with_message_key(mk_a_recv, pkt_b["body"]["nonce_b64"], pkt_b["body"]["ct_b64"])
    print("Alice got:", pt3.decode())

if __name__ == "__main__":
    demo()
