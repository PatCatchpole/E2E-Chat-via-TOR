from nacl.public import PrivateKey
from crypto.ratchet import RatchetState

# Example setup
alice_root = b"0" * 32
alice_priv = PrivateKey.generate()
bob_priv   = PrivateKey.generate()

state = RatchetState(alice_root, alice_priv, bob_priv.public_key)
msg_key = state.sending_chain.next_message_key()
print("First message key:", msg_key.hex()[:16])
