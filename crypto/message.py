from nacl.secret import SecretBox
from nacl.utils import random as nacl_random
from nacl.encoding import Base64Encoder

# ----- Minimal message header -----
# You'll normally include:
#   - dh_pub (sender's current DH ratchet public key, base64)
#   - n      (message number in this sending chain)
#   - pn     (previous chain length before last DH ratchet)  [optional for MVP]
# For MVP we send just 'n'; you can extend later.

def encrypt_with_message_key(message_key: bytes, plaintext: bytes, ad: bytes | None = None) -> dict:
    """
    Encrypts plaintext with a one-time message_key derived from the chain.
    Returns a dict you can JSON-serialize and send over the wire.
    """
    box = SecretBox(message_key)
    nonce = nacl_random(SecretBox.NONCE_SIZE)
    # Encrypt with AEAD
    ciphertext = box.encrypt(plaintext, nonce)
    # box.encrypt returns nonce + ciphertext combined, but we want them separate
    # Extract just the ciphertext part (skip the nonce prefix)
    ct_only = ciphertext[SecretBox.NONCE_SIZE:]
    return {
        "nonce_b64": Base64Encoder.encode(nonce).decode(),
        "ct_b64": Base64Encoder.encode(ct_only).decode()
    }

def decrypt_with_message_key(message_key: bytes, nonce_b64: str, ct_b64: str, ad: bytes | None = None) -> bytes:
    """
    Decrypts using the given message_key.
    Raises CryptoError if auth fails.
    """
    box = SecretBox(message_key)
    nonce = Base64Encoder.decode(nonce_b64)
    ct = Base64Encoder.decode(ct_b64)
    # SecretBox.decrypt expects nonce + ciphertext combined
    combined = nonce + ct
    return box.decrypt(combined)
