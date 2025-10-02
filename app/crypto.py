import os
from nacl.public import PrivateKey, PublicKey, Box
from nacl.encoding import Base64Encoder

KEYFILE = "identity_key.pem"

def generate_keypair():
    sk = PrivateKey.generate()
    pk = sk.public_key
    return sk, pk

def save_keypair(sk: PrivateKey, filename=KEYFILE):
    with open(filename, "wb") as f:
        f.write(sk.encode(encoder=Base64Encoder))

def load_keypair(filename=KEYFILE):
    if not os.path.exists(filename):
        raise FileNotFoundError(filename)
    with open(filename, "rb") as f:
        b64 = f.read().strip()
    sk = PrivateKey(b64, encoder=Base64Encoder)
    return sk, sk.public_key

def pk_to_b64(pk: PublicKey) -> str:
    return pk.encode(encoder=Base64Encoder).decode()

def b64_to_pk(b64: str) -> PublicKey:
    return PublicKey(b64.encode(), encoder=Base64Encoder)

def encrypt_with(recipient_pk: PublicKey, sender_sk: PrivateKey, plaintext: str) -> bytes:
    box = Box(sender_sk, recipient_pk)
    return box.encrypt(plaintext.encode())

def decrypt_with(recipient_sk: PrivateKey, sender_pk: PublicKey, ciphertext: bytes) -> str:
    box = Box(recipient_sk, sender_pk)
    return box.decrypt(ciphertext).decode()
