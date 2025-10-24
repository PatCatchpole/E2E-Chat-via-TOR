from nacl.public import PrivateKey, PublicKey
from nacl.encoding import Base64Encoder
import os

IDENTITY_KEY_PATH = "crypto/identity_key"
EPHEMERAL_KEY_PATH = "crypto/ephemeral_key"

def generate_identity_keypair():
    if os.path.exists(IDENTITY_KEY_PATH):
        with open(IDENTITY_KEY_PATH, 'rb') as f:
            private_key = PrivateKey(f.read())
    else:
        private_key = PrivateKey.generate()
        with open(IDENTITY_KEY_PATH, 'wb') as f:
            f.write(private_key.encode())
    return private_key, private_key.public_key

def generate_ephemeral_keypair():
    private_key = PrivateKey.generate()
    with open(EPHEMERAL_KEY_PATH, 'wb') as f:
        f.write(private_key.encode())
    return private_key, private_key.public_key

def export_public_key(public_key):
    return public_key.encode(encoder=Base64Encoder).decode()

def import_public_key(public_key_b64):
    return PublicKey(public_key_b64.encode(), encoder=Base64Encoder)
