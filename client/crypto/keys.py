from nacl.public import PrivateKey, PublicKey
from nacl.encoding import Base64Encoder
import os

EPHEMERAL_KEY_PATH = "crypto/ephemeral_key"

def generate_identity_keypair(key_path=None):
    """
    Generate or load an identity keypair.
    If key_path is None, always generate a new keypair (for unique sessions).
    """
    if key_path and os.path.exists(key_path):
        with open(key_path, 'rb') as f:
            private_key = PrivateKey(f.read())
    else:
        private_key = PrivateKey.generate()
        if key_path:
            with open(key_path, 'wb') as f:
                f.write(private_key.encode())
    return private_key, private_key.public_key

def generate_ephemeral_keypair(key_path=None):
    """
    Always generate a new ephemeral keypair.
    """
    private_key = PrivateKey.generate()
    if key_path:
        with open(key_path, 'wb') as f:
            f.write(private_key.encode())
    return private_key, private_key.public_key

def export_public_key(public_key):
    return public_key.encode(encoder=Base64Encoder).decode()

def import_public_key(public_key_b64):
    return PublicKey(public_key_b64.encode(), encoder=Base64Encoder)
