from nacl.bindings import crypto_scalarmult
from nacl.public import PrivateKey, PublicKey
from nacl.hash import blake2b
from nacl.encoding import RawEncoder

def dh(private_key: PrivateKey, public_key: PublicKey) -> bytes:
    """Perform a Diffie-Hellman operation."""
    return crypto_scalarmult(private_key.encode(), public_key.encode())

def kdf(inputs: bytes, salt: bytes = b"SpectreProtocol") -> bytes:
    """Key derivation function using BLAKE2b."""
    return blake2b(inputs + salt, encoder=RawEncoder)

def derive_shared_secret(initiator_priv_id: PrivateKey,
                         initiator_priv_eph: PrivateKey,
                         responder_pub_id: PublicKey,
                         responder_pub_eph: PublicKey) -> bytes:
    """
    Performs 3-DH X3DH-like key agreement and return a derived shared secret.

    Arguments:
        initiator_priv_id: Our identity private key
        initiator_priv_eph: Our ephemeral private key
        responder_pub_id: Their identity public key
        responder_pub_eph: Their ephemeral public key

    Returns:
        32-byte shared secret (HKDF output)
    """
    dh1 = dh(initiator_priv_id, responder_pub_id)
    dh2 = dh(initiator_priv_eph, responder_pub_id)
    dh3 = dh(initiator_priv_id, responder_pub_eph)

    combined = dh1 + dh2 + dh3
    return kdf(combined)
