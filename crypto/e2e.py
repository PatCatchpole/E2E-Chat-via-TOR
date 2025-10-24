from nacl.public import PrivateKey, Box
from nacl.encoding import Base64Encoder

def generate_keypair():
    private_key = PrivateKey.generate()
    public_key = private_key.public_key
    return private_key, public_key

def encrypt_message(sender_private_key, recipient_public_key, message):
    box = Box(sender_private_key, recipient_public_key)
    encrypted = box.encrypt(message.encode(), encoder=Base64Encoder)
    return encrypted.decode()

def decrypt_message(recipient_private_key, sender_public_key, encrypted_message):
    box = Box(recipient_private_key, sender_public_key)
    decrypted = box.decrypt(encrypted_message.encode(), encoder=Base64Encoder)
    return decrypted.decode()
