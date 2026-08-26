"""
Password verifier derivation.

The original scheme sent a locally-generated bcrypt hash and the backend
compared it with string equality. That made the stored hash itself the
credential: anyone who read the database could log in directly, and because
bcrypt salts randomly, a user who lost `~/.spectre` could never reproduce their
own hash and was locked out for good.

What happens now:

  client   verifier = PBKDF2-SHA256(password, salt = H(username), 200k)
  backend  stored   = bcrypt(verifier, random salt)   and verifies with bcrypt

The client salt is derived from the username so the verifier is reproducible on
any machine, and the plaintext password never leaves the client. The backend
applies its own randomly-salted bcrypt, so the stored value is not replayable
as a login credential.
"""

from __future__ import annotations

import base64
import hashlib

from crypto.kdf import hkdf

PBKDF2_ITERATIONS = 200_000
SALT_INFO = b"SpectreProtocol/password-salt/v1"


def derive_verifier(username: str, password: str) -> str:
    """
    The value sent to the server in place of a password. Deterministic for a
    given (username, password) pair, and expensive to brute-force.
    """
    if not username:
        raise ValueError("username is required to derive a password verifier")

    salt = hkdf(username.encode(), info=SALT_INFO, length=16)
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS, dklen=32
    )
    return base64.b64encode(digest).decode()
