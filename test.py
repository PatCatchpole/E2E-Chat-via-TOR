from crypto.keys import generate_identity_keypair, generate_ephemeral_keypair
from crypto.x3dh import derive_shared_secret,dh, kdf

# Alice's keys
sk_id_a, pk_id_a = generate_identity_keypair()
sk_eph_a, pk_eph_a = generate_ephemeral_keypair()

# Bob's keys
sk_id_b, pk_id_b = generate_identity_keypair()
sk_eph_b, pk_eph_b = generate_ephemeral_keypair()

# Alice derives shared secret
shared_a = derive_shared_secret(sk_id_a, sk_eph_a, pk_id_b, pk_eph_b)

# Bob does the same (reverse the roles)

combined = dh(sk_id_b, pk_id_a) + dh(sk_id_b, pk_eph_a) + dh(sk_eph_b, pk_id_a)
shared_b = kdf(combined)

print("Match:", shared_a == shared_b)  # Should print: True