# backend/encryption/diffie_hellman.py

from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.hashes import SHA256

class DiffieHellman:
    def __init__(self):
        self.parameters = dh.generate_parameters(generator=2, key_size=2048)

    def generate_private_key(self):
        return self.parameters.generate_private_key()

    def generate_shared_key(self, private_key, peer_public_key):
        shared_key = private_key.exchange(peer_public_key)
        derived_key = HKDF(algorithm=SHA256(), length=32, salt=None, info=b'handshake').derive(shared_key)
        return derived_key
