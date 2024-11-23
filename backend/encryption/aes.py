# backend/encryption/aes.py

from Crypto.Cipher import AES
import base64
import os

class AESCipher:
    def __init__(self, key=None):
        self.key = key or os.urandom(16)  # 128-bit key

    def encrypt(self, data):
        cipher = AES.new(self.key, AES.MODE_EAX)
        ciphertext, tag = cipher.encrypt_and_digest(data.encode('utf-8'))
        return base64.b64encode(cipher.nonce + tag + ciphertext).decode('utf-8')

    def decrypt(self, data):
        raw_data = base64.b64decode(data)
        nonce, tag, ciphertext = raw_data[:16], raw_data[16:32], raw_data[32:]
        cipher = AES.new(self.key, AES.MODE_EAX, nonce=nonce)
        return cipher.decrypt_and_verify(ciphertext, tag).decode('utf-8')
