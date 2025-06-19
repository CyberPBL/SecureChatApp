# --- Updated encryption.py with AES-GCM Support ---

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Util.Padding import pad, unpad
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
import base64
import os

class RSAEncryption:
    @staticmethod
    def generate_keys():
        key = RSA.generate(2048)
        private_key = key.export_key().decode('utf-8')
        public_key = key.publickey().export_key().decode('utf-8')
        return public_key, private_key

    @staticmethod
    def encrypt_with_public_key(message: str, public_key_str: str) -> str:
        public_key = RSA.import_key(public_key_str.encode('utf-8'))
        cipher = PKCS1_OAEP.new(public_key, hashAlgo=SHA256)
        encrypted = cipher.encrypt(message.encode('utf-8'))
        return base64.b64encode(encrypted).decode('utf-8')

    @staticmethod
    def decrypt_with_private_key(encrypted_message_b64: str, private_key_str: str) -> str:
        private_key = RSA.import_key(private_key_str.encode('utf-8'))
        cipher = PKCS1_OAEP.new(private_key, hashAlgo=SHA256)
        try:
            decrypted = cipher.decrypt(base64.b64decode(encrypted_message_b64))
            return decrypted.decode('utf-8')
        except ValueError as e:
            print(f"❌ Decryption Error (RSA): {e}")
            raise

class AesEncryption:
    @staticmethod
    def encrypt(message: str, key: str) -> str:
        key_bytes = key.encode('utf-8')
        if len(key_bytes) != 32:
            raise ValueError("AES-GCM key must be 32 bytes for AES-256.")

        iv = os.urandom(12)  # 12 bytes IV for GCM
        cipher = AES.new(key_bytes, AES.MODE_GCM, nonce=iv)
        ciphertext, tag = cipher.encrypt_and_digest(message.encode('utf-8'))
        payload = iv + tag + ciphertext
        return base64.b64encode(payload).decode('utf-8')

    @staticmethod
    def decrypt(encrypted_message_b64: str, key: str) -> str:
        key_bytes = key.encode('utf-8')
        if len(key_bytes) != 32:
            raise ValueError("AES-GCM key must be 32 bytes for AES-256.")

        data = base64.b64decode(encrypted_message_b64)
        iv = data[:12]
        tag = data[12:28]
        ciphertext = data[28:]

        cipher = AES.new(key_bytes, AES.MODE_GCM, nonce=iv)
        try:
            decrypted = cipher.decrypt_and_verify(ciphertext, tag)
            return decrypted.decode('utf-8')
        except Exception as e:
            print(f"❌ Decryption Error (AES-GCM): {e}")
            raise
