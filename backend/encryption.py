# encryption.py

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Util.Padding import pad, unpad
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256 # Explicitly import SHA256 for OAEP
import base64
import os

class RSAEncryption:
    """Handles RSA public/private key generation, encryption, and decryption."""

    @staticmethod
    def generate_keys():
        """Generates a new 2048-bit RSA key pair.

        Returns:
            tuple: (public_key_pem_string, private_key_pem_string)
        """
        key = RSA.generate(2048)
        private_key = key.export_key().decode('utf-8')
        public_key = key.publickey().export_key().decode('utf-8')
        return public_key, private_key

    @staticmethod
    def encrypt_with_public_key(message: str, public_key_str: str) -> str:
        """Encrypts a message using an RSA public key (OAEP padding).

        Args:
            message (str): The plaintext message to encrypt.
            public_key_str (str): The RSA public key in PEM string format.

        Returns:
            str: Base64 encoded ciphertext.
        """
        public_key = RSA.import_key(public_key_str.encode('utf-8'))
        # Explicitly use SHA256 for OAEP padding to match frontend
        cipher = PKCS1_OAEP.new(public_key, hashAlgo=SHA256)
        encrypted = cipher.encrypt(message.encode('utf-8'))
        return base64.b64encode(encrypted).decode('utf-8')

    @staticmethod
    def decrypt_with_private_key(encrypted_message_b64: str, private_key_str: str) -> str:
        """Decrypts a base64 encoded ciphertext using an RSA private key (OAEP padding).

        Args:
            encrypted_message_b64 (str): Base64 encoded ciphertext.
            private_key_str (str): The RSA private key in PEM string format.

        Returns:
            str: Decrypted plaintext message.
        """
        private_key = RSA.import_key(private_key_str.encode('utf-8'))
        # Explicitly use SHA256 for OAEP padding to match frontend
        cipher = PKCS1_OAEP.new(private_key, hashAlgo=SHA256)
        try:
            decrypted = cipher.decrypt(base64.b64decode(encrypted_message_b64))
            return decrypted.decode('utf-8')
        except ValueError as e:
            print(f"❌ Decryption Error (RSA): {e}")
            raise # Re-raise to propagate the error

class AesEncryption:
    """Handles AES symmetric encryption and decryption (CBC mode)."""

    @staticmethod
    def encrypt(message: str, key: str) -> str:
        """Encrypts a message using AES-CBC with a given key.

        Args:
            message (str): The plaintext message to encrypt.
            key (str): The symmetric AES key (16, 24, or 32 bytes).

        Returns:
            str: Base64 encoded IV + ciphertext.
        """
        key_bytes = key.encode('utf-8')
        if len(key_bytes) not in {16, 24, 32}:
            raise ValueError(f"Invalid AES key length. Key must be 16, 24, or 32 bytes. Got {len(key_bytes)} bytes.")

        iv = os.urandom(16)
        cipher = AES.new(key_bytes, AES.MODE_CBC, iv)
        encrypted_message = cipher.encrypt(pad(message.encode('utf-8'), AES.block_size))

        return base64.b64encode(iv + encrypted_message).decode('utf-8')

    @staticmethod
    def decrypt(encrypted_message_b64: str, key: str) -> str:
        """Decrypts a base64 encoded ciphertext using AES-CBC with a given key.

        Args:
            encrypted_message_b64 (str): Base64 encoded IV + ciphertext.
            key (str): The symmetric AES key (16, 24, or 32 bytes).

        Returns:
            str: Decrypted plaintext message.
        """
        key_bytes = key.encode('utf-8')
        if len(key_bytes) not in {16, 24, 32}:
            raise ValueError(f"Invalid AES key length. Key must be 16, 24, or 32 bytes. Got {len(key_bytes)} bytes.")

        try:
            data = base64.b64decode(encrypted_message_b64)
            iv = data[:16]
            ciphertext = data[16:]
            cipher = AES.new(key_bytes, AES.MODE_CBC, iv)
            decrypted = unpad(cipher.decrypt(ciphertext), AES.block_size)
            return decrypted.decode('utf-8')
        except (ValueError, IndexError) as e:
            print(f"❌ Decryption Error (AES): {e}")
            raise
