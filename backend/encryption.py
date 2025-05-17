from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64
import os

class AesEncryption:
    @staticmethod
    def encrypt(message, key):
        # Ensure the key is the correct length
        if len(key.encode()) not in {16, 24, 32}:  # Valid key lengths for AES
            raise ValueError("Invalid AES key length. Key must be 16, 24, or 32 bytes.")
        
        iv = os.urandom(16)  # Generate a random Initialization Vector (IV)
        cipher = AES.new(key.encode(), AES.MODE_CBC, iv)  # Create cipher object
        encrypted_message = cipher.encrypt(pad(message.encode(), AES.block_size))
        
        # Combine the IV and the encrypted message and encode it in base64 for easy transmission
        return base64.b64encode(iv + encrypted_message).decode('utf-8')

    @staticmethod
    def decrypt(encrypted_message, key):
        # Ensure the key is the correct length
        if len(key.encode()) not in {16, 24, 32}:  # Valid key lengths for AES
            raise ValueError("Invalid AES key length. Key must be 16, 24, or 32 bytes.")
        
        data = base64.b64decode(encrypted_message)  # Decode from base64
        iv = data[:16]  # Extract the IV from the beginning
        encrypted_message = data[16:]  # Extract the encrypted part of the message

        cipher = AES.new(key.encode(), AES.MODE_CBC, iv)  # Recreate the cipher object
        decrypted_message = unpad(cipher.decrypt(encrypted_message), AES.block_size)

        return decrypted_message.decode('utf-8')  # Return the decrypted message as a string
