from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import os
import base64

# The encrypter function:
# takes in a key and a message as parameters and returns a string
def encrypt_message(key: bytes, message: str) -> str:
    
    # generate the random 16-byte intilization vector
    iv = os.urandom(16)

    # create the cipher
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # pad the message
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_message = padder.update(message.encode()) + padder.finalize()

    # Encrypt the padded message
    encrypted_message = encryptor.update(padded_message) + encryptor.finalize()
    
    # Return the IV and the encrypted message, both base64 encoded
    return base64.b64encode(iv + encrypted_message).decode('utf-8')

# the decrypter function
def decrypt_message(key: bytes, encrypted_message: str) -> str:

    encrypted_data = base64.b64decode(encrypted_message)
    iv = encrypted_data[:16]
    ciphered_message = encrypted_data[16:]
    
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    
    padded_message = decryptor.update(ciphered_message) + decryptor.finalize()
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    message = unpadder.update(padded_message) + unpadder.finalize()
    
    return message.decode('utf-8')

if __name__ == "__main__":
    # Ask user for the message
    original_message = input("Enter the message to encrypt: ")

    # Generate a random key (32 bytes)
    key = os.urandom(32)
    print(f"Encryption Key (share this securely): {base64.b64encode(key).decode('utf-8')}")

    # Encrypt the message
    encrypted_message = encrypt_message(key, original_message)
    print(f"Encrypted Message: {encrypted_message}")

    # Ask user for the key to decrypt
    while True:
        key_input = input("Enter the encryption key to decrypt (in base64): ")
        try:
            key = base64.b64decode(key_input)
            if len(key) not in {16, 24, 32}:
                raise ValueError("Key must be 16, 24, or 32 bytes after decoding.")
            break
        except (ValueError, base64.binascii.Error) as e:
            print(f"Error: {e}. Please enter a valid base64-encoded key.")

    # Decrypt the message
    try:
        decrypted_message = decrypt_message(key, encrypted_message)
        print(f"Decrypted Message: {decrypted_message}")
    except Exception as e:
        print(f"Decryption failed: {e}")