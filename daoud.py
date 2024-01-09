from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from base64 import b64encode, b64decode
import os

def encrypt_with_rsa(public_key, plaintext):
    ciphertext = public_key.encrypt(
        plaintext.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return b64encode(ciphertext).decode()

def encrypt_with_aes(key, plaintext):
    # Generate a random IV for each encryption operation
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    encryptor = cipher.encryptor()

    # Add padding to the plaintext if needed
    padded_plaintext = plaintext.encode() + b'\x00' * (16 - (len(plaintext) % 16))

    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
    return b64encode(iv + ciphertext).decode()

# Get user input for the message
original_message = input("Enter your message: ")

# Generate AES key (in a real-world scenario, securely manage and share this key)
aes_key = b'0123456789ABCDEF'
print("the AES key in our case will be fixed to be ",aes_key)
with open("key.txt", "rb") as key_file:
    public_key = serialization.load_pem_public_key(key_file.read())
    print("Public key of Chadi is loaded successfully and it is ", public_key)
# Encrypt with AES key
encrypted_aes = encrypt_with_aes(aes_key, original_message)
print("Encrypted with AES: ", encrypted_aes)
# Encrypt with RSA public key
encrypted_rsa = encrypt_with_rsa(public_key, encrypted_aes)
print("Encrypted with RSA: ", encrypted_rsa)

with open("message.txt", "w") as file:
    file.write(encrypted_rsa)
    print("Message is sent successfully and it is waiting to be received...")
    
input("Press Enter to exit...")
