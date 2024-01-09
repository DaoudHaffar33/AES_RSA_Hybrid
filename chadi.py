from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from base64 import b64encode, b64decode
import os

def generate_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()

    return private_key, public_key

def decrypt_with_rsa(private_key, ciphertext):
    decrypted = private_key.decrypt(
        b64decode(ciphertext),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted.decode()

def decrypt_with_aes(key, ciphertext):
    data = b64decode(ciphertext)
    iv = data[:16]
    ciphertext = data[16:]
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    decryptor = cipher.decryptor()
    decrypted = decryptor.update(ciphertext) + decryptor.finalize()
    # Remove padding after decryption
    unpadded_decrypted = decrypted.rstrip(b'\x00')
    return unpadded_decrypted.decode()

# Example usage:
private_key, public_key = generate_key_pair()
print("RSA public key is ",private_key)
print("RSA private key is (should not be shared usually but shown for demonstration) ",private_key)
# Generate AES key (in a real-world scenario, securely manage and share this key)
aes_key = b'0123456789ABCDEF'
print("AES key is (should not be shared usually but shown for demonstration) ",aes_key)

input("Press a key to Share your generated public key...")

with open("key.txt", "wb") as keyFile:
    keyFile.write(public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ))

input("Press a key when you're ready to decrypt a delivered message...")

# Get user input for the message
with open("message.txt", "r") as file:
    encrypted_rsa = file.read()


# Decrypt with RSA private key
decrypted_rsa = decrypt_with_rsa(private_key, encrypted_rsa)
print("Decrypted with RSA:", decrypted_rsa)
# Decrypt with AES key
decrypted_aes = decrypt_with_aes(aes_key, decrypted_rsa)
print("original message after Decrypting it again with AES is:", decrypted_aes)

input("Press Enter to exit...")