import time
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import os
from ecies import encrypt, decrypt
from coincurve import PrivateKey, PublicKey


# Generate RSA and ECC keys
def generate_keys():
    # Generate RSA key pair
    rsa_key = RSA.generate(2048)
    # Generate ECC private key
    ecc_private_key = PrivateKey()
    # Derive ECC public key from the private key
    ecc_public_key = ecc_private_key.public_key
    return rsa_key, ecc_private_key, ecc_public_key


# Encrypt and decrypt file using RSA
def rsa_encrypt_decrypt(file_path, rsa_key):
    # Start timing the RSA encryption process
    start = time.time()
    # Create RSA cipher object with the public key
    cipher_rsa = PKCS1_OAEP.new(rsa_key.publickey())
    # Generate a random AES session key
    aes_key = get_random_bytes(16)
    # Read the plaintext from the file
    with open(file_path, "rb") as f:
        plaintext = f.read()
    # Encrypt the AES session key with RSA
    enc_session_key = cipher_rsa.encrypt(aes_key)
    # Create AES cipher object with the session key
    cipher_aes = AES.new(aes_key, AES.MODE_EAX)
    # Encrypt the plaintext with AES and pad it
    ciphertext, tag = cipher_aes.encrypt_and_digest(pad(plaintext, AES.block_size))
    # Calculate RSA encryption time
    rsa_encrypt_time = time.time() - start

    # Start timing the RSA decryption process
    start = time.time()
    # Create RSA cipher object with the private key
    cipher_rsa = PKCS1_OAEP.new(rsa_key)
    # Decrypt the AES session key with RSA
    aes_key = cipher_rsa.decrypt(enc_session_key)
    # Create AES cipher object with the decrypted session key and nonce
    cipher_aes = AES.new(aes_key, AES.MODE_EAX, nonce=cipher_aes.nonce)
    # Decrypt the ciphertext with AES and unpad it
    plaintext = unpad(cipher_aes.decrypt_and_verify(ciphertext, tag), AES.block_size)
    # Calculate RSA decryption time
    rsa_decrypt_time = time.time() - start

    return rsa_encrypt_time, rsa_decrypt_time


# Encrypt and decrypt file using ECC
def ecc_encrypt_decrypt(file_path, ecc_private_key, ecc_public_key):
    # Start timing the ECC encryption process
    start = time.time()
    # Generate a random AES session key
    aes_key = get_random_bytes(16)
    # Read the plaintext from the file
    with open(file_path, "rb") as f:
        plaintext = f.read()
    # Encrypt the AES session key with ECC
    enc_session_key = encrypt(ecc_public_key.format(True), aes_key)
    # Create AES cipher object with the session key
    cipher_aes = AES.new(aes_key, AES.MODE_EAX)
    # Encrypt the plaintext with AES and pad it
    ciphertext, tag = cipher_aes.encrypt_and_digest(pad(plaintext, AES.block_size))
    # Calculate ECC encryption time
    ecc_encrypt_time = time.time() - start

    # Start timing the ECC decryption process
    start = time.time()
    # Decrypt the AES session key with ECC
    aes_key = decrypt(ecc_private_key.to_hex(), enc_session_key)
    # Create AES cipher object with the decrypted session key and nonce
    cipher_aes = AES.new(aes_key, AES.MODE_EAX, nonce=cipher_aes.nonce)
    # Decrypt the ciphertext with AES and unpad it
    plaintext = unpad(cipher_aes.decrypt_and_verify(ciphertext, tag), AES.block_size)
    # Calculate ECC decryption time
    ecc_decrypt_time = time.time() - start

    return ecc_encrypt_time, ecc_decrypt_time


def main():
    # Generate RSA and ECC keys
    rsa_key, ecc_private_key, ecc_public_key = generate_keys()
    file_path = "example_file.txt"

    # Create a sample file with random data (1 MB)
    with open(file_path, "wb") as f:
        f.write(os.urandom(1024 * 1024))  # 1 MB file

    # Encrypt and decrypt the file using RSA
    rsa_encrypt_time, rsa_decrypt_time = rsa_encrypt_decrypt(file_path, rsa_key)
    # Encrypt and decrypt the file using ECC
    ecc_encrypt_time, ecc_decrypt_time = ecc_encrypt_decrypt(
        file_path, ecc_private_key, ecc_public_key
    )

    # Print the encryption and decryption times for RSA and ECC
    print(f"RSA Encryption Time: {rsa_encrypt_time:.4f} seconds")
    print(f"RSA Decryption Time: {rsa_decrypt_time:.4f} seconds")
    print(f"ECC Encryption Time: {ecc_encrypt_time:.4f} seconds")
    print(f"ECC Decryption Time: {ecc_decrypt_time:.4f} seconds")


if __name__ == "__main__":
    main()
