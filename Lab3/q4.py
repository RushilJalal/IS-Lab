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
    rsa_key = RSA.generate(2048)
    ecc_private_key = PrivateKey()
    ecc_public_key = ecc_private_key.public_key
    return rsa_key, ecc_private_key, ecc_public_key


# Encrypt and decrypt file using RSA
def rsa_encrypt_decrypt(file_path, rsa_key):
    start = time.time()
    cipher_rsa = PKCS1_OAEP.new(rsa_key.publickey())
    aes_key = get_random_bytes(16)
    with open(file_path, "rb") as f:
        plaintext = f.read()
    enc_session_key = cipher_rsa.encrypt(aes_key)
    cipher_aes = AES.new(aes_key, AES.MODE_EAX)
    ciphertext, tag = cipher_aes.encrypt_and_digest(pad(plaintext, AES.block_size))
    rsa_encrypt_time = time.time() - start

    start = time.time()
    cipher_rsa = PKCS1_OAEP.new(rsa_key)
    aes_key = cipher_rsa.decrypt(enc_session_key)
    cipher_aes = AES.new(aes_key, AES.MODE_EAX, nonce=cipher_aes.nonce)
    plaintext = unpad(cipher_aes.decrypt_and_verify(ciphertext, tag), AES.block_size)
    rsa_decrypt_time = time.time() - start

    return rsa_encrypt_time, rsa_decrypt_time


# Encrypt and decrypt file using ECC
def ecc_encrypt_decrypt(file_path, ecc_private_key, ecc_public_key):
    start = time.time()
    aes_key = get_random_bytes(16)
    with open(file_path, "rb") as f:
        plaintext = f.read()
    enc_session_key = encrypt(ecc_public_key.format(True), aes_key)
    cipher_aes = AES.new(aes_key, AES.MODE_EAX)
    ciphertext, tag = cipher_aes.encrypt_and_digest(pad(plaintext, AES.block_size))
    ecc_encrypt_time = time.time() - start

    start = time.time()
    aes_key = decrypt(ecc_private_key.to_hex(), enc_session_key)
    cipher_aes = AES.new(aes_key, AES.MODE_EAX, nonce=cipher_aes.nonce)
    plaintext = unpad(cipher_aes.decrypt_and_verify(ciphertext, tag), AES.block_size)
    ecc_decrypt_time = time.time() - start

    return ecc_encrypt_time, ecc_decrypt_time


def main():
    rsa_key, ecc_private_key, ecc_public_key = generate_keys()
    file_path = "example_file.txt"

    # Create a sample file
    with open(file_path, "wb") as f:
        f.write(os.urandom(1024 * 1024))  # 1 MB file

    rsa_encrypt_time, rsa_decrypt_time = rsa_encrypt_decrypt(file_path, rsa_key)
    ecc_encrypt_time, ecc_decrypt_time = ecc_encrypt_decrypt(
        file_path, ecc_private_key, ecc_public_key
    )

    print(f"RSA Encryption Time: {rsa_encrypt_time:.4f} seconds")
    print(f"RSA Decryption Time: {rsa_decrypt_time:.4f} seconds")
    print(f"ECC Encryption Time: {ecc_encrypt_time:.4f} seconds")
    print(f"ECC Decryption Time: {ecc_decrypt_time:.4f} seconds")


if __name__ == "__main__":
    main()
