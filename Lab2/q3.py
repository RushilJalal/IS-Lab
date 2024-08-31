import timeit
from Crypto.Cipher import DES, AES
from Crypto.Util.Padding import pad, unpad

# Message to be encrypted
message = "Performance Testing of Encryption Algorithms".encode()

# DES key (8 bytes for DES)
des_key = b"12345678"

# AES-256 key (32 bytes for AES-256)
aes_key = b"0123456789ABCDEF0123456789ABCDEF"

# Padding the message to be a multiple of block size
padded_message_des = pad(message, DES.block_size)
padded_message_aes = pad(message, AES.block_size)

# DES Encryption and Decryption
des_cipher = DES.new(des_key, DES.MODE_ECB)


def des_encrypt():
    return des_cipher.encrypt(padded_message_des)


def des_decrypt(encrypted_message):
    return unpad(des_cipher.decrypt(encrypted_message), DES.block_size)


encrypted_message_des = des_encrypt()

encryption_time_des = timeit.timeit(des_encrypt, number=1000) / 1000
decryption_time_des = (
    timeit.timeit(lambda: des_decrypt(encrypted_message_des), number=1000) / 1000
)

# AES-256 Encryption and Decryption
aes_cipher = AES.new(aes_key, AES.MODE_ECB)


def aes_encrypt():
    return aes_cipher.encrypt(padded_message_aes)


def aes_decrypt(encrypted_message):
    return unpad(aes_cipher.decrypt(encrypted_message), AES.block_size)


encrypted_message_aes = aes_encrypt()

encryption_time_aes = timeit.timeit(aes_encrypt, number=1000) / 1000
decryption_time_aes = (
    timeit.timeit(lambda: aes_decrypt(encrypted_message_aes), number=1000) / 1000
)

# Print the results
print(f"DES Encryption Time: {encryption_time_des:.8f} seconds")
print(f"DES Decryption Time: {decryption_time_des:.8f} seconds")
print(f"AES-256 Encryption Time: {encryption_time_aes:.8f} seconds")
print(f"AES-256 Decryption Time: {decryption_time_aes:.8f} seconds")
