from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

# Message to be encrypted
message = "Top Secret Data".encode()

# AES-192 key (24 bytes for AES-192)
key = b"FEDCBA9876543210FEDCBA9876543210"

# Ensure the key is 24 bytes for AES-192
key = key[:24]

# Padding the message to be a multiple of block size
padded_message = pad(message, AES.block_size)

# Encrypting the message
cipher = AES.new(key, AES.MODE_ECB)
encrypted_message = cipher.encrypt(padded_message)
print("Encrypted message:", encrypted_message.hex())
