from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# Message and key
message = "Sensitive Information".encode()
key = b"0123456789ABCDEF0123456789ABCDEF"

# Ensure the key is 16 bytes for AES-128
key = key[:16]

# Padding the message to be a multiple of AES block size
padded_message = pad(message, AES.block_size)

# Encrypting the message
cipher = AES.new(key, AES.MODE_ECB)
encrypted_message = cipher.encrypt(padded_message)
print("Encrypted message:", encrypted_message.hex())

# Decrypting the message
decrypted_bytes = cipher.decrypt(encrypted_message)
decrypted_message = unpad(decrypted_bytes, AES.block_size).decode()
print("Decrypted message:", decrypted_message)
