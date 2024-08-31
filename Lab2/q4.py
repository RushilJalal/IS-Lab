from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad, unpad

# Message to be encrypted
message = "Classified Text".encode()

# Triple DES key (24 bytes for 3DES)
key = b"1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF"

# Ensure the key is 24 bytes for Triple DES
key = key[:24]

# Padding the message to be a multiple of block size
padded_message = pad(message, DES3.block_size)

# Encrypting the message
cipher = DES3.new(key, DES3.MODE_ECB)
encrypted_message = cipher.encrypt(padded_message)
print("Encrypted message:", encrypted_message.hex())

# Decrypting the message
decrypted_bytes = cipher.decrypt(encrypted_message)
decrypted_message = unpad(decrypted_bytes, DES3.block_size).decode()
print("Decrypted message:", decrypted_message)
