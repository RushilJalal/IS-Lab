from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

message = "Confidential Data".encode()
key = b"A1B2C3D4E4124324"


padded_message = pad(message, AES.block_size)

cipher = AES.new(key, AES.MODE_ECB)

encrypted_message = cipher.encrypt(padded_message)

print("Encrypted message:", encrypted_message.hex())


# decryption
decrypted_bytes = cipher.decrypt(encrypted_message)


decrypted_message = unpad(decrypted_bytes, AES.block_size).decode("utf-8")

print("Decrypted message:", decrypted_message)
