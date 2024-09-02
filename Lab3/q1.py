from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

# Generate RSA keys
key = RSA.generate(2048)
public_key = key.publickey()
private_key = key

# Message to be encrypted
message = "Asymmetric Encryption".encode()

# Encrypting the message with the public key
cipher_rsa = PKCS1_OAEP.new(public_key)
encrypted_message = cipher_rsa.encrypt(message)
print("Encrypted message:", encrypted_message.hex())

# Decrypting the message with the private key
cipher_rsa = PKCS1_OAEP.new(private_key)
decrypted_message = cipher_rsa.decrypt(encrypted_message)
print("Decrypted message:", decrypted_message.decode())
