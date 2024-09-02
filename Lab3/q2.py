from ecies import encrypt, decrypt
from ecies.utils import generate_eth_key

# Generate ECC keys
eth_key = generate_eth_key()
private_key = eth_key.to_hex()
public_key = eth_key.public_key.to_hex()

# Message to be encrypted
message = "Secure Transactions".encode()

# Encrypting the message with the public key
encrypted_message = encrypt(public_key, message)
print("Encrypted message:", encrypted_message.hex())

# Decrypting the message with the private key
decrypted_message = decrypt(private_key, encrypted_message)
print("Decrypted message:", decrypted_message.decode())
