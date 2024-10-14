from Crypto.PublicKey import ElGamal
from Crypto.Random import get_random_bytes
from Crypto.Random.random import randint
from Crypto.Util.number import GCD
from ecdsa import SigningKey, NIST256p, BadSignatureError
import hashlib

# There is nurse, doctor and lab assistant. The nurse takes info from user like name, gender, vital signs etc.
# Encrypts and signs it and sends it to the doctor.
# Doctor gets the information verifies it decrypts it and suggests lab tests and sends it to lab assistant.
# lab assistant is able to see only lab tests and name of the patient


# Key Generation
key = ElGamal.generate(256, get_random_bytes)
public_key = (int(key.p), int(key.g), int(key.y))  # Ensure all are integers
private_key = int(key.x)  # Ensure the private key is an integer


# Convert string to integer
def string_to_int(message):
    return int.from_bytes(message.encode("utf-8"), byteorder="big")


# Convert integer to string
def int_to_string(message_int):
    return message_int.to_bytes(
        (message_int.bit_length() + 7) // 8, byteorder="big"
    ).decode("utf-8")


# Encryption
def elgamal_encrypt(message, key):
    p, g, y = int(key.p), int(key.g), int(key.y)  # Convert to native Python integers
    k = randint(1, p - 2)
    while GCD(k, p - 1) != 1:
        k = randint(1, p - 2)
    c1 = pow(g, k, p)
    c2 = (message * pow(y, k, p)) % p
    return (c1, c2)


# Decryption
def elgamal_decrypt(cipher_text, key):
    c1, c2 = cipher_text
    p = int(key.p)  # Convert to native Python integer
    s = pow(c1, int(key.x), p)  # Convert to native Python integers
    # Use pow to compute the modular inverse
    s_inv = pow(s, p - 2, p)  # Fermat's Little Theorem
    return (c2 * s_inv) % p


# Generate Schnorr Keys
private_key = SigningKey.generate(curve=NIST256p)  # Private key
public_key = private_key.verifying_key  # Public key


# Schnorr Sign
def schnorr_sign(message, private_key):
    message_hash = hashlib.sha256(message.encode()).digest()
    signature = private_key.sign(message_hash, hashfunc=hashlib.sha256)
    return signature


# Schnorr Verify
def schnorr_verify(message, signature, public_key):
    try:
        message_hash = hashlib.sha256(message.encode()).digest()
        return public_key.verify(signature, message_hash, hashfunc=hashlib.sha256)
    except BadSignatureError:
        return False


# Example usage
name = input("Enter patient name: ")
gender = input("Enter gender: ")
vitals = input("Enter patient vitals: ")

# message = f"Name: {name}, Gender: {gender}, Vitals: {vitals}"
message = name + gender + vitals
signed = schnorr_sign(message, private_key)
message_int = string_to_int(message)
cipher_text = elgamal_encrypt(message_int, key)

decrypted_message_int = elgamal_decrypt(cipher_text, key)
decrypted_message = int_to_string(decrypted_message_int)
verify = schnorr_verify(decrypted_message, signed, public_key)

print("Original message:", message)
print("Digital signature: ", signed.hex())
print("Encrypted message:", cipher_text)
print("Decrypted message:", decrypted_message)
print("Signature verify: ", verify)
