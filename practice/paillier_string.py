import random
from math import gcd


def generate_keypair(p, q):
    n = p * q
    g = n + 1
    lambda_ = (p - 1) * (q - 1) // gcd(p - 1, q - 1)
    mu = pow(lambda_, -1, n)
    return (n, g), (lambda_, mu)


def L(x, n):
    return (x - 1) // n


def encrypt(public_key, m):
    n, g = public_key
    r = random.randrange(1, n)
    c = (pow(g, m, n**2) * pow(r, n, n**2)) % (n**2)
    return c


def decrypt(private_key, public_key, c):
    n, _ = public_key
    lambda_, mu = private_key
    x = pow(c, lambda_, n**2)
    m = (L(x, n) * mu) % n
    return m


# Convert string to integer
def string_to_int(message):
    return int.from_bytes(message.encode("utf-8"), byteorder="big")


# Convert integer to string
def int_to_string(message_int):
    try:
        return message_int.to_bytes(
            (message_int.bit_length() + 7) // 8, byteorder="big"
        ).decode("utf-8")
    except UnicodeDecodeError as e:
        print(f"UnicodeDecodeError: {e}")
        return None


# Generate keys with larger primes
p = 499
q = 547
public_key, private_key = generate_keypair(p, q)

# Take input from the user
message1 = input("Enter the first string: ")
message2 = input("Enter the second string: ")

# Convert strings to integers
message1_int = string_to_int(message1)
message2_int = string_to_int(message2)

# Encrypt the integers
c1 = encrypt(public_key, message1_int)
c2 = encrypt(public_key, message2_int)

print(f"Ciphertext of '{message1}': {c1}")
print(f"Ciphertext of '{message2}': {c2}")

# Decrypt the integers
decrypted_message1_int = decrypt(private_key, public_key, c1)
decrypted_message2_int = decrypt(private_key, public_key, c2)

# Convert decrypted integers back to strings
decrypted_message1 = int_to_string(decrypted_message1_int)
decrypted_message2 = int_to_string(decrypted_message2_int)

print(f"Decrypted message 1: {decrypted_message1}")
print(f"Decrypted message 2: {decrypted_message2}")

# Verify the result
print(f"Original message 1: {message1}")
print(f"Original message 2: {message2}")
print(
    f"Decrypted message 1 matches original message 1: {decrypted_message1 == message1}"
)
print(
    f"Decrypted message 2 matches original message 2: {decrypted_message2 == message2}"
)
