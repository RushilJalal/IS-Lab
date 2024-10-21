import random
from math import gcd


# Function to generate a public/private key pair
def generate_keypair(p, q):
    n = p * q  # Compute n as the product of p and q
    g = n + 1  # Choose g as n + 1
    lambda_ = (
        (p - 1) * (q - 1) // gcd(p - 1, q - 1)
    )  # Compute lambda as the least common multiple (LCM) of (p-1) and (q-1)
    mu = pow(
        lambda_, -1, n
    )  # Compute mu as the modular multiplicative inverse of lambda modulo n
    return (n, g), (
        lambda_,
        mu,
    )  # Return the public key (n, g) and the private key (lambda, mu)


# Function to compute the L function used in decryption
def L(x, n):
    return (x - 1) // n


# Function to encrypt a message using the public key
def encrypt(public_key, m):
    n, g = public_key
    r = random.randrange(1, n)  # Generate a random number r
    c = (pow(g, m, n**2) * pow(r, n, n**2)) % (n**2)  # Compute the ciphertext
    return c


# Function to decrypt a ciphertext using the private key
def decrypt(private_key, public_key, c):
    n, _ = public_key
    lambda_, mu = private_key
    x = pow(c, lambda_, n**2)  # Compute x = c^lambda mod n^2
    m = (L(x, n) * mu) % n  # Compute the plaintext message
    return m


# Function to perform homomorphic addition on two ciphertexts
def add_encrypted(public_key, c1, c2):
    n, _ = public_key
    return (c1 * c2) % (n**2)  # Compute the product of the ciphertexts modulo n^2


# Generate keys
p, q = 17, 19  # Choose two prime numbers
public_key, private_key = generate_keypair(p, q)  # Generate the public and private keys

# Encrypt two integers
m1, m2 = 15, 25  # Plaintext messages
c1 = encrypt(public_key, m1)  # Encrypt the first message
c2 = encrypt(public_key, m2)  # Encrypt the second message

print(f"Ciphertext of {m1}: {c1}")
print(f"Ciphertext of {m2}: {c2}")

# Perform homomorphic addition
c_sum = add_encrypted(public_key, c1, c2)  # Compute the encrypted sum
print(f"Encrypted sum: {c_sum}")

# Decrypt the sum
decrypted_sum = decrypt(private_key, public_key, c_sum)  # Decrypt the encrypted sum
print(f"Decrypted sum: {decrypted_sum}")

# Verify the result
print(f"Original sum: {m1 + m2}")
print(f"Decrypted sum matches original sum: {decrypted_sum == m1 + m2}")
