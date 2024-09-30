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


def add_encrypted(public_key, c1, c2):
    n, _ = public_key
    return (c1 * c2) % (n**2)


# Generate keys
p, q = 17, 19
public_key, private_key = generate_keypair(p, q)

# Encrypt two integers
m1, m2 = 15, 25
c1 = encrypt(public_key, m1)
c2 = encrypt(public_key, m2)

print(f"Ciphertext of {m1}: {c1}")
print(f"Ciphertext of {m2}: {c2}")

# Perform homomorphic addition
c_sum = add_encrypted(public_key, c1, c2)
print(f"Encrypted sum: {c_sum}")

# Decrypt the sum
decrypted_sum = decrypt(private_key, public_key, c_sum)
print(f"Decrypted sum: {decrypted_sum}")

# Verify the result
print(f"Original sum: {m1 + m2}")
print(f"Decrypted sum matches original sum: {decrypted_sum == m1 + m2}")
