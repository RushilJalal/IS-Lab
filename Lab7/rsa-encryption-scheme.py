import random
from math import gcd


def is_prime(n):
    if n < 2:
        return False
    for i in range(2, int(n**0.5) + 1):
        if n % i == 0:
            return False
    return True


def generate_prime(min_value, max_value):
    prime = random.randint(min_value, max_value)
    while not is_prime(prime):
        prime = random.randint(min_value, max_value)
    return prime


def mod_inverse(a, m):
    def egcd(a, b):
        if a == 0:
            return (b, 0, 1)
        else:
            g, y, x = egcd(b % a, a)
            return (g, x - (b // a) * y, y)

    g, x, _ = egcd(a, m)
    if g != 1:
        raise Exception("Modular inverse does not exist")
    else:
        return x % m


def generate_keypair(p, q):
    n = p * q
    phi = (p - 1) * (q - 1)

    e = random.randrange(1, phi)
    while gcd(e, phi) != 1:
        e = random.randrange(1, phi)

    d = mod_inverse(e, phi)

    return ((e, n), (d, n))


def encrypt(public_key, plaintext):
    e, n = public_key
    return pow(plaintext, e, n)


def decrypt(private_key, ciphertext):
    d, n = private_key
    return pow(ciphertext, d, n)


# Generate RSA keys
p = generate_prime(100, 1000)
q = generate_prime(100, 1000)
public_key, private_key = generate_keypair(p, q)

# Original integers
m1, m2 = 7, 3

# Encrypt the integers
c1 = encrypt(public_key, m1)
c2 = encrypt(public_key, m2)

print(f"Ciphertext of {m1}: {c1}")
print(f"Ciphertext of {m2}: {c2}")

# Perform homomorphic multiplication
c_product = (c1 * c2) % public_key[1]
print(f"Encrypted product: {c_product}")

# Decrypt the product
decrypted_product = decrypt(private_key, c_product)
print(f"Decrypted product: {decrypted_product}")

# Verify the result
print(f"Original product: {m1 * m2}")
print(f"Decrypted product matches original product: {decrypted_product == m1 * m2}")
