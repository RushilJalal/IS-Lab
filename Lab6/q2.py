import random
from sympy import isprime


# Function to generate a large prime number of specified bit length
def generate_large_prime(bits=256):
    # Generate random numbers of the specified bit length until a prime is found
    return next(n for n in iter(lambda: random.getrandbits(bits), None) if isprime(n))


# Function to generate Diffie-Hellman key pairs
def dh_keygen(bits=256):
    # Generate a large prime number p and a random base g
    p, g = generate_large_prime(bits), random.randint(
        2, (p := generate_large_prime(bits)) - 2
    )
    # Generate private keys a and b for two parties
    a, b = random.randint(1, p - 2), random.randint(1, p - 2)
    # Compute public keys A and B
    A, B = pow(g, a, p), pow(g, b, p)
    # Return public values (p, g, A, B) and shared secrets for both parties
    return (p, g, A, B), (pow(B, a, p), pow(A, b, p))


# Generate public values and shared secrets
(pub, (sec_A, sec_B)) = dh_keygen()

# Print public values
print("Public values (p, g, A, B):", *pub)
# Check if the shared secrets match
print("Shared secrets match?", sec_A == sec_B)

"""
Output:

Public values (p, g, A, B): 57362700967700179027746614187317044674120646808356604905972465806112511326147 58601255477100039570470421947914615739523804063449601475977088658831515288612 39384236907483045297374802164089030443584050728289431914118131510699584633484 42966337621924961370621816291450829649739610013752348158366030243070495895726
Shared secrets match? True
"""
