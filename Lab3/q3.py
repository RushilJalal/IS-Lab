import random, math


# Function to compute the greatest common divisor (GCD) of two numbers
def gcd(a, b):
    return math.gcd(a, b)


# Function to generate a key that is coprime with q
def gen_key(q):
    key = random.randint(
        pow(10, 20), q
    )  # Generate a random key in the range [10^20, q]
    while gcd(q, key) != 1:  # Ensure the key is coprime with q
        key = random.randint(pow(10, 20), q)
    return key


# Function to perform modular exponentiation
def power(a, b, c):
    x = 1
    y = a
    while b > 0:
        if b % 2 != 0:  # If b is odd, multiply x with the current y
            x = (x * y) % c
        y = (y * y) % c  # Square y
        b = int(b / 2)  # Divide b by 2
    return x % c


# Function to encrypt a message using ElGamal encryption
def encrypt(msg, q, h, g):
    en_msg = []
    k = gen_key(q)  # Private key for sender
    s = power(h, k, q)  # Shared secret
    p = power(g, k, q)  # Public key component
    for i in range(len(msg)):
        en_msg.append(msg[i])
    print("g^k used:", p)
    print("g^ak used:", s)
    for i in range(len(en_msg)):
        en_msg[i] = s * ord(en_msg[i])  # Encrypt each character
    return en_msg, p


# Function to decrypt a message using ElGamal decryption
def decrypt(en_msg, p, key, q):
    dr_msg = []
    h = power(p, key, q)  # Compute the shared secret
    for i in range(len(en_msg)):
        dr_msg.append(chr(int(en_msg[i] / h)))  # Decrypt each character
    return dr_msg


# Main function to demonstrate encryption and decryption
def main():
    msg = "Confidential Data"
    print("Original Message:", msg)
    q = random.randint(pow(10, 20), pow(10, 50))  # Large prime number
    g = random.randint(2, q)  # Random base
    key = gen_key(q)  # Private key for receiver
    h = power(g, key, q)  # Public key component
    print("g used:", g)
    print("g^a used:", h)
    en_msg, p = encrypt(msg, q, h, g)  # Encrypt the message
    dr_msg = decrypt(en_msg, p, key, q)  # Decrypt the message
    dmsg = "".join(dr_msg)  # Join decrypted characters to form the original message
    print("Decrypted Message:", dmsg)


# Entry point of the script
if __name__ == "__main__":
    main()
