# hill cipher


plaintext = "We live in an insecure world"  # ignore spaces
K = [[3, 3], [2, 7]]


def encrypt(plaintext):
    plaintext = plaintext.upper().replace(" ", "")
    if len(plaintext) % 2 != 0:
        plaintext += "X"

    encrypted = ""
    for i in range(0, len(plaintext), 2):
        pair = plaintext[i : i + 2]
        matrix = [ord(pair[0]) - ord("A"), ord(pair[1]) - ord("A")]

        encrypted_pair = [
            (K[0][0] * matrix[0] + K[0][1] * matrix[1]) % 26,
            (K[1][0] * matrix[0] + K[1][1] * matrix[1]) % 26,
        ]

        encrypted += chr(encrypted_pair[0] + ord("A"))
        encrypted += chr(encrypted_pair[1] + ord("A"))

    return encrypted


print("Encrypted string: ", encrypt(plaintext))
