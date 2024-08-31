def autokey_encrypt(plaintext, key):
    plaintext = plaintext.replace(" ", "").lower()
    ciphertext = ""
    current_key = key

    for i, char in enumerate(plaintext):
        shift = (ord(char) - ord("a") + current_key) % 26
        ciphertext += chr(shift + ord("a"))
        current_key = ord(char) - ord("a")

    return ciphertext


def autokey_decrypt(ciphertext, key):
    plaintext = ""
    current_key = key

    for i, char in enumerate(ciphertext):
        shift = (ord(char) - ord("a") - current_key + 26) % 26
        plaintext += chr(shift + ord("a"))
        current_key = shift

    return plaintext


plaintext = "the house is being sold tonight"
key = 7

ciphertext = autokey_encrypt(plaintext, key)
print("Encrypted message:", ciphertext)

decrypted_text = autokey_decrypt(ciphertext, key)
print("Decrypted message:", decrypted_text)
