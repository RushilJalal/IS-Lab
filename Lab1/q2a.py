# Vigenere cipher
str = "the house is being sold tonight"
key = "dollars"


def encrypt(str):
    new_str = []
    for i in range(len(str)):
        offset = 65 if str[i].isupper() else 97
        key_offset = 65 if key[i % len(key)].isupper() else 97
        shift = ord(key[i % len(key)]) - key_offset
        new_char = chr((ord(str[i]) - offset + shift) % 26 + offset)
        if str[i] == " ":
            new_char = " "
        new_str.append(new_char)

    return "".join(new_str)


encrypted_string = encrypt(str)
print("Encrypted string: ", encrypted_string)


def decrypt(str):
    new_str = []
    for i in range(len(str)):
        offset = 65 if str[i].isupper() else 97
        key_offset = 65 if key[i % len(key)].isupper() else 97
        shift = ord(key[i % len(key)]) - key_offset
        new_char = chr((ord(str[i]) - offset - shift) % 26 + offset)
        if str[i] == " ":
            new_char = " "
        new_str.append(new_char)

    return "".join(new_str)


decrypted_string = decrypt(encrypted_string)
print("Decrypted string: ", decrypted_string)
