#additive cipher with key 20
str="I am learning information security"
key=20

def encrypt(str):
    encrypted_text = []
    for letter in str:
        offset = 65 if letter.isupper() else 97
        encrypted_letter = chr((ord(letter) - offset + key) % 26 + offset)
        if letter == " ": encrypted_letter = " "
        encrypted_text.append(encrypted_letter)

    return ''.join(encrypted_text)

print(encrypt(str))