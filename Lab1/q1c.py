#Affine cipher with key = (15, 20)
#(ax+b)%26 where x is ascii value of letter

str="I am learning information security"
a=15
b=20

def encrypt(str):
    encrypted_text = []
    for letter in str:
        offset = 65 if letter.isupper() else 97
        encrypted_letter = chr((a * (ord(letter) - offset) + b) % 26 + offset)
        if letter == " ":
            encrypted_letter = " "
            
        encrypted_text.append(encrypted_letter)

    return ''.join(encrypted_text)

encrypted = encrypt(str)
print("Encrypted text: ", encrypted)

def decrypt(str):
    decrypted_text = []
    a_inv = pow(a, -1, 26)
    for letter in str:
        offset = 65 if letter.isupper() else 97
        
        encrypted_letter = chr(a_inv * (((ord(letter) - offset) - b)) % 26 + offset)
        if letter == " ":
            encrypted_letter = " "
            
        decrypted_text.append(encrypted_letter)

    return ''.join(decrypted_text)

decrypted = decrypt(encrypted)
print("Decrypted text: ", decrypted)