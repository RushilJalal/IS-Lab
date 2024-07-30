#Multiplicative cipher with key = 15
str="I am learning information security"
key=15

def encrypt(str):
    encrypted_text = []
    for letter in str:
        offset = 65 if letter.isupper() else 97
        encrypted_letter = chr(((ord(letter) - offset) * key) % 26 + offset)
        if letter == " ": 
            encrypted_letter = " "
            
        encrypted_text.append(encrypted_letter)

    return ''.join(encrypted_text)

encrypted_text = encrypt(str)
print("Encrypted text: ", encrypted_text)

def decrypt(str):
    decrypted_text = []
    
    for letter in str:
        offset = 65 if letter.isupper() else 97
        mod_multi_inv = pow(key,-1,26)#modular multiplicative inverse
        encrypted_letter = chr((ord(letter) - offset) * mod_multi_inv % 26 + offset)
        if letter == " ": 
            encrypted_letter = " "
        decrypted_text.append(encrypted_letter)

    return ''.join(decrypted_text)

decrypted_text = decrypt(encrypted_text)
print("Decrypted text: ", decrypted_text)