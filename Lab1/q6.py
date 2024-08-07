""" Use a brute-force attack to decipher the following message. Assume that you know it is an 
affine cipher and that the plaintext "ab" is enciphered to "GL": 
XPALASXYFGFUKPXUSOGEUTKCDGEXANMGNVS 

Explanation:
a->g ==> 0.x + b % 26 = 6
b->l ==> 1.x + b % 26 = 11
Thus, a = 5, b = 6
"""

ciphertext = "XPALASXYFGFUKPXUSOGEUTKCDGEXANMGNVS"
a = 5
b = 6
plaintext = ""
a_inv = pow(a, -1, 26)

for letter in ciphertext:
    y = ord(letter) - ord("A")
    x = a_inv * (y - b) % 26
    plaintext += chr(x + ord("A"))

print("Decrypted text: ", plaintext)
