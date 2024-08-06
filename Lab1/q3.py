# playfair


def generate_key_square(key):
    key = key.upper().replace("J", "I")
    key_square = []
    used_chars = set()

    for char in key:
        if char not in used_chars and char.isalpha():
            key_square.append(char)
            used_chars.add(char)

    for char in "ABCDEFGHIKLMNOPQRSTUVWXYZ":
        if char not in used_chars:
            key_square.append(char)
            used_chars.add(char)

    return [key_square[i : i + 5] for i in range(0, 25, 5)]


def prepare_text(text):
    text = text.upper().replace("J", "I")
    prepared_text = []
    i = 0

    while i < len(text):
        if text[i].isalpha():
            if i + 1 < len(text) and text[i] == text[i + 1]:
                prepared_text.append(text[i] + "X")
                i += 1
            elif i + 1 < len(text):
                prepared_text.append(text[i] + text[i + 1])
                i += 2
            else:
                prepared_text.append(text[i] + "X")
                i += 1
        else:
            i += 1

    return prepared_text


def find_position(key_square, char):
    for row in range(5):
        for col in range(5):
            if key_square[row][col] == char:
                return row, col
    return -1, -1


def encrypt_digraph(key_square, digraph):
    row1, col1 = find_position(key_square, digraph[0])
    row2, col2 = find_position(key_square, digraph[1])

    if row1 == row2:
        return key_square[row1][(col1 + 1) % 5] + key_square[row2][(col2 + 1) % 5]
    elif col1 == col2:
        return key_square[(row1 + 1) % 5][col1] + key_square[(row2 + 1) % 5][col2]
    else:
        return key_square[row1][col2] + key_square[row2][col1]


def playfair_encrypt(message, key):
    key_square = generate_key_square(key)
    prepared_text = prepare_text(message)
    encrypted_message = ""

    for digraph in prepared_text:
        encrypted_message += encrypt_digraph(key_square, digraph)

    return encrypted_message


message = "The key is hidden under the door pad"
key = "GUIDANCE"

encrypted_message = playfair_encrypt(message, key)
print("Encrypted message:", encrypted_message)
