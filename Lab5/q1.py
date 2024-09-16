def hash_function(s):
    hash_value = 5381

    for char in s:
        hash_value = (hash_value * 33) + ord(char)

        hash_value = hash_value ^ (hash_value << 16)

    hash_value = hash_value & 0xFFFFFFFF

    return hash_value


input = "Hello World"
hashed = hash_function(input)
print("Hashed value: ", hashed)
