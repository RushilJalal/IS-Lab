# Function to convert a string to its ASCII representation as a single integer
def string_to_ascii(s):
    return int("".join(str(ord(c)) for c in s))


# Take input from the user
string1 = input("Enter the first string: ")
string2 = input("Enter the second string: ")

# Concatenate the strings
concatenated_string = string1 + string2

# Convert the concatenated string to ASCII
ascii_representation = string_to_ascii(concatenated_string)

# Print the results
print(f"Concatenated string: {concatenated_string}")
print(f"ASCII representation: {ascii_representation}")
