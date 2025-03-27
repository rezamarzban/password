import secrets

# Generate a strong 256-bit (32-byte) key
key = secrets.token_bytes(32)

# Optionally, print the key in hexadecimal format
print("256-bit AES key (hex):", key.hex())
