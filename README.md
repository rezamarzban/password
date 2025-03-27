# password
AES-ECB-256 HEX data encryption:

This is an actual AES encryption output. Most modern encryption methods like AES, DES, and RSA produce binary data, which is typically represented in HEX for readability: `3ea0aadd80e8725691de44913a69ab31`

Below is an example using PyCryptodome to encrypt (and decrypt) HEX‑encoded data with AES‑ECB using a 256‑bit key. In this example, both the key and the plaintext are provided as hexadecimal strings. The code converts them into bytes, applies PKCS#7 padding (since AES works on 16‑byte blocks), performs the ECB encryption, and finally returns the result as a HEX string.

```python
from Crypto.Cipher import AES
import binascii

def pkcs7_pad(data: bytes) -> bytes:
    pad_len = AES.block_size - (len(data) % AES.block_size)
    return data + bytes([pad_len] * pad_len)

def pkcs7_unpad(data: bytes) -> bytes:
    pad_len = data[-1]
    if pad_len < 1 or pad_len > AES.block_size:
        raise ValueError("Invalid padding")
    return data[:-pad_len]

def aes_ecb_encrypt(hex_plaintext: str, hex_key: str) -> str:
    # Convert HEX strings to bytes.
    key = binascii.unhexlify(hex_key)
    plaintext = binascii.unhexlify(hex_plaintext)
    # Ensure the key is 32 bytes (256 bits)
    if len(key) != 32:
        raise ValueError("Key must be 64 hex digits (256 bits)")
    # Pad the plaintext as needed.
    padded_plaintext = pkcs7_pad(plaintext)
    # Create AES cipher in ECB mode.
    cipher = AES.new(key, AES.MODE_ECB)
    ciphertext = cipher.encrypt(padded_plaintext)
    # Return the ciphertext as a HEX string.
    return binascii.hexlify(ciphertext).decode('utf-8')

def aes_ecb_decrypt(hex_ciphertext: str, hex_key: str) -> str:
    key = binascii.unhexlify(hex_key)
    ciphertext = binascii.unhexlify(hex_ciphertext)
    if len(key) != 32:
        raise ValueError("Key must be 64 hex digits (256 bits)")
    cipher = AES.new(key, AES.MODE_ECB)
    padded_plaintext = cipher.decrypt(ciphertext)
    plaintext = pkcs7_unpad(padded_plaintext)
    # Return the plaintext as a HEX string.
    return binascii.hexlify(plaintext).decode('utf-8')

# Example usage:
if __name__ == '__main__':
    # A 256-bit key: 64 hex digits.
    hex_key = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'
    # Example plaintext (in hex). This need not be a multiple of 16 bytes.
    hex_plaintext = 'deadbeefcafebabe'
    
    print("Plaintext (hex):", hex_plaintext)
    hex_ciphertext = aes_ecb_encrypt(hex_plaintext, hex_key)
    print("Ciphertext (hex):", hex_ciphertext)
    
    decrypted = aes_ecb_decrypt(hex_ciphertext, hex_key)
    print("Decrypted plaintext (hex):", decrypted)
```

The `password.py` Python file is a simple script designed to generate a secure 256-bit key suitable for AES encryption. Here's a breakdown of the code:

- **Importing the Module:**  
  The script begins by importing the built-in Python module `secrets`, which is used for generating cryptographically strong random numbers.

- **Key Generation:**  
  The line `key = secrets.token_bytes(32)` generates 32 random bytes. Since 1 byte equals 8 bits, these 32 bytes form a 256-bit key, making it ideal for AES-256 encryption.

- **Printing the Key:**  
  The script then prints the generated key in a hexadecimal format using `key.hex()`, which converts the binary key into a human-readable string.

The `password.py` file is useful for applications where a strong, random key is required for encryption purposes.

Here is the bash script (`decrypt.sh`) that decrypts a hex-encoded string using AES-256 in ECB mode with OpenSSL. Let's break down how it works:

1. `key=$(echo -n "YOUR_KEY" | xxd -p | tr -d '\n')`
   - Takes a plaintext key (`YOUR_KEY`) and converts it to hexadecimal format using `xxd -p`
   - `tr -d '\n'` removes any newline characters
   - Stores the result in the `key` variable
   - Note: For AES-256, the key should be 32 bytes (64 hex characters) long

2. `echo -n "YOUR_HEX_STRING" | xxd -r -p | openssl enc -aes-256-ecb -d -K "$key" -nopad`
   - `echo -n "YOUR_HEX_STRING"` outputs the hex-encoded ciphertext
   - `xxd -r -p` converts the hex string back to binary
   - `openssl enc -aes-256-ecb -d` performs AES-256-ECB decryption
   - `-K "$key"` specifies the key in hex format
   - `-nopad` disables padding (input must be an exact multiple of the block size, 16 bytes)

To use this script:
1. Replace `YOUR_KEY` with a 32-byte (256-bit) key in plaintext
2. Replace `YOUR_HEX_STRING` with your hex-encoded ciphertext
3. Ensure the ciphertext length is a multiple of 32 hex characters (16 bytes) since there's no padding

```bash
#!/bin/bash

key=$(echo -n "YOUR_KEY" | xxd -p | tr -d '\n')

echo -n "YOUR_HEX_STRING" | xxd -r -p | openssl enc -aes-256-ecb -d -K "$key" -nopad
```

[Run Bash Online](https://rextester.com/l/bash_online_compiler)
