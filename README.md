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

