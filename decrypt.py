from Crypto.Cipher import AES
import base64
import time
import sys

def pad(text):
    pad_len = 16 - len(text) % 16
    return text + chr(pad_len) * pad_len

def unpad(text):
    pad_len = ord(text[-1])
    return text[:-pad_len]

# --- Encryption (used internally) ---
def encrypt(plain_text):
    key = b'ThisIsASecretKey'  # 16-byte key
    cipher = AES.new(key, AES.MODE_ECB)
    padded_text = pad(plain_text)
    encrypted = cipher.encrypt(padded_text.encode('utf-8'))
    return base64.b64encode(encrypted).decode('utf-8')

# --- Decryption ---
def decrypt(encrypted_base64):
    key = b'ThisIsASecretKey'
    cipher = AES.new(key, AES.MODE_ECB)
    encrypted_bytes = base64.b64decode(encrypted_base64)
    decrypted_padded = cipher.decrypt(encrypted_bytes).decode('utf-8')
    return unpad(decrypted_padded)

# Prepare encrypted message (simulating it's already stored)
ciphertext = encrypt("imissyou")  # you can replace with stored ciphertext

# Simulate 10-second loading animation
print("Decrypting", end="")
for _ in range(10):
    time.sleep(1)
    print(".", end="")
    sys.stdout.flush()
print()

# Decrypt and show the original message
decrypted = decrypt(ciphertext)
print("Decrypted:", decrypted)
