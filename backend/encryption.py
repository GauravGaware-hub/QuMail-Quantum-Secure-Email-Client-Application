from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os

def otp_encrypt(plaintext: bytes, key: bytes) -> bytes:
    """
    One Time Pad Encryption (XOR)
    Key must be at least plaintext length.
    """
    if len(key) < len(plaintext):
        raise ValueError("Key length must be >= plaintext length for OTP.")
    ciphertext = bytes([p ^ k for p, k in zip(plaintext, key)])
    return ciphertext

def otp_decrypt(ciphertext: bytes, key: bytes) -> bytes:
    """
    OTP decryption is same as encryption (XOR)
    """
    return otp_encrypt(ciphertext, key)

def aes_encrypt(plaintext: bytes, key: bytes) -> bytes:
    """
    AES CBC mode with PKCS7 padding
    Key length must be 16/24/32 bytes (128/192/256 bits)
    """
    key = key[:32]  # truncate if longer
    iv = os.urandom(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
    return iv + ciphertext  # prepend IV for decryption

def aes_decrypt(ciphertext: bytes, key: bytes) -> bytes:
    key = key[:32]
    iv = ciphertext[:16]
    actual_ciphertext = ciphertext[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(actual_ciphertext), AES.block_size)
    return plaintext

def pqc_encrypt(plaintext: bytes, key: bytes) -> bytes:
    """
    Placeholder for PQC encryption
    """
    # For demo, return plaintext unmodified
    return plaintext

def pqc_decrypt(ciphertext: bytes, key: bytes) -> bytes:
    """
    Placeholder for PQC decryption
    """
    # For demo, return ciphertext unmodified
    return ciphertext