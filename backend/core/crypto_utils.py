import base64
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from oqs import kyber512

# ---------- LEVEL 1: OTP ----------
def otp_encrypt(key: bytes, plaintext: str) -> dict:
    data = plaintext.encode("utf-8")
    if len(key) < len(data):
        raise ValueError("Key must be at least as long as the message")
    ciphertext = bytes([d ^ k for d, k in zip(data, key)])
    return {"ciphertext": base64.b64encode(ciphertext).decode("ascii")}

def otp_decrypt(key: bytes, ciphertext_b64: str) -> str:
    ciphertext = base64.b64decode(ciphertext_b64)
    plaintext = bytes([c ^ k for c, k in zip(ciphertext, key)])
    return plaintext.decode("utf-8")

# ---------- LEVEL 2: AES-GCM ----------
def aes_encrypt(key: bytes, plaintext: str) -> dict:
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)
    return {
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
    }

def aes_decrypt(key: bytes, nonce_b64: str, ciphertext_b64: str) -> str:
    aesgcm = AESGCM(key)
    nonce = base64.b64decode(nonce_b64)
    ciphertext = base64.b64decode(ciphertext_b64)
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    return plaintext.decode("utf-8")

# ---------- LEVEL 3: PQC (Kyber512 + AES) ----------
def pqc_encrypt(key: bytes, plaintext: str) -> dict:
    # Generate Kyber keypair (simulating recipient's public key)
    pk, sk = kyber512.generate_keypair()

    # Encapsulate a shared secret
    ciphertext_kem, shared_secret = kyber512.encrypt(pk)

    # Use shared secret as AES key
    aesgcm = AESGCM(shared_secret[:32])
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)

    return {
        "kem_ciphertext": base64.b64encode(ciphertext_kem).decode("ascii"),
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
        "sk": base64.b64encode(sk).decode("ascii"),  # In practice, only receiver stores this
    }

def pqc_decrypt(key: bytes, data: dict) -> str:
    # Recover secret using stored secret key (sk)
    sk = base64.b64decode(data["sk"])
    ciphertext_kem = base64.b64decode(data["kem_ciphertext"])

    shared_secret = kyber512.decrypt(sk, ciphertext_kem)

    # Decrypt AES
    aesgcm = AESGCM(shared_secret[:32])
    nonce = base64.b64decode(data["nonce"])
    ciphertext = base64.b64decode(data["ciphertext"])
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    return plaintext.decode("utf-8")

# ---------- LEVEL 4: Plaintext ----------
def plain_encrypt(plaintext: str) -> dict:
    return {"ciphertext": plaintext}

def plain_decrypt(ciphertext: str) -> str:
    return ciphertext

# ---------- UNIFIED INTERFACE ----------
def encrypt(level: int, key: bytes, plaintext: str) -> dict:
    if level == 1:
        return otp_encrypt(key, plaintext)
    elif level == 2:
        return aes_encrypt(key, plaintext)
    elif level == 3:
        return pqc_encrypt(key, plaintext)
    elif level == 4:
        return plain_encrypt(plaintext)
    else:
        raise ValueError("Invalid security level")

def decrypt(level: int, key: bytes, data: dict) -> str:
    if level == 1:
        return otp_decrypt(key, data["ciphertext"])
    elif level == 2:
        return aes_decrypt(key, data["nonce"], data["ciphertext"])
    elif level == 3:
        return pqc_decrypt(key, data)
    elif level == 4:
        return plain_decrypt(data["ciphertext"])
    else:
        raise ValueError("Invalid security level")
