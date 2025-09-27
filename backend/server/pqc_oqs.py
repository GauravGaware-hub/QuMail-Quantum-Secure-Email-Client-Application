import oqs
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

def pqc_generate_keypair():
    with oqs.KeyEncapsulation("Kyber512") as kem:
        pk = kem.generate_keypair()
        sk = kem.export_secret_key()
        return pk, sk

def pqc_encrypt(pk: bytes, plaintext: str):
    with oqs.KeyEncapsulation("Kyber512") as kem:
        kem.import_public_key(pk)
        ciphertext, shared_secret = kem.encap_secret()

    aesgcm = AESGCM(shared_secret[:32])
    nonce = os.urandom(12)
    ciphertext_aes = aesgcm.encrypt(nonce, plaintext.encode(), None)

    return {
        "kem_ciphertext": base64.b64encode(ciphertext).decode(),
        "nonce": base64.b64encode(nonce).decode(),
        "ciphertext": base64.b64encode(ciphertext_aes).decode()
    }

def pqc_decrypt(sk: bytes, kem_ciphertext_b64: str, nonce_b64: str, ciphertext_b64: str) -> str:
    kem_ciphertext = base64.b64decode(kem_ciphertext_b64)
    nonce = base64.b64decode(nonce_b64)
    ciphertext = base64.b64decode(ciphertext_b64)

    with oqs.KeyEncapsulation("Kyber512") as kem:
        kem.import_secret_key(sk)
        shared_secret = kem.decap_secret(kem_ciphertext)

    aesgcm = AESGCM(shared_secret[:32])
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    return plaintext.decode()
