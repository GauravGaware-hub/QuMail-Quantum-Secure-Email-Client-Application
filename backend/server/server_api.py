import os
import json
from flask import Flask, request, jsonify
from flask_cors import CORS
from pqc_oqs import pqc_generate_keypair as generate_keypair, pqc_encrypt as kem_enc, pqc_decrypt as kem_dec

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import base64

app = Flask(__name__)
CORS(app)

KEY_DIR = os.path.join(os.path.dirname(__file__), "keys")
os.makedirs(KEY_DIR, exist_ok=True)

def load_or_create_keypair(username: str):
    pk_file = os.path.join(KEY_DIR, f"{username}_pk.bin")
    sk_file = os.path.join(KEY_DIR, f"{username}_sk.bin")

    if os.path.exists(pk_file) and os.path.exists(sk_file):
        with open(pk_file, "rb") as f:
            pk = f.read()
        with open(sk_file, "rb") as f:
            sk = f.read()
    else:
        pk, sk = generate_keypair()
        with open(pk_file, "wb") as f:
            f.write(pk)
        with open(sk_file, "wb") as f:
            f.write(sk)
    return pk, sk

def aes_encrypt(shared_secret: bytes, plaintext: str):
    aesgcm = AESGCM(shared_secret[:32])  # use 256-bit key
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)
    return {
        "nonce": base64.b64encode(nonce).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode()
    }

def aes_decrypt(shared_secret: bytes, nonce_b64: str, ciphertext_b64: str):
    aesgcm = AESGCM(shared_secret[:32])
    nonce = base64.b64decode(nonce_b64)
    ciphertext = base64.b64decode(ciphertext_b64)
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    return plaintext.decode("utf-8")

@app.route("/api/get_pk", methods=["POST"])
def get_public_key():
    data = request.get_json()
    username = data.get("username")
    if not username:
        return jsonify({"error": "username required"}), 400
    pk, _ = load_or_create_keypair(username)
    return jsonify({"public_key": base64.b64encode(pk).decode()})

@app.route("/api/encrypt", methods=["POST"])
def encrypt_message():
    data = request.get_json()
    recipient = data["recipient"]
    message = data["message"]

    # load recipient's public key
    pk_file = os.path.join(KEY_DIR, f"{recipient}_pk.bin")
    if not os.path.exists(pk_file):
        return jsonify({"error": "recipient public key not found"}), 404

    with open(pk_file, "rb") as f:
        recipient_pk = f.read()

    # Kyber encapsulation
    kem_ciphertext, shared_secret = kem_enc(recipient_pk)

    # AES-GCM encryption
    encrypted = aes_encrypt(shared_secret, message)

    return jsonify({
        "kem_ciphertext": base64.b64encode(kem_ciphertext).decode(),
        "nonce": encrypted["nonce"],
        "ciphertext": encrypted["ciphertext"]
    })

@app.route("/api/decrypt", methods=["POST"])
def decrypt_message():
    data = request.get_json()
    username = data["username"]
    kem_ciphertext_b64 = data["kem_ciphertext"]
    nonce = data["nonce"]
    ciphertext = data["ciphertext"]

    _, sk = load_or_create_keypair(username)

    kem_ciphertext = base64.b64decode(kem_ciphertext_b64)

    # Kyber decapsulation
    shared_secret = kem_dec(sk, kem_ciphertext)

    # AES-GCM decryption
    plaintext = aes_decrypt(shared_secret, nonce, ciphertext)

    return jsonify({"plaintext": plaintext})

if __name__ == "__main__":
    app.run(port=8000, debug=True)
