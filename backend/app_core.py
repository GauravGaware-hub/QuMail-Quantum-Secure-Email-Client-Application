from km_client import KMClient
from encryption import otp_encrypt, otp_decrypt, aes_encrypt, aes_decrypt, pqc_encrypt, pqc_decrypt  
from email_client import EmailClient
from database import init_db, add_user, get_user, verify_user
from flask import jsonify, request

# Security Levels
SECURITY_LEVEL_OTP = 1
SECURITY_LEVEL_AES = 2
SECURITY_LEVEL_PQC = 3
SECURITY_LEVEL_NONE = 4


class QuMailApp:
    def __init__(self):
        init_db()
        self.km_client = KMClient()
        self.email_client = None
        self.current_user = None
        self.security_level = SECURITY_LEVEL_NONE

    def login(self, email, password):
        if not verify_user(email, password):
            return False
        user = get_user(email)
        if not user:
            return False

        # Setup user session and email client
        self.current_user = {
            'email': user[1],
            'password': password,
            'km_token': user[3],
            'smtp_server': user[4],
            'smtp_port': user[5],
            'imap_server': user[6],
            'imap_port': user[7]
        }
        self.email_client = EmailClient(
            email_addr=user[1],
            password=password,
            smtp_server=user[4],
            smtp_port=user[5],
            imap_server=user[6],
            imap_port=user[7]
        )
        self.km_client.token = user[3]
        return True

    def register_user(self, email, password, km_token,
                      smtp_server, smtp_port, imap_server, imap_port):
        add_user(email, password, km_token, smtp_server, smtp_port, imap_server, imap_port)

    def set_security_level(self, level):
        if level in (SECURITY_LEVEL_OTP, SECURITY_LEVEL_AES, SECURITY_LEVEL_PQC, SECURITY_LEVEL_NONE):
            self.security_level = level
        else:
            raise ValueError("Invalid security level")

    def _ensure_logged_in(self):
        if not self.current_user or not self.email_client:
            raise Exception("User is not logged in")

    def encrypt_message(self, plaintext: bytes) -> bytes:
        self._ensure_logged_in()
        key_length = len(plaintext) if self.security_level == SECURITY_LEVEL_OTP else 32
        key = self.km_client.get_quantum_key(self.current_user['email'], key_length)
        if not key:
            raise Exception("Failed to get quantum key from KM")

        if self.security_level == SECURITY_LEVEL_OTP:
            return otp_encrypt(plaintext, key)
        elif self.security_level == SECURITY_LEVEL_AES:
            return aes_encrypt(plaintext, key)
        elif self.security_level == SECURITY_LEVEL_PQC:
            return pqc_encrypt(plaintext, key)
        elif self.security_level == SECURITY_LEVEL_NONE:
            return plaintext

    def decrypt_message(self, ciphertext: bytes) -> bytes:
        self._ensure_logged_in()
        key_length = len(ciphertext) if self.security_level == SECURITY_LEVEL_OTP else 32
        key = self.km_client.get_quantum_key(self.current_user['email'], key_length)
        if not key:
            raise Exception("Failed to get quantum key from KM")

        if self.security_level == SECURITY_LEVEL_OTP:
            return otp_decrypt(ciphertext, key)
        elif self.security_level == SECURITY_LEVEL_AES:
            return aes_decrypt(ciphertext, key)
        elif self.security_level == SECURITY_LEVEL_PQC:
            return pqc_decrypt(ciphertext, key)
        elif self.security_level == SECURITY_LEVEL_NONE:
            return ciphertext

    def send_secure_email(self, to_addr, subject, plaintext_body: bytes,
                          attachment_bytes=None, attachment_name=None):
        self._ensure_logged_in()
        encrypted_body = self.encrypt_message(plaintext_body)
        encrypted_attachment = None
        if attachment_bytes:
            encrypted_attachment = self.encrypt_message(attachment_bytes)
        self.email_client.send_email(to_addr, subject, encrypted_body,
                                     encrypted_attachment, attachment_name)

    def receive_secure_emails(self):
        self._ensure_logged_in()
        emails = self.email_client.fetch_unread_emails()
        decrypted_emails = []
        for mail in emails:
            try:
                decrypted_body = self.decrypt_message(mail['body_bytes'])
                decrypted_attachments = []
                for att_name, att_data in mail['attachments']:
                    dec_att = self.decrypt_message(att_data)
                    decrypted_attachments.append((att_name, dec_att))
                decrypted_emails.append({
                    'from': mail['from'],
                    'subject': mail['subject'],
                    'body': decrypted_body,
                    'attachments': decrypted_attachments
                })
            except Exception as e:
                print(f"Error decrypting email: {e}")
        return decrypted_emails