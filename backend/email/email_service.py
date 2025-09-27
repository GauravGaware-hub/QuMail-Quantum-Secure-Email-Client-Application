from km_client import KMClient, encrypt_email_content, decrypt_email_content
import time

class EmailService:
    def __init__(self):
        self.km_client = KMClient()
        self.key_cache = {}  # user_email: (key_bytes, timestamp)
        self.key_expiry_seconds = 300  # 5 minutes for example

    def get_key(self, user_email):
        entry = self.key_cache.get(user_email)
        if entry:
            key, timestamp = entry
            if time.time() - timestamp < self.key_expiry_seconds:
                return key
        key = self.km_client.get_quantum_key(user_email, 32)
        if key:
            self.key_cache[user_email] = (key, time.time())
            return key
        return None
        
    def send_email(self, sender_email, recipient_email, plaintext_content):
        key = self.get_key(recipient_email)
        if not key:
            print("Failed to get quantum key for recipient.")
            return None

        encrypted = encrypt_email_content(key, plaintext_content)
        email_package = {
            'sender': sender_email,
            'recipient': recipient_email,
            'encrypted_content': encrypted
        }
        print(f"Email sent to {recipient_email} (encrypted).")
        return email_package

    def receive_email(self, email_package):
        recipient_email = email_package.get('recipient')
        encrypted = email_package.get('encrypted_content')

        key = self.get_key(recipient_email)
        if not key:
            print("Failed to get quantum key for recipient.")
            return None

        try:
            plaintext = decrypt_email_content(key, encrypted['nonce'], encrypted['ciphertext'])
            print(f"Email received by {recipient_email}:")
            print(plaintext)
            return plaintext
        except Exception as e:
            print(f"Failed to decrypt email: {e}")
            return None