# config.py (use environment variables for safety)
import os

KM_API_URL = os.environ.get('KM_API_URL', "http://127.0.0.1:5000/api/keys")
KM_API_TOKEN = os.environ.get('KM_API_TOKEN', "demo-token")

EMAIL_SMTP_SERVER = os.environ.get('EMAIL_SMTP_SERVER', "smtp.gmail.com")
EMAIL_SMTP_PORT = int(os.environ.get('EMAIL_SMTP_PORT', 587))
EMAIL_IMAP_SERVER = os.environ.get('EMAIL_IMAP_SERVER', "imap.gmail.com")
EMAIL_IMAP_PORT = int(os.environ.get('EMAIL_IMAP_PORT', 993))

AES_KEY_LENGTH = int(os.environ.get('AES_KEY_LENGTH', 32))
