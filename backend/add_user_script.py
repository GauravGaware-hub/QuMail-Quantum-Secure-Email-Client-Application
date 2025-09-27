# add_user_script.py - prompts for credentials; uses env vars if present
import os
import getpass
from database import add_user, init_db

def main():
    init_db()
    email = os.environ.get('SEED_EMAIL') or input("Email: ").strip()
    password = os.environ.get('SEED_PASSWORD') or getpass.getpass("Password: ")
    km_token = os.environ.get('KM_API_TOKEN', 'demo-token')
    smtp_server = os.environ.get('EMAIL_SMTP_SERVER', 'smtp.gmail.com')
    smtp_port = int(os.environ.get('EMAIL_SMTP_PORT', 587))
    imap_server = os.environ.get('EMAIL_IMAP_SERVER', 'imap.gmail.com')
    imap_port = int(os.environ.get('EMAIL_IMAP_PORT', 993))

    add_user(email, password, km_token, smtp_server, smtp_port, imap_server, imap_port)
    print(f"User {email} added (hashed password stored).")

if __name__ == "__main__":
    main()
