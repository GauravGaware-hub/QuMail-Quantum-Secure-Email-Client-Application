import sqlite3
from contextlib import closing
import bcrypt
import os

DB_PATH = os.path.join(os.path.dirname(__file__), "database", "qumail.db")

def init_db():
    with closing(sqlite3.connect(DB_PATH)) as conn:
        cursor = conn.cursor()
        # Users table for storing email accounts and KM tokens securely (hashed/encrypted in prod)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                km_token TEXT NOT NULL,
                smtp_server TEXT,
                smtp_port INTEGER,
                imap_server TEXT,
                imap_port INTEGER
            )
        ''')
        # Config table for storing app-wide settings if needed
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS config (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )
        ''')
        conn.commit()

def add_user(email, password, km_token,
             smtp_server, smtp_port, imap_server, imap_port):
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    with closing(sqlite3.connect(DB_PATH)) as conn:
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO users (email, password, km_token, smtp_server, smtp_port, imap_server, imap_port)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (email, hashed_password, km_token, smtp_server, smtp_port, imap_server, imap_port))
        conn.commit()

def verify_user(email, password):
    with closing(sqlite3.connect(DB_PATH)) as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT password FROM users WHERE email=?', (email,))
        row = cursor.fetchone()
        if row:
            stored_hash = row[0]
            return bcrypt.checkpw(password.encode('utf-8'), stored_hash)
        return False
    
def get_user(email):
    with closing(sqlite3.connect(DB_PATH)) as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE email=?', (email,))
        return cursor.fetchone()