# backend/key_store.py
import sqlite3
import os
import time
from typing import Optional

DB_PATH = os.environ.get("QUMAIL_DB", "backend/database/qumail.db")

def _conn():
    return sqlite3.connect(DB_PATH, detect_types=sqlite3.PARSE_DECLTYPES)

def init_key_table():
    with _conn() as c:
        c.execute("""
        CREATE TABLE IF NOT EXISTS keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            owner_email TEXT NOT NULL,
            key_blob BLOB NOT NULL,
            length INTEGER NOT NULL,
            used_offset INTEGER DEFAULT 0,
            metadata TEXT,
            created_at INTEGER
        )""")
        c.execute("CREATE INDEX IF NOT EXISTS idx_keys_owner ON keys(owner_email)")
        c.commit()

def add_key(owner_email: str, key_bytes: bytes, metadata: Optional[str] = None):
    with _conn() as c:
        c.execute("INSERT INTO keys (owner_email, key_blob, length, used_offset, metadata, created_at) VALUES (?, ?, ?, 0, ?, ?)",
                  (owner_email, key_bytes, len(key_bytes), metadata or "", int(time.time())))
        c.commit()
        return c.lastrowid

def reserve_key(owner_email: str, num_bytes: int):
    """
    Find a key row that has at least num_bytes remaining and reserve (advance used_offset).
    Returns (key_id, offset, slice_bytes) where slice_bytes is the byte chunk to use.
    """
    with _conn() as c:
        rows = c.execute("SELECT id, length, used_offset FROM keys WHERE owner_email=? ORDER BY created_at", (owner_email,)).fetchall()
        for r in rows:
            kid, length, used = r
            remaining = length - used
            if remaining >= num_bytes:
                # read that slice
                cur = c.execute("SELECT substr(key_blob, ?, ?) FROM keys WHERE id=?", (used+1, num_bytes, kid)).fetchone()
                chunk = cur[0]
                new_used = used + num_bytes
                c.execute("UPDATE keys SET used_offset=? WHERE id=?", (new_used, kid))
                c.commit()
                return kid, used, chunk
    raise ValueError("No key material available with sufficient length")

def get_key_status(owner_email: str):
    with _conn() as c:
        rows = c.execute("SELECT id, length, used_offset, metadata, created_at FROM keys WHERE owner_email=?", (owner_email,)).fetchall()
        return [{"id": r[0], "length": r[1], "used": r[2], "meta": r[3], "created_at": r[4]} for r in rows]
