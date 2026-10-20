"""
database.py — SQLite database setup.

Call init_db() once at application startup to create the tables.
Safe to call multiple times; existing tables are never dropped.
"""

import sqlite3
from config import Config


def get_connection() -> sqlite3.Connection:
    """
    Open and return a connection to the SQLite database.

    row_factory=sqlite3.Row lets us access columns by name
    (e.g. row['username']) instead of by index (row[0]).
    """
    conn = sqlite3.connect(Config.DATABASE_PATH)
    conn.row_factory = sqlite3.Row

    # Enforce foreign-key constraints (SQLite disables them by default).
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db() -> None:
    """
    Create all tables if they do not already exist.

    Tables
    ------
    users
        Stores one row per registered user.
        - password_hash  : PBKDF2-SHA256 hash of the master password.
                           Used only for login verification. Never plaintext.
        - salt           : 32 random bytes (hex string) generated at
                           registration. Used in Phase 2 to derive the
                           AES-GCM vault encryption key via scrypt.
                           Storing the salt is safe — it is not a secret.

    vault
        Stores one encrypted credential per row.
        Created here so the schema is complete, but populated in Phase 2.
        - encrypted_password : base64(nonce || ciphertext || auth_tag).
                               Never plaintext.
        - risk_score         : 0-100 AI score assigned at save time.
    """
    conn = get_connection()
    try:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                username      TEXT    NOT NULL UNIQUE,
                password_hash TEXT    NOT NULL,
                salt          TEXT    NOT NULL,
                created_at    DATETIME DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS vault (
                id                  INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id             INTEGER NOT NULL
                                        REFERENCES users(id) ON DELETE CASCADE,
                site_name           TEXT    NOT NULL,
                site_username       TEXT    NOT NULL,
                encrypted_password  TEXT    NOT NULL,
                risk_score          INTEGER DEFAULT 0,
                created_at          DATETIME DEFAULT (datetime('now'))
            );
        """)
        conn.commit()
    finally:
        conn.close()
