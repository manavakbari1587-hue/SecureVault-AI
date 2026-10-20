"""
config.py — Application configuration.

Reads secrets from a .env file (or real environment variables).
Never put actual secret values in this file.
"""

import os
from dotenv import load_dotenv

# Load variables from .env into the process environment.
load_dotenv()


class Config:
    # ------------------------------------------------------------------ #
    # Flask core
    # ------------------------------------------------------------------ #

    # Signs session cookies. Must be long, random, and kept secret.
    # If missing, the app refuses to start (see app.py guard).
    SECRET_KEY: str = os.environ.get("SECRET_KEY", "")

    # ------------------------------------------------------------------ #
    # Session cookie hardening
    # ------------------------------------------------------------------ #

    # JavaScript cannot read the session cookie — blocks XSS theft.
    SESSION_COOKIE_HTTPONLY: bool = True

    # Cookie is only sent for same-site requests — reduces CSRF risk.
    SESSION_COOKIE_SAMESITE: str = "Lax"

    # Cookie is only sent over HTTPS in production.
    # Set to False during local HTTP development if needed.
    SESSION_COOKIE_SECURE: bool = os.environ.get("HTTPS", "false").lower() == "true"

    # Session expires after 30 minutes of inactivity.
    PERMANENT_SESSION_LIFETIME: int = 1800  # seconds

    # ------------------------------------------------------------------ #
    # Database
    # ------------------------------------------------------------------ #

    DATABASE_PATH: str = os.environ.get("DATABASE_PATH", "securevault.db")

    # ------------------------------------------------------------------ #
    # scrypt key-derivation parameters (for Phase 2 vault encryption)
    # Documented here so they are easy to review and adjust.
    # NIST SP 800-132 / OWASP recommended minimums for 2024.
    # ------------------------------------------------------------------ #

    # CPU/memory cost factor. Must be a power of 2.
    # Higher = harder to brute-force, slower to derive.
    SCRYPT_N: int = 32768   # 2^15

    # Block size — controls memory usage per iteration.
    SCRYPT_R: int = 8

    # Parallelisation factor.
    SCRYPT_P: int = 1

    # Length of the derived key in bytes (32 bytes = AES-256).
    SCRYPT_KEY_LEN: int = 32

    # Length of the random salt generated per user (bytes).
    SCRYPT_SALT_LEN: int = 32
