# 🔐 SecureVault AI

**AI-Powered Password Security and Risk Detection System**  
*College Cybersecurity Demonstration Project*

---

## Overview

SecureVault AI is a browser-based web application that:

- **Stores website credentials** encrypted at rest with AES-256-GCM
- **Analyzes password risk** using an explainable Gradient Boosting machine-learning model trained entirely on synthetic data
- **Generates cryptographically random passwords** using Python's `secrets` module
- **Provides a security dashboard** showing credential risk distribution
- **Supports secure master-password change** with atomic vault key rotation

All passwords stored in the database are encrypted — never plaintext. The vault encryption key is derived from your master password using scrypt and is never written to any file or database.

---

## Technology Stack

| Layer | Technology |
|-------|-----------|
| Web framework | Flask 3.1 |
| UI | Bootstrap 5.3 + custom CSS |
| Database | SQLite (via `sqlite3`) |
| Encryption | AES-256-GCM (`cryptography` library) |
| Key derivation | scrypt (N=32768, r=8, p=1) |
| Password hashing | PBKDF2-SHA256 (`werkzeug`) |
| ML model | Gradient Boosting Classifier (`scikit-learn`) |
| Password generator | `secrets` module (OS CSPRNG) |
| CSRF protection | `flask-wtf` |
| Testing | `pytest` |

---

## Installation

### Prerequisites

- Python 3.9 or later (tested on Python 3.15)
- pip

### Steps

```bash
# 1. Clone or extract the project
cd SecureVault-AI

# 2. (Recommended) Create a virtual environment
python -m venv .venv
.venv\Scripts\activate        # Windows
# source .venv/bin/activate   # macOS / Linux

# 3. Install dependencies
pip install -r requirements.txt

# 4. Create your .env file from the template
copy .env.example .env        # Windows
# cp .env.example .env        # macOS / Linux

# 5. Generate a real SECRET_KEY and paste it into .env
python -c "import secrets; print('SECRET_KEY=' + secrets.token_hex(32))"
# Edit .env and replace the placeholder value

# 6. Train the AI model (one-time, takes ~5 seconds)
python ai/train_model.py

# 7. Start the application
python app.py
```

Open **http://127.0.0.1:5000** in your browser.

---

## Running the Tests

```bash
python -m pytest tests/ -v
```

Expected output: **all tests pass** with no failures or errors.

| Test file | What is tested |
|-----------|---------------|
| `test_auth.py` | Registration, login, salt uniqueness, hash verification |
| `test_crypto.py` | AES-GCM encrypt/decrypt, tamper detection (×3), wrong key |
| `test_database.py` | Schema creation, idempotency |
| `test_generator.py` | Length, character classes, uniqueness, no stdout output |
| `test_kdf.py` | scrypt determinism, salt uniqueness, session encoding |
| `test_key_rotation.py` | Vault re-encryption, HTTP change-password route |
| `test_routes.py` | Register/login/logout HTTP flows |
| `test_routes_extended.py` | Vault CRUD, cross-user isolation, analyzer, generator HTTP |
| `test_vault.py` | Encrypted storage, model-layer isolation |
| `test_analyzer.py` | Feature extraction, risk labels, no password in result |

---

## Features

### 🔑 Password Vault

- Add, view, edit, and delete credentials for any website
- Passwords are encrypted with AES-256-GCM before any database write
- A fresh 12-byte random nonce is generated for every encryption
- The authentication tag detects tampering: if any byte of the ciphertext changes, decryption raises an error
- Each credential shows a risk badge (Unscored / Strong / Medium / Weak)

### 🤖 AI Password Analyzer

- Enter any password to receive a structural risk score: **Low Risk**, **Medium Risk**, or **High Risk**
- The model explains **why** with plain-English risk factors (too short, no symbols, predictable sequence, common password…)
- Provides actionable recommendations
- Shows an Explainable AI feature table (collapsible)
- **The analyzed password is never stored or logged** — only 10 numerical features are passed to the model
- A mandatory disclaimer on every result: *"This score is an estimate based on structural patterns. No score guarantees a password is safe."*

### 🎲 Password Generator

- Generates cryptographically random passwords using `secrets.choice()` (backed by `os.urandom`)
- Configurable length (8–64 characters) and character classes
- Guarantees at least one character from each selected class
- Available on the Analyzer page; generated password can be submitted for analysis in one click

### 🛡️ Security Dashboard

- Summary cards: Total saved / Strong / Medium Risk / Weak credentials
- Quick links to vault and analyzer

### 🔑 Change Master Password

- Verifies current password before any change
- Derives new scrypt key with a fresh random salt
- Re-encrypts every vault entry in memory, then writes atomically
- Clears session, forcing re-login with the new password

---

## Architecture

```
SecureVault-AI/
│
├── app.py                  Flask routes and application factory
├── config.py               Settings loaded from .env
├── database.py             SQLite schema (users + vault tables)
│
├── models/
│   ├── user.py             Registration, login verification
│   └── vault.py            Encrypted credential CRUD + key rotation
│
├── ai/
│   ├── train_model.py      Synthetic data generation + model training
│   ├── analyzer.py         Feature extraction + risk prediction + explanations
│   └── password_model.pkl  Trained model (generated by train_model.py)
│
├── utils/
│   ├── crypto.py           AES-GCM encrypt / decrypt
│   ├── kdf.py              scrypt key derivation + session encoding
│   └── generator.py        Cryptographically random password generator
│
├── templates/              Jinja2 HTML templates (Bootstrap 5)
├── static/                 CSS and JavaScript
└── tests/                  pytest test suite (10 files, 150+ tests)
```

### Key Management Flow

```
REGISTER  →  generate random 32-byte salt  →  store salt (not the key)
           →  hash master password (PBKDF2)  →  store hash

LOGIN     →  verify password against hash
           →  scrypt(password, salt)  →  32-byte vault_key (in memory only)
           →  base64-encode  →  store in signed session cookie

ENCRYPT   →  os.urandom(12)  →  nonce
           →  AES-GCM(vault_key, nonce).encrypt(plaintext)
           →  store base64(nonce || ciphertext || tag) in SQLite

LOGOUT    →  session.clear()  →  vault_key gone
```

---

## Security Limitations

These are known, by-design constraints. They are acceptable for a student demonstration but would need to change in production.

| Limitation | Explanation | Production fix |
|---|---|---|
| Vault key in signed cookie | The AES key is in the cookie (HMAC-signed but not server-side). If the machine's SECRET_KEY is leaked, an attacker could forge cookies. | Use Redis + TTL for server-side session storage. |
| No rate limiting on /login | Unlimited login attempts are permitted. | Add `flask-limiter` (5 attempts/min per IP). |
| SQLite, single-writer | SQLite is unsuitable for concurrent multi-user production load. | Use PostgreSQL + SQLAlchemy. |
| No HTTPS enforcement locally | SESSION_COOKIE_SECURE=False for local HTTP dev. | Deploy behind TLS reverse proxy; set HTTPS=true. |
| AI score is structural only | The model does not know whether a password is in a breach database. | Integrate HaveIBeenPwned k-anonymity API. |
| No two-factor authentication | Password is the only factor. | Add TOTP with `pyotp`. |
| `pickle` for ML model | `pickle` is unsafe if the .pkl file is replaced by an attacker. | Sign model file with HMAC or use a safer serialisation format. |

---

## License

This project is a college demonstration and is not intended for production use.
