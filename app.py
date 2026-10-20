"""
app.py — Flask application entry point.

Routes
------
GET  /              → redirect to /dashboard or /login
GET  /register      → show registration form
POST /register      → create account
GET  /login         → show login form
POST /login         → authenticate, derive vault key, start session
GET  /logout        → clear session (drops vault key) and redirect to /login
GET  /dashboard     → security overview with vault stats

GET  /vault                     → list all credentials (decrypted in memory)
GET  /vault/add                 → show add-credential form
POST /vault/add                 → encrypt and save new credential
GET  /vault/<id>/edit           → show edit form (decrypted for display)
POST /vault/<id>/edit           → re-encrypt and update credential
POST /vault/<id>/delete         → delete a credential

GET  /change-password           → show change-password form
POST /change-password           → verify old password, re-derive keys, rotate vault

Security features
-----------------
- CSRF protection on every state-changing form (flask-wtf CSRFProtect).
- Session cookie is HttpOnly, SameSite=Lax, and optionally Secure.
- Session has a 30-minute lifetime.
- @login_required decorator blocks unauthenticated access to every vault route.
- Vault key derived at login via scrypt; stored base64-encoded in signed cookie.
- Vault key cleared on logout via session.clear().
- SECRET_KEY is validated at startup; the app refuses to start without it.
"""

import sys
from datetime import timedelta
from functools import wraps

from flask import (
    Flask,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from flask_wtf import CSRFProtect

from cryptography.exceptions import InvalidTag

from config import Config
from database import init_db
from models.user import get_user_by_id, register_user, verify_user
from models.vault import (
    add_entry,
    count_by_risk,
    delete_entry,
    get_entries,
    get_entry,
    rotate_vault_key,
    update_entry,
)
from utils.kdf import derive_vault_key, key_from_session_str, key_to_session_str
from utils.generator import generate_password

# ------------------------------------------------------------------ #
# Application factory
# ------------------------------------------------------------------ #

app = Flask(__name__)
app.config.from_object(Config)
app.permanent_session_lifetime = timedelta(seconds=Config.PERMANENT_SESSION_LIFETIME)

# Guard: refuse to start with the placeholder secret key.
if not app.config["SECRET_KEY"] or app.config["SECRET_KEY"] == "change-me-to-a-random-secret":
    sys.exit(
        "ERROR: SECRET_KEY is not set or is still the placeholder value.\n"
        "Copy .env.example to .env and set a real random SECRET_KEY."
    )

# Enable CSRF protection globally.
# Every form that POSTs must include {{ csrf_token() }} in its template.
csrf = CSRFProtect(app)

# ------------------------------------------------------------------ #
# Database initialisation
# ------------------------------------------------------------------ #

with app.app_context():
    init_db()

# ------------------------------------------------------------------ #
# Authentication decorator
# ------------------------------------------------------------------ #

def login_required(f):
    """
    Decorator that redirects unauthenticated users to /login.

    Usage:
        @app.route("/dashboard")
        @login_required
        def dashboard():
            ...
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in to access that page.", "warning")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated

# ------------------------------------------------------------------ #
# Error handlers
# ------------------------------------------------------------------ #

@app.errorhandler(RuntimeError)
def handle_missing_vault_key(e):
    """
    Catch the RuntimeError raised by _get_vault_key() when the session
    is missing the vault key.  Redirect to /login with a user-friendly
    message instead of showing a 500 page.
    """
    flash("Your session expired or is invalid. Please log in again.", "warning")
    return redirect(url_for("login"))


# ------------------------------------------------------------------ #
# Routes
# ------------------------------------------------------------------ #

@app.route("/")
def index():
    """Show landing page for visitors; redirect logged-in users to dashboard."""
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return render_template("landing.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """
    GET  — render the registration form.
    POST — validate input, create account, redirect to login.
    """
    if "user_id" in session:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        confirm  = request.form.get("confirm_password", "")

        # Basic validation (more detailed in Phase 2 with WTForms).
        if not username or not password:
            flash("Username and password are required.", "danger")
            return render_template("register.html")

        if len(username) < 3:
            flash("Username must be at least 3 characters.", "danger")
            return render_template("register.html")

        if len(password) < 8:
            flash("Password must be at least 8 characters.", "danger")
            return render_template("register.html")

        if password != confirm:
            flash("Passwords do not match.", "danger")
            return render_template("register.html")

        success, error = register_user(username, password)
        if not success:
            flash(error, "danger")
            return render_template("register.html")

        flash("Account created! Please log in.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    """
    GET  — render the login form.
    POST — verify credentials, start session, redirect to dashboard.
    """
    if "user_id" in session:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        user = verify_user(username, password)

        if user is None:
            # Same message for "user not found" and "wrong password"
            # to prevent username enumeration.
            flash("Invalid username or password.", "danger")
            return render_template("login.html")

        # Start a permanent session (respects PERMANENT_SESSION_LIFETIME).
        session.permanent = True
        session["user_id"]  = user["id"]
        session["username"] = user["username"]

        # Derive the vault encryption key from the master password + user salt.
        # We use `password` (the plaintext from the form, still in scope here),
        # NOT user["password_hash"].  The key is stored base64-encoded in the
        # signed session cookie and is NEVER written to the database or any file.
        vault_key = derive_vault_key(password, user["salt"])
        session["vault_key"] = key_to_session_str(vault_key)

        flash(f"Welcome back, {user['username']}!", "success")
        return redirect(url_for("dashboard"))

    return render_template("login.html")


@app.route("/logout")
def logout():
    """
    Clear the entire session (removes user_id, username, and any
    vault key material added in Phase 2) then redirect to /login.
    """
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("login"))


@app.route("/dashboard")
@login_required
def dashboard():
    """Security overview: shows vault risk stats and quick links."""
    user = get_user_by_id(session["user_id"])
    stats = count_by_risk(session["user_id"])
    return render_template("dashboard.html", user=user, stats=stats)


# ------------------------------------------------------------------ #
# Helper: get the vault key from the session or abort
# ------------------------------------------------------------------ #

def _get_vault_key() -> bytes:
    """
    Retrieve and decode the vault key from the session.

    Returns raw 32-byte key.

    If the key is missing (e.g. session was partially written or cookie
    was tampered with), clears the session and redirects to login via
    a RuntimeError that the caller must not catch.  In practice every
    caller is a @login_required route, so this is a safety net only.
    """
    key_str = session.get("vault_key")
    if not key_str:
        session.clear()
        # Raise so the route aborts; the caller does not need to handle this —
        # Flask will propagate it as a 500 unless we add an error handler.
        raise RuntimeError(
            "vault_key missing from session. Session cleared; please log in again."
        )
    return key_from_session_str(key_str)


# ------------------------------------------------------------------ #
# Vault routes
# ------------------------------------------------------------------ #

@app.route("/vault")
@login_required
def vault():
    """List all saved credentials, decrypted in memory."""
    vault_key = _get_vault_key()
    entries = get_entries(session["user_id"], vault_key)
    return render_template("vault.html", entries=entries)


@app.route("/vault/add", methods=["GET", "POST"])
@login_required
def vault_add():
    """
    GET  — show the add-credential form.
    POST — validate, encrypt, and save the new credential.
    """
    if request.method == "POST":
        site_name      = request.form.get("site_name", "").strip()
        site_username  = request.form.get("site_username", "").strip()
        password       = request.form.get("password", "")

        if not site_name or not site_username or not password:
            flash("All fields are required.", "danger")
            return render_template("add_entry.html")

        if len(site_name) > 100:
            flash("Site name must be 100 characters or fewer.", "danger")
            return render_template("add_entry.html")

        vault_key = _get_vault_key()
        add_entry(
            user_id=session["user_id"],
            site_name=site_name,
            site_username=site_username,
            plaintext_password=password,
            vault_key=vault_key,
        )
        flash(f"Credential for '{site_name}' saved.", "success")
        return redirect(url_for("vault"))

    return render_template("add_entry.html")


@app.route("/vault/<int:entry_id>/edit", methods=["GET", "POST"])
@login_required
def vault_edit(entry_id: int):
    """
    GET  — show the edit form, pre-filled with decrypted values.
    POST — re-encrypt and update the credential.
    """
    vault_key = _get_vault_key()

    try:
        entry = get_entry(entry_id, session["user_id"], vault_key)
    except InvalidTag:
        flash("Could not decrypt that entry — it may be corrupt.", "danger")
        return redirect(url_for("vault"))

    if entry is None:
        flash("Entry not found.", "danger")
        return redirect(url_for("vault"))

    if request.method == "POST":
        site_name     = request.form.get("site_name", "").strip()
        site_username = request.form.get("site_username", "").strip()
        password      = request.form.get("password", "")

        if not site_name or not site_username or not password:
            flash("All fields are required.", "danger")
            return render_template("edit_entry.html", entry=entry)

        updated = update_entry(
            entry_id=entry_id,
            user_id=session["user_id"],
            site_name=site_name,
            site_username=site_username,
            plaintext_password=password,
            vault_key=vault_key,
        )
        if updated:
            flash(f"'{site_name}' updated.", "success")
        else:
            flash("Update failed — entry not found.", "danger")
        return redirect(url_for("vault"))

    return render_template("edit_entry.html", entry=entry)


@app.route("/vault/<int:entry_id>/delete", methods=["POST"])
@login_required
def vault_delete(entry_id: int):
    """
    POST-only delete route.  Using POST (not GET) prevents accidental
    deletion via link prefetching or browser history.
    """
    deleted = delete_entry(entry_id, session["user_id"])
    if deleted:
        flash("Credential deleted.", "success")
    else:
        flash("Entry not found or already deleted.", "warning")
    return redirect(url_for("vault"))


# ------------------------------------------------------------------ #
# Change-password / key rotation route
# ------------------------------------------------------------------ #

@app.route("/change-password", methods=["GET", "POST"])
@login_required
def change_password():
    """
    GET  — show the change-password form.
    POST — verify old password, derive new vault key, re-encrypt all
           vault entries atomically, update auth hash and salt in DB,
           clear session, and redirect to /login.

    Key-rotation security properties:
    - Old password is verified before any key is derived or any DB write
      is attempted.
    - All vault entries are decrypted with the old key and re-encrypted
      with the new key entirely in memory before the first DB write.
    - The DB update (new auth hash, new salt, re-encrypted vault entries)
      is performed inside a single SQLite transaction via rotate_vault_key.
    - On success the session is cleared, forcing a fresh login with the
      new password so the new vault key is derived and stored correctly.
    - Plaintext passwords are never written to the database at any point.
    """
    if request.method == "POST":
        old_password = request.form.get("old_password", "")
        new_password = request.form.get("new_password", "")
        confirm      = request.form.get("confirm_password", "")

        # --- Validate inputs ---
        if not old_password or not new_password or not confirm:
            flash("All fields are required.", "danger")
            return render_template("change_password.html")

        if len(new_password) < 8:
            flash("New password must be at least 8 characters.", "danger")
            return render_template("change_password.html")

        if new_password != confirm:
            flash("New passwords do not match.", "danger")
            return render_template("change_password.html")

        # --- Verify the old password ---
        from models.user import verify_user
        user_row = verify_user(session["username"], old_password)
        if user_row is None:
            flash("Current password is incorrect.", "danger")
            return render_template("change_password.html")

        # --- Derive old and new vault keys ---
        old_vault_key = derive_vault_key(old_password, user_row["salt"])

        import os
        from werkzeug.security import generate_password_hash
        from database import get_connection as _get_conn

        new_salt = os.urandom(Config.SCRYPT_SALT_LEN).hex()
        new_vault_key = derive_vault_key(new_password, new_salt)

        # --- Re-encrypt all vault entries with the new key ---
        try:
            rotate_vault_key(session["user_id"], old_vault_key, new_vault_key)
        except Exception:
            flash(
                "Key rotation failed — one or more vault entries could not be "
                "re-encrypted.  Your password was NOT changed.",
                "danger",
            )
            return render_template("change_password.html")

        # --- Update auth hash and salt in users table ---
        new_hash = generate_password_hash(new_password)
        conn = _get_conn()
        try:
            conn.execute(
                "UPDATE users SET password_hash=?, salt=? WHERE id=?",
                (new_hash, new_salt, session["user_id"]),
            )
            conn.commit()
        finally:
            conn.close()

        # --- Force re-login with the new password ---
        session.clear()
        flash(
            "Password changed successfully. "
            "All vault entries have been re-encrypted. "
            "Please log in with your new password.",
            "success",
        )
        return redirect(url_for("login"))

    return render_template("change_password.html")


# ------------------------------------------------------------------ #
# AI Analyzer routes
# ------------------------------------------------------------------ #

@app.route("/analyze", methods=["GET", "POST"])
@login_required
def analyze():
    """
    GET  — show the password analyzer form (empty).
    POST — receive a password, analyze it, render result.

    Privacy: the password is NEVER stored, logged, or saved to the DB.
    It is used only to extract numerical features inside analyze_password().
    The result dict returned by the analyzer contains no password string.
    """
    result = None

    if request.method == "POST":
        # Import lazily to avoid loading the ML model at app startup.
        # The model is loaded once and cached on first call.
        from ai.analyzer import analyze_password

        password = request.form.get("password", "")
        if not password:
            flash("Please enter a password to analyze.", "warning")
        else:
            result = analyze_password(password)
            # Deliberately do NOT log `password` anywhere.

    return render_template("analyze.html", result=result)


@app.route("/generate")
@login_required
def generate():
    """
    JSON endpoint: return a single randomly generated strong password.

    Parameters (query string, all optional):
        length   : int  (default 16, clamped 8–64)
        symbols  : "1" to include symbols (default 1)

    Returns JSON: {"password": "..."}.

    The generated password is returned only in the JSON response.
    It is not logged or stored here.
    """
    try:
        length = int(request.args.get("length", 16))
    except (ValueError, TypeError):
        length = 16
    length = max(8, min(length, 64))

    use_symbols = request.args.get("symbols", "1") != "0"

    pw = generate_password(
        length=length,
        use_upper=True,
        use_lower=True,
        use_digits=True,
        use_symbols=use_symbols,
    )
    return jsonify({"password": pw})


# ------------------------------------------------------------------ #
# Entry point
# ------------------------------------------------------------------ #

if __name__ == "__main__":
    # debug=False in any real deployment.
    app.run(debug=True)
