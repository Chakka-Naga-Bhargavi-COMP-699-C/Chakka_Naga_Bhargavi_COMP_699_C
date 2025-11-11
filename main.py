# weather_food_books_cocktails_gui.py
import os
import io
import json
import csv
import hashlib
import hmac
import secrets
import time
import logging
import threading
import webbrowser
import random
import re
import smtplib
import ssl
from email.mime.text import MIMEText
from datetime import datetime
from typing import Dict, Tuple, List, Optional

import requests
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from PIL import Image, ImageTk

logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")

APP_DIR = os.path.abspath(os.path.dirname(__file__))
USERS_PATH = os.path.join(APP_DIR, "users.json")
HISTORY_DIR = os.path.join(APP_DIR, "history")
CATALOGS_PATH = os.path.join(APP_DIR, "catalogs.json")  # <-- NEW: shared catalogs
os.makedirs(HISTORY_DIR, exist_ok=True)

# =========================
#    Utilities / Helpers
# =========================

def now_iso():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def sha256(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()

def password_hash(password: str, salt: Optional[str] = None) -> Tuple[str, str]:
    """Return (salt, hash)."""
    if not salt:
        salt = secrets.token_hex(16)
    return salt, sha256(salt + password)

def load_json(path: str, default):
    """
    Safe JSON loader.
    Returns default on error. (CatalogManager will additionally notify admins.)
    """
    try:
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
    except Exception as e:
        logging.error(f"Failed to load {path}: {e}")
    return default

def save_json(path: str, data):
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        return True
    except Exception as e:
        logging.error(f"Failed to save {path}: {e}")
        return False

def copy_to_clipboard(root: tk.Tk, text: str):
    try:
        root.clipboard_clear()
        root.clipboard_append(text)
        root.update()
        return True
    except Exception:
        return False

# =========================
#     Admin Notifications
# =========================

class AdminNotifier:
    """
    Very small helper to surface operational alerts to admins via popup.
    - App constructs this and passes to clients that might error (WeatherClient, CatalogManager).
    - Only pops a messagebox if the current user is an admin and wants notifications (Account menu toggle).
    """
    def __init__(self, app_getter):
        # app_getter is a callable returning the current App instance (to avoid circular refs)
        self.app_getter = app_getter

    def _should_notify(self) -> bool:
        app = self.app_getter()
        if not app or not app.current_user:
            return False
        # Show to currently logged-in admin only (local desktop app)
        try:
            return app.auth.is_admin(app.current_user) and app.auth.get_notify(app.current_user)
        except Exception:
            return False

    def alert(self, title: str, message: str):
        logging.warning(f"[ADMIN ALERT] {title}: {message}")
        if self._should_notify():
            try:
                messagebox.showwarning(title, message)
            except Exception:
                pass

# =========================
#          Email
# =========================

class EmailHelper:
    """SMTP email sender (optional). Uses env vars if present."""
    @staticmethod
    def send_reset_email(to_email: str, reset_link: str) -> bool:
        host = os.getenv("SMTP_HOST")
        port = int(os.getenv("SMTP_PORT", "587"))
        user = os.getenv("SMTP_USER")
        pwd  = os.getenv("SMTP_PASSWORD")
        sender = os.getenv("SMTP_FROM", user or "")
        if not (host and port and user and pwd and sender):
            logging.warning("SMTP not configured; cannot send email.")
            return False

        subj = "Password Reset Link"
        body = f"Hello,\n\nClick the link below to reset your password:\n{reset_link}\n\nIf you didn't request this, ignore."
        msg = MIMEText(body, "plain", "utf-8")
        msg["Subject"] = subj
        msg["From"] = sender
        msg["To"] = to_email

        try:
            context = ssl.create_default_context()
            with smtplib.SMTP(host, port, timeout=20) as server:
                server.starttls(context=context)
                server.login(user, pwd)
                server.sendmail(sender, [to_email], msg.as_string())
            return True
        except Exception as e:
            logging.error(f"Email send failed: {e}")
            return False

# =========================
#        Auth Store
# =========================

class AuthManager:
    """
    Stores users in users.json:
    {
      "users": {
         "email@example.com": {
             "salt": "...",
             "passhash": "...",
             "created_at": "...",
             "notify": true,
             "is_admin": false,
             "reset": {"token": "...","exp": 1699999999}   # optional
         },
         ...
      }
    }
    """
    def __init__(self, path=USERS_PATH):
        self.path = path
        self.data = load_json(self.path, {"users": {}})

    def _save(self):
        return save_json(self.path, self.data)

    def exists(self, email: str) -> bool:
        return email in self.data["users"]

    def is_admin(self, email: str) -> bool:
        return bool(self.data["users"].get(email, {}).get("is_admin", False))

    def register(self, email: str, password: str, is_admin: bool = False) -> Tuple[bool, str]:
        email = email.strip().lower()
        if not email or not password:
            return False, "Email and password required."
        if self.exists(email):
            return False, "Email already registered."
        salt, phash = password_hash(password)
        self.data["users"][email] = {
            "salt": salt,
            "passhash": phash,
            "created_at": now_iso(),
            "notify": False,
            "is_admin": bool(is_admin)
        }
        self._save()
        return True, "Registered successfully."

    def authenticate(self, email: str, password: str) -> bool:
        email = email.strip().lower()
        u = self.data["users"].get(email)
        if not u: return False
        salt = u["salt"]
        _, phash = password_hash(password, salt=salt)
        return hmac.compare_digest(phash, u["passhash"])

    def change_password(self, email: str, current_password: str, new_password: str) -> Tuple[bool, str]:
        """NEW: Used by User tab."""
        email = email.strip().lower()
        if not self.authenticate(email, current_password):
            return False, "Current password is incorrect."
        salt, phash = password_hash(new_password)
        self.data["users"][email]["salt"] = salt
        self.data["users"][email]["passhash"] = phash
        self._save()
        return True, "Password changed successfully."

    def start_reset(self, email: str) -> Tuple[bool, str]:
        email = email.strip().lower()
        if not self.exists(email):
            return False, "No account for that email."
        token = secrets.token_urlsafe(24)
        exp = int(time.time()) + 3600  # valid 1 hour
        self.data["users"][email]["reset"] = {"token": token, "exp": exp}
        self._save()
        # App-specific link scheme (no server): app://reset?email=...&token=...
        link = f"app://reset?email={email}&token={token}"
        sent = EmailHelper.send_reset_email(email, link)
        if sent:
            return True, "Reset link emailed."
        else:
            return True, f"Email not configured. Reset link copied to clipboard:\n{link}"

    def finish_reset(self, email: str, token: str, new_password: str) -> Tuple[bool, str]:
        email = email.strip().lower()
        u = self.data["users"].get(email)
        if not u or "reset" not in u:
            return False, "No reset pending."
        rec = u["reset"]
        if int(time.time()) > rec["exp"]:
            return False, "Reset link expired."
        if token != rec["token"]:
            return False, "Invalid reset token."
        salt, phash = password_hash(new_password)
        u["salt"], u["passhash"] = salt, phash
        del u["reset"]
        self._save()
        return True, "Password updated."

    def set_notify(self, email: str, notify: bool):
        email = email.strip().lower()
        if self.exists(email):
            self.data["users"][email]["notify"] = bool(notify)
            self._save()

    def get_notify(self, email: str) -> bool:
        email = email.strip().lower()
        return bool(self.data["users"].get(email, {}).get("notify", False))

    def delete_account(self, email: str) -> bool:
        email = email.strip().lower()
        if self.exists(email):
            del self.data["users"][email]
            self._save()
            # delete history file too
            hpath = HistoryManager.history_path_for(email)
            try:
                if os.path.exists(hpath):
                    os.remove(hpath)
            except Exception as e:
                logging.warning(f"Failed to delete history: {e}")
            return True
        return False
