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
