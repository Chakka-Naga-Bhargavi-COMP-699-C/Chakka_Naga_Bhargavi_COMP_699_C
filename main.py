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
# =========================
#      History Store
# =========================

class HistoryManager:
    """
    Stores history per user in history/history_<email>.json:
    [
      {
        "timestamp": "...",
        "type": "food|book|drink",
        "label": "Lasagna",
        "metadata": {...source ids...},
        "weather": {...snapshot from WeatherTab.latest...}
      }, ...
    ]
    """
    @staticmethod
    def history_path_for(email: str) -> str:
        safe = re.sub(r"[^a-zA-Z0-9_.-]+", "_", email)
        return os.path.join(HISTORY_DIR, f"history_{safe}.json")

    def __init__(self, user_email: str):
        self.user_email = user_email
        self.path = self.history_path_for(user_email)
        self.items = load_json(self.path, [])

    def add(self, item_type: str, label: str, metadata: Dict, weather_snapshot: Dict):
        entry = {
            "timestamp": now_iso(),
            "type": item_type,
            "label": label,
            "metadata": metadata or {},
            "weather": weather_snapshot or {},
        }
        self.items.append(entry)
        self.save()

    def delete_index(self, idx: int):
        if 0 <= idx < len(self.items):
            del self.items[idx]
            self.save()

    def save(self):
        save_json(self.path, self.items)

    def export_csv(self, filepath: str, selection: Optional[List[int]] = None):
        rows = [self.items[i] for i in (selection or range(len(self.items)))]

        with open(filepath, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["timestamp", "type", "label", "metadata", "weather"])
            for r in rows:
                w.writerow([r["timestamp"], r["type"], r["label"],
                            json.dumps(r["metadata"], ensure_ascii=False),
                            json.dumps(r["weather"], ensure_ascii=False)])

    def export_json(self, filepath: str, selection: Optional[List[int]] = None):
        rows = [self.items[i] for i in (selection or range(len(self.items)))]

        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(rows, f, indent=2, ensure_ascii=False)

# =========================
#        Catalogs (NEW)
# =========================

class CatalogManager:
    """
    Simple local catalogs for admin CRUD.
    Schema:
    {
      "foods": ["Mac and Cheese", "Ramen", ...],
      "beverages": ["Mango shake", "Iced Tea", ...],
      "books": ["The Hobbit", "Atomic Habits", ...]
    }
    """
    DEFAULT = {"foods": [], "beverages": [], "books": []}

    def __init__(self, path: str, notifier: Optional[AdminNotifier] = None):
        self.path = path
        self.notifier = notifier
        self.data = self._load_with_guard()

    def _load_with_guard(self):
        data = None
        try:
            if os.path.exists(self.path):
                with open(self.path, "r", encoding="utf-8") as f:
                    data = json.load(f)
        except Exception as e:
            logging.error(f"Catalog load failed: {e}")
            if self.notifier:
                self.notifier.alert(
                    "Catalog Error",
                    "Catalogs could not be read (file may be corrupted). A fresh catalog will be created."
                )
        if not isinstance(data, dict):
            data = json.loads(json.dumps(self.DEFAULT))  # deep copy
            self._save_with_guard(data)
        # normalize keys
        for k in ("foods", "beverages", "books"):
            data.setdefault(k, [])
            if not isinstance(data[k], list):
                data[k] = []
        return data

    def _save_with_guard(self, data: dict) -> bool:
        ok = save_json(self.path, data)
        if not ok and self.notifier:
            self.notifier.alert("Catalog Save Error", "Failed to save catalogs to disk.")
        return ok

    def all(self) -> dict:
        return self.data

    def add_item(self, category: str, value: str) -> bool:
        category = category.lower()
        if category not in self.data:
            self.data[category] = []
        if value and value not in self.data[category]:
            self.data[category].append(value)
            return self._save_with_guard(self.data)
        return False

    def edit_item(self, category: str, old_value: str, new_value: str) -> bool:
        category = category.lower()
        lst = self.data.get(category, [])
        try:
            idx = lst.index(old_value)
            lst[idx] = new_value
            return self._save_with_guard(self.data)
        except ValueError:
            return False

    def delete_item(self, category: str, value: str) -> bool:
        category = category.lower()
        lst = self.data.get(category, [])
        try:
            lst.remove(value)
            return self._save_with_guard(self.data)
        except ValueError:
            return False

# -------------------------------
#            API Clients
# -------------------------------

class WeatherClient:
    """Lightweight OpenWeatherMap wrapper for current weather."""
    def __init__(self, api_key: str, notifier: Optional[AdminNotifier] = None):
        self.api_key = api_key
        self.notifier = notifier

    def current_by_city(self, city: str) -> Dict:
        url = "https://api.openweathermap.org/data/2.5/weather"
        params = {"q": city, "appid": self.api_key, "units": "metric"}
        try:
            r = requests.get(url, params=params, timeout=12)
            r.raise_for_status()
            data = r.json()
            if not data or "weather" not in data or "main" not in data:
                raise ValueError("Unexpected weather payload")
            weather = data["weather"][0]
            return {
                "city": data.get("name") or city,
                "description": weather.get("description", "").capitalize(),
                "temp_c": data["main"].get("temp"),
                "icon": weather.get("icon"),         # e.g. '10d'
                "feels_like": data["main"].get("feels_like"),
                "humidity": data["main"].get("humidity"),
                "wind": (data.get("wind") or {}).get("speed"),
                "raw": data,
            }
        except Exception as e:
            logging.error(f"Weather error: {e}")
            # NEW: Let admins know something went wrong
            if self.notifier:
                self.notifier.alert("Weather API Error", f"Failed to fetch weather: {e}")
            return {"error": str(e)}

    @staticmethod
    def icon_url(icon_code: str) -> str:
        return f"https://openweathermap.org/img/wn/{icon_code}@2x.png"

class SpoonacularClient:
    """Spoonacular recipe search (complexSearch)."""
    def __init__(self, api_key: str):
        self.api_key = api_key

    def search(self, query: str, number: int = 8, tags: Optional[List[str]] = None) -> List[Dict]:
        url = "https://api.spoonacular.com/recipes/complexSearch"
        params = {
            "apiKey": self.api_key,
            "query": query,
            "number": number,
            "addRecipeInformation": True,
            "instructionsRequired": True,
        }
        if tags:
            params["diet"] = ",".join(tags)  # or use cuisine/intolerances if you prefer
        try:
            r = requests.get(url, params=params, timeout=12)
            r.raise_for_status()
            data = r.json()
            return data.get("results", [])
        except Exception as e:
            logging.error(f"Spoonacular error: {e}")
            return []

class GoogleBooksClient:
    """Google Books simple search wrapper."""
    def __init__(self, api_key: str):
        self.api_key = api_key

    def search(self, query: str, max_results: int = 20, start_index: int = 0) -> List[Dict]:
        url = "https://www.googleapis.com/books/v1/volumes"
        params = {
            "q": query,
            "key": self.api_key,
            "maxResults": max(1, min(max_results, 40)),
            "startIndex": max(0, start_index),
            "printType": "books"
        }
        try:
            r = requests.get(url, params=params, timeout=12)
            r.raise_for_status()
            data = r.json()
            return data.get("items", [])
        except Exception as e:
            logging.error(f"Google Books error: {e}")
            return []

class CocktailDBClient:
    """TheCocktailDB queries."""
    BASE = "https://www.thecocktaildb.com/api/json/v1/1"

    def search_by_name(self, name: str) -> List[Dict]:
        try:
            r = requests.get(f"{self.BASE}/search.php", params={"s": name}, timeout=12)
            r.raise_for_status()
            data = r.json()
            return data.get("drinks") or []
        except Exception as e:
            logging.error(f"CocktailDB error: {e}")
            return []

    def filter_by_alcoholic(self, kind: str) -> List[Dict]:
        try:
            r = requests.get(f"{self.BASE}/filter.php", params={"a": kind}, timeout=12)
            r.raise_for_status()
            data = r.json()
            return data.get("drinks") or []
        except Exception as e:
            logging.error(f"CocktailDB error: {e}")
            return []

    def filter_by_ingredient(self, ingredient: str) -> List[Dict]:
        try:
            r = requests.get(f"{self.BASE}/filter.php", params={"i": ingredient}, timeout=12)
            r.raise_for_status()
            data = r.json()
            return data.get("drinks") or []
        except Exception as e:
            logging.error(f"CocktailDB error: {e}")
            return []

    def lookup_by_id(self, drink_id: str) -> Optional[Dict]:
        try:
            r = requests.get(f"{self.BASE}/lookup.php", params={"i": drink_id}, timeout=12)
            r.raise_for_status()
            data = r.json()
            drinks = data.get("drinks") or []
            return drinks[0] if drinks else None
        except Exception as e:
            logging.error(f"CocktailDB error: {e}")
            return None
