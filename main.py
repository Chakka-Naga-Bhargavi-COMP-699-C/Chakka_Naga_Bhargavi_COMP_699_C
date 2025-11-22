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


# -------------------------------
#     Weather → Mood Mapping
# -------------------------------

def derive_mood(weather_desc: str, temp_c: float) -> Dict[str, str]:
    desc = (weather_desc or "").lower()
    t = temp_c if isinstance(temp_c, (int, float)) else None
    if t is not None:
        if t <= 12:
            base = {"food_query": "soup", "book_query": "cozy mystery", "cocktail_query": "hot toddy"}
        elif 12 < t <= 22:
            base = {"food_query": "comfort casserole", "book_query": "feel good fiction", "cocktail_query": "whiskey sour"}
        elif 22 < t <= 30:
            base = {"food_query": "salad bowl", "book_query": "light romance", "cocktail_query": "mojito"}
        else:
            base = {"food_query": "ice cream", "book_query": "beach read", "cocktail_query": "piña colada"}
    else:
        base = {"food_query": "comfort food", "book_query": "popular fiction", "cocktail_query": "margarita"}

    if any(k in desc for k in ["rain", "drizzle", "storm"]):
        base.update(food_query="ramen", book_query="cozy fantasy", cocktail_query="irish coffee")
    elif "snow" in desc:
        base.update(food_query="chili", book_query="historical fiction", cocktail_query="hot buttered rum")
    elif any(k in desc for k in ["clear", "sunny"]):
        base.update(food_query="grilled", book_query="adventure", cocktail_query="aperol spritz")
    return base

def mood_food_ideas(weather_desc: str, temp_c: float, catalogs: Optional[dict] = None) -> List[str]:
    """
    NEW: Appends admin-managed catalog food entries to weather ideas.
    """
    m = derive_mood(weather_desc, temp_c)
    q = m["food_query"].lower()
    base = []
    if "soup" in q or "ramen" in q:
        base = ["Ramen", "Tomato Soup", "Chicken Noodle Soup", "Minestrone", "Pho", "Miso Soup"]
    elif "casserole" in q or "comfort" in q:
        base = ["Mac and Cheese", "Shepherd's Pie", "Lasagna", "Chicken Pot Pie", "Baked Ziti"]
    elif "salad" in q:
        base = ["Greek Salad", "Caesar Salad", "Pasta Salad", "Quinoa Salad", "Fruit Salad"]
    elif "ice cream" in q:
        base = ["Chocolate Ice Cream", "Vanilla Ice Cream", "Mango Sorbet", "Kulfi", "Gelato"]
    elif "grilled" in q:
        base = ["Grilled Chicken", "Grilled Paneer", "BBQ Ribs", "Grilled Salmon", "Grilled Veggies"]
    elif "chili" in q:
        base = ["Beef Chili", "Chicken Chili", "Vegetarian Chili", "Turkey Chili"]
    else:
        base = ["Comfort Food", "Pasta", "Pizza", "Burger", "Stir Fry", "Curry"]
    extras = (catalogs or {}).get("foods", [])
    return list(dict.fromkeys(extras + base))  # extras first, dedupe preserving order

def mood_drink_ideas(weather_desc: str, temp_c: float, catalogs: Optional[dict] = None) -> List[str]:
    desc = (weather_desc or "").lower()
    t = temp_c if isinstance(temp_c, (int, float)) else None
    base: List[str]
    if t is None:
        base = ["Lemonade", "Iced Tea", "Pineapple drinks", "Watermelon drinks", "Mango drinks", "Mint drinks"]
    elif t >= 28:
        base = ["Pineapple drinks", "Watermelon drinks", "Lemonade", "Iced Tea", "Mango drinks", "Mint drinks"]
    elif 20 <= t < 28:
        base = ["Berry drinks", "Citrus coolers", "Iced Coffee", "Iced Tea", "Ginger Ale"]
    elif 10 <= t < 20:
        base = ["Masala Chai", "Hot Chocolate", "Coffee drinks", "Apple Cider", "Ginger Tea"]
    else:
        base = ["Hot Chocolate", "Masala Chai", "Turmeric Latte", "Ginger Tea", "Mulled drinks"]
    extras = (catalogs or {}).get("beverages", [])
    return list(dict.fromkeys(extras + base))

# -------------------------------
#            UI: Auth
# -------------------------------

class LoginDialog(tk.Toplevel):
    """Modal auth dialog: Sign In / Register / Reset."""
    def __init__(self, master, auth: AuthManager):
        super().__init__(master)
        self.title("Sign In")
        self.resizable(False, False)
        self.auth = auth
        self.result_email = None
        self.grab_set()  # modal
        nb = ttk.Notebook(self)
        nb.pack(fill="both", expand=True, padx=10, pady=10)

        # --- Sign In ---
        frm_sign = ttk.Frame(nb)
        nb.add(frm_sign, text="Sign In")
        ttk.Label(frm_sign, text="Email").grid(row=0, column=0, sticky="e", padx=6, pady=6)
        ttk.Label(frm_sign, text="Password").grid(row=1, column=0, sticky="e", padx=6, pady=6)
        self.si_email = ttk.Entry(frm_sign, width=32)
        self.si_pass = ttk.Entry(frm_sign, show="*", width=32)
        self.si_email.grid(row=0, column=1, padx=6, pady=6)
        self.si_pass.grid(row=1, column=1, padx=6, pady=6)
        ttk.Button(frm_sign, text="Sign In", command=self._do_sign_in).grid(row=2, column=0, columnspan=2, pady=8)

        # --- Register ---
        frm_reg = ttk.Frame(nb)
        nb.add(frm_reg, text="Register")
        ttk.Label(frm_reg, text="Email").grid(row=0, column=0, sticky="e", padx=6, pady=6)
        ttk.Label(frm_reg, text="Password").grid(row=1, column=0, sticky="e", padx=6, pady=6)
        ttk.Label(frm_reg, text="Confirm").grid(row=2, column=0, sticky="e", padx=6, pady=6)
        self.re_email = ttk.Entry(frm_reg, width=32)
        self.re_pass = ttk.Entry(frm_reg, show="*", width=32)
        self.re_conf = ttk.Entry(frm_reg, show="*", width=32)
        self.re_email.grid(row=0, column=1, padx=6, pady=6)
        self.re_pass.grid(row=1, column=1, padx=6, pady=6)
        self.re_conf.grid(row=2, column=1, padx=6, pady=6)

        # NEW: Register-as-admin checkbox
        self.re_admin_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(frm_reg, text="Register as Admin", variable=self.re_admin_var).grid(
            row=3, column=0, columnspan=2, pady=(2, 4)
        )

        ttk.Button(frm_reg, text="Create Account", command=self._do_register).grid(row=4, column=0, columnspan=2, pady=8)

        # --- Reset ---
        frm_rst = ttk.Frame(nb)
        nb.add(frm_rst, text="Reset Password")
        ttk.Label(frm_rst, text="Email").grid(row=0, column=0, sticky="e", padx=6, pady=6)
        self.rs_email = ttk.Entry(frm_rst, width=32)
        self.rs_email.grid(row=0, column=1, padx=6, pady=6)
        ttk.Button(frm_rst, text="Send Reset Link", command=self._do_send_reset).grid(row=1, column=0, columnspan=2, pady=8)

        ttk.Separator(frm_rst).grid(row=2, column=0, columnspan=2, sticky="ew", pady=(6,4))
        ttk.Label(frm_rst, text="Have a link? Paste token below").grid(row=3, column=0, columnspan=2)
        ttk.Label(frm_rst, text="Token").grid(row=4, column=0, sticky="e", padx=6, pady=6)
        ttk.Label(frm_rst, text="New Password").grid(row=5, column=0, sticky="e", padx=6, pady=6)
        self.r_token = ttk.Entry(frm_rst, width=34)
        self.r_newpw = ttk.Entry(frm_rst, show="*", width=34)
        self.r_token.grid(row=4, column=1, padx=6, pady=6)
        self.r_newpw.grid(row=5, column=1, padx=6, pady=6)
        ttk.Button(frm_rst, text="Reset Password", command=self._do_finish_reset).grid(row=6, column=0, columnspan=2, pady=8)

        self.bind("<Return>", lambda _e: self._do_sign_in())

    def _do_sign_in(self):
        e = (self.si_email.get() or "").strip().lower()
        p = self.si_pass.get() or ""
        if self.auth.authenticate(e, p):
            self.result_email = e
            self.destroy()
        else:
            messagebox.showerror("Sign In", "Invalid email or password.")

    def _do_register(self):
        e = (self.re_email.get() or "").strip().lower()
        p = self.re_pass.get() or ""
        c = self.re_conf.get() or ""
        is_admin = bool(self.re_admin_var.get())
        if p != c:
            messagebox.showerror("Register", "Passwords do not match.")
            return
        ok, msg = self.auth.register(e, p, is_admin=is_admin)
        if ok:
            messagebox.showinfo("Register", msg)
        else:
            messagebox.showerror("Register", msg)

    def _do_send_reset(self):
        e = (self.rs_email.get() or "").strip().lower()
        ok, msg = self.auth.start_reset(e)
        if ok and "copied to clipboard" in msg:
            copy_to_clipboard(self, msg.split(":")[-1].strip())
        messagebox.showinfo("Reset", msg)

    def _do_finish_reset(self):
        e = (self.rs_email.get() or "").strip().lower()
        t = (self.r_token.get() or "").strip()
        n = self.r_newpw.get() or ""
        ok, msg = self.auth.finish_reset(e, t, n)
        if ok:
            messagebox.showinfo("Reset", msg)
        else:
            messagebox.showerror("Reset", msg)

# -------------------------------
#            UI
# -------------------------------

class WeatherTab(ttk.Frame):
    """
    Weather tab with mini previews + Detect Location + Refresh.
    """
    def __init__(self, master, weather_client, books_client, catalog_mgr: CatalogManager):
        super().__init__(master)
        self.client = weather_client
        self.books_client = books_client
        self.catalog_mgr = catalog_mgr
        self._icon_img = None

        row = ttk.Frame(self)
        row.pack(fill="x", padx=10, pady=(10, 6))
        ttk.Label(row, text="City:").pack(side="left")
        self.city_entry = ttk.Entry(row, width=28)
        self.city_entry.pack(side="left", padx=(6, 6))
        ttk.Button(row, text="Get Weather", command=self.fetch_weather).pack(side="left")
        ttk.Button(row, text="Detect Location", command=self.detect_location).pack(side="left", padx=(6,0))
        ttk.Button(row, text="Refresh", command=self.refresh_weather).pack(side="left", padx=(6,0))
        ttk.Button(row, text="Use Result in Other Tabs", command=self.push_to_others).pack(side="left", padx=(8, 0))

        self.info = tk.StringVar(value="Enter a city and click Get Weather.")
        ttk.Label(self, textvariable=self.info, wraplength=520, justify="left").pack(anchor="w", padx=10, pady=6)

        self.icon_label = ttk.Label(self); self.icon_label.pack(anchor="w", padx=10)

        self.preview_frame = ttk.LabelFrame(self, text="Suggestions based on current weather")
        self.preview_frame.pack(fill="x", padx=10, pady=(8, 10))
        self.preview_frame.columnconfigure(0, weight=1)
        self.preview_frame.columnconfigure(1, weight=1)
        self.preview_frame.columnconfigure(2, weight=1)

        ttk.Label(self.preview_frame, text="Comfort Food Ideas").grid(row=0, column=0, sticky="w", padx=6, pady=(6, 2))
        self.food_list = tk.Listbox(self.preview_frame, height=5, exportselection=False)
        self.food_list.grid(row=1, column=0, sticky="nsew", padx=6, pady=(0, 8))
        ttk.Label(self.preview_frame, text="Book Suggestions").grid(row=0, column=1, sticky="w", padx=6, pady=(6, 2))
        self.books_list = tk.Listbox(self.preview_frame, height=5, exportselection=False)
        self.books_list.grid(row=1, column=1, sticky="nsew", padx=6, pady=(0, 8))
        ttk.Label(self.preview_frame, text="Beverage Ideas").grid(row=0, column=2, sticky="w", padx=6, pady=(6, 2))
        self.drinks_list = tk.Listbox(self.preview_frame, height=5, exportselection=False)
        self.drinks_list.grid(row=1, column=2, sticky="nsew", padx=6, pady=(0, 8))

        self.latest = None

    def _threaded(self, fn):
        t = threading.Thread(target=fn, daemon=True)
        t.start()

    def detect_location(self):
        """Detect the user's location automatically using ipgeolocation.io (requires IPGEOLOCATION_API_KEY)."""
        def work():
            try:
                api_key = os.getenv("IPGEOLOCATION_API_KEY")
                if not api_key:
                    messagebox.showerror(
                        "Detect Location",
                        "IPGEOLOCATION_API_KEY is not set.\n\nUse:\n  set IPGEOLOCATION_API_KEY=YOUR_KEY\nthen restart the terminal."
                    )
                    return

                url = f"https://api.ipgeolocation.io/ipgeo?apiKey={api_key}"
                response = requests.get(url, timeout=10)
                if response.status_code == 200:
                    data = response.json()
                    city = (data.get("city") or "").strip()
                    if city:
                        # update input and fetch weather (keeps your existing flow unchanged)
                        self.city_entry.delete(0, tk.END)
                        self.city_entry.insert(0, city)
                        self.fetch_weather()
                    else:
                        messagebox.showerror("Detect Location", "Could not detect city from location data.")
                else:
                    messagebox.showerror("Detect Location", "Could not detect location. Try again.")
            except requests.exceptions.RequestException as e:
                logging.error(f"Network error during location detection: {e}")
                messagebox.showerror("Detect Location", f"Network error: {e}")
        self._threaded(work)

    def refresh_weather(self):
        if not self.city_entry.get().strip():
            messagebox.showinfo("Refresh", "Enter a city or detect location first.")
            return
        self.fetch_weather()

    def fetch_weather(self):
        city = self.city_entry.get().strip()
        if not city:
            messagebox.showerror("Error", "Please enter a city.")
            return

        def work():
            self.info.set("Fetching weather...")
            data = self.client.current_by_city(city)
            if "error" in data:
                self.info.set(f"Error: {data['error']}")
                self.icon_label.configure(image=""); self.icon_label.image = None
                self.latest = None
                self._clear_previews()
                return

            self.latest = data
            txt = (f"{data['city']}: {data['description']}\n"
                   f"Temperature: {data['temp_c']}°C (feels like {data['feels_like']}°C)\n"
                   f"Humidity: {data['humidity']}%   Wind: {data['wind']} m/s")
            self.info.set(txt)

            try:
                if data.get("icon"):
                    icon_url = WeatherClient.icon_url(data["icon"])
                    r = requests.get(icon_url, timeout=12); r.raise_for_status()
                    img = Image.open(io.BytesIO(r.content)).resize((100, 100))
                    self._icon_img = ImageTk.PhotoImage(img)
                    self.icon_label.configure(image=self._icon_img); self.icon_label.image = self._icon_img
                else:
                    self.icon_label.configure(image=""); self.icon_label.image = None
            except Exception as e:
                logging.warning(f"Icon load failed: {e}")
                self.icon_label.configure(image=""); self.icon_label.image = None

            self._update_previews()

        self._threaded(work)

    def _clear_previews(self):
        self.food_list.delete(0, tk.END)
        self.books_list.delete(0, tk.END)
        self.drinks_list.delete(0, tk.END)

    def _update_previews(self):
        self._clear_previews()
        w = self.latest or {}
        desc = w.get("description", "")
        temp_c = w.get("temp_c")

        catalogs = self.catalog_mgr.all()  # include admin-managed extras
        for idea in mood_food_ideas(desc, temp_c, catalogs)[:5]:
            self.food_list.insert(tk.END, f"• {idea}")
        for idea in mood_drink_ideas(desc, temp_c, catalogs)[:5]:
            self.drinks_list.insert(tk.END, f"• {idea}")

        mood = derive_mood(desc, temp_c)
        q = mood.get("book_query", "popular fiction")

        def load_books():
            self.books_list.insert(tk.END, "Loading…")
            items = self.books_client.search(q, max_results=10, start_index=0)
            self.books_list.delete(0, tk.END)
            if not items:
                self.books_list.insert(tk.END, "No suggestions found.")
                # If admin added custom book names, show a couple of those as ideas:
                for b in catalogs.get("books", [])[:3]:
                    self.books_list.insert(tk.END, f"• {b}")
                return
            for it in items[:5]:
                info = it.get("volumeInfo", {})
                title = info.get("title", "Untitled")
                self.books_list.insert(tk.END, f"• {title}")
        self._threaded(load_books)

    def push_to_others(self):
        if not self.latest:
            messagebox.showinfo("Info", "Get weather first.")
            return
        self.master.event_generate("<<WeatherUpdated>>", when="tail")
