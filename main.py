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


class RecipesTab(ttk.Frame):
    """Comfort Food with ideas → recipes, plus Save Selected to History."""
    def __init__(self, master, spoon_client, weather_tab, catalog_mgr: CatalogManager):
        super().__init__(master)
        self.client = spoon_client
        self.weather_tab = weather_tab
        self.catalog_mgr = catalog_mgr
        self.items = []

        top = ttk.Frame(self); top.pack(fill="x", padx=10, pady=(10, 6))
        ttk.Label(top, text="Food keyword:").pack(side="left")
        self.query_entry = ttk.Entry(top, width=24); self.query_entry.pack(side="left", padx=(6, 6))
        ttk.Button(top, text="Search", command=self.search_direct).pack(side="left")
        ttk.Button(top, text="Use Weather Mood", command=self.populate_ideas).pack(side="left", padx=(8, 0))
        ttk.Button(top, text="Save Selected", command=self.save_selected).pack(side="left", padx=(8, 0))

        body = ttk.Frame(self); body.pack(fill="both", expand=True, padx=10, pady=(6, 4))
        left = ttk.Frame(body); left.pack(side="left", fill="both", expand=True)
        ttk.Label(left, text="Food Ideas").pack(anchor="w")
        self.ideas = tk.Listbox(left, height=12); self.ideas.pack(fill="both", expand=True)
        self.ideas.bind("<Double-Button-1>", self._on_idea)

        right = ttk.Frame(body); right.pack(side="left", fill="both", expand=True, padx=(10, 0))
        ttk.Label(right, text="Recipes").pack(anchor="w")
        self.results = tk.Listbox(right, height=12); self.results.pack(fill="both", expand=True)
        self.results.bind("<Double-Button-1>", self.open_recipe)

        self.status = tk.StringVar(value=""); ttk.Label(self, textvariable=self.status).pack(anchor="w", padx=10, pady=(4, 6))

    def populate_ideas(self):
        w = (self.weather_tab.latest or {})
        ideas = mood_food_ideas(w.get("description", ""), w.get("temp_c"), self.catalog_mgr.all())
        self.ideas.delete(0, tk.END)
        for it in ideas: self.ideas.insert(tk.END, it)
        self.status.set("Pick an idea to fetch recipes.")

    def _on_idea(self, _evt=None):
        sel = self.ideas.curselection()
        if not sel: return
        idea = self.ideas.get(sel[0]); self.search_for(idea)

    def search_direct(self):
        q = self.query_entry.get().strip() or "comfort food"; self.search_for(q)

    def search_for(self, query: str):
        self.results.delete(0, tk.END); self.items = []; self.status.set(f"Searching recipes for: {query}")
        def work():
            data = self.client.search(query, number=12)
            self.items = data or []
            if not self.items:
                self.results.insert(tk.END, "No recipes found."); self.status.set("No recipes found."); return
            for i, rcp in enumerate(self.items, start=1):
                title = rcp.get("title", "Recipe"); ready = rcp.get("readyInMinutes"); servings = rcp.get("servings")
                self.results.insert(tk.END, f"{i}. {title} • {ready} min • serves {servings}")
            self.status.set(f"Found {len(self.items)} recipes for '{query}'.")
        threading.Thread(target=work, daemon=True).start()

    def _try_open_url(self, url: str) -> bool:
        if not url: return False
        try:
            r = requests.get(url, timeout=6, allow_redirects=True)
            if r.status_code and r.status_code < 400:
                webbrowser.open(url); return True
            return False
        except Exception:
            return False

    def open_recipe(self, _evt=None):
        sel = self.results.curselection()
        if not sel or not self.items: return
        idx = sel[0]; item = self.items[idx]
        spoon_url = item.get("spoonacularSourceUrl"); src_url = item.get("sourceUrl")
        if self._try_open_url(spoon_url): return
        if self._try_open_url(src_url): return
        rid = item.get("id")
        if not rid:
            messagebox.showinfo("Recipe", "This recipe has no details link. Try another result."); return
        try:
            info_url = f"https://api.spoonacular.com/recipes/{rid}/information"
            params = {"apiKey": self.client.api_key, "includeNutrition": "false"}
            r = requests.get(info_url, params=params, timeout=10); r.raise_for_status()
            info = r.json(); title = info.get("title", "Recipe")
            ings = []
            for ing in info.get("extendedIngredients", []) or []:
                amount = []
                if ing.get("amount"): amount.append(str(ing["amount"]))
                if ing.get("unit"): amount.append(ing["unit"])
                amt = (" ".join(amount)).strip(); name = (ing.get("name") or "").strip()
                ings.append(f"{amt} {name}".strip() if amt else name)
            steps_text = "No instructions provided."
            analyzed = info.get("analyzedInstructions") or []; steps=[]
            for block in analyzed:
                for step in block.get("steps", []):
                    txt = (step.get("step") or "").strip()
                    if txt: steps.append(txt)
            if steps: steps_text = "\n".join([f"{i+1}. {s}" for i, s in enumerate(steps)])
            popup = f"{title}\n\nIngredients:\n- " + "\n- ".join(ings) + f"\n\nInstructions:\n{steps_text}"
            live_url = info.get("spoonacularSourceUrl") or info.get("sourceUrl")
            if live_url:
                archive_link = f"https://web.archive.org/web/*/{live_url}"
                popup += f"\n\nIf the original page is down, try Archive.org:\n{archive_link}"
            messagebox.showinfo("Recipe", popup)
        except requests.exceptions.RequestException as e:
            logging.error(f"Error fetching recipe details: {e}")
            messagebox.showerror("Recipe", "Could not load recipe details. Please try another result.")

    def save_selected(self):
        sel = self.results.curselection()
        if not sel or not self.items:
            messagebox.showinfo("History", "Select a recipe first."); return
        idx = sel[0]; item = self.items[idx]
        label = item.get("title") or "Recipe"
        metadata = {"source": "spoonacular", "id": item.get("id"), "url": item.get("sourceUrl")}
        app = self.winfo_toplevel()
        weather = getattr(app, "last_weather_snapshot", {})
        app.history.add("food", label, metadata, weather)
        # NEW: Immediate refresh of History tab
        app.tab_history.refresh()
        messagebox.showinfo("History", f"Saved to history:\n{label}")

class BooksTab(ttk.Frame):
    DECADES = ["Any", "1950s", "1960s", "1970s", "1980s", "1990s", "2000s", "2010s", "2020s"]
    def __init__(self, master, gb_client, weather_tab, catalog_mgr: CatalogManager):
        super().__init__(master)
        self.client = gb_client
        self.weather_tab = weather_tab
        self.catalog_mgr = catalog_mgr
        self.last_query = None
        self.items: List[Dict] = []

        row = ttk.Frame(self); row.pack(fill="x", padx=10, pady=(10, 6))
        ttk.Label(row, text="Book keyword/genre:").pack(side="left")
        self.query_entry = ttk.Entry(row, width=28); self.query_entry.pack(side="left", padx=(6, 6))
        ttk.Button(row, text="Search", command=self.search).pack(side="left")
        ttk.Button(row, text="Use Weather Mood", command=self.use_mood).pack(side="left", padx=(8, 0))
        ttk.Button(row, text="Shuffle", command=self.shuffle).pack(side="left", padx=(8, 0))
        ttk.Button(row, text="Save Selected", command=self.save_selected).pack(side="left", padx=(8, 0))

        ttk.Label(row, text="Decade:").pack(side="left", padx=(10, 4))
        self.decade_var = tk.StringVar(value="Any")
        self.decade_box = ttk.Combobox(row, textvariable=self.decade_var, state="readonly",
                                       values=self.DECADES, width=10)
        self.decade_box.pack(side="left")
        self.decade_box.bind("<<ComboboxSelected>>", lambda _e: self.search())

        self.results = tk.Listbox(self, height=12)
        self.results.pack(fill="both", expand=True, padx=10, pady=(6, 4))
        self.results.bind("<Double-Button-1>", self.open_google_books)

    def _parse_year(self, date_str: str) -> Optional[int]:
        if not date_str: return None
        m = re.match(r"(\d{4})", date_str); return int(m.group(1)) if m else None

    def _decade_bounds(self, decade_label: str) -> Tuple[Optional[int], Optional[int]]:
        if decade_label == "Any": return None, None
        start = int(decade_label[:4]); return start, start + 9

    def _filter_by_decade(self, items: List[Dict], decade_label: str) -> List[Dict]:
        lo, hi = self._decade_bounds(decade_label)
        if lo is None: return items
        out = []
        for it in items:
            info = it.get("volumeInfo", {})
            yr = self._parse_year(info.get("publishedDate", "")) or None
            if yr is not None and lo <= yr <= hi:
                out.append(it)
        return out

    def use_mood(self):
        w = (self.weather_tab.latest or {})
        mood = derive_mood(w.get("description", ""), w.get("temp_c"))
        self.query_entry.delete(0, tk.END); self.query_entry.insert(0, mood["book_query"])
        self.decade_var.set("Any"); self.search()

    def shuffle(self):
        q = self.query_entry.get().strip() or "popular fiction"
        self._search_internal(q, start_index=random.choice([0, 20, 40, 60, 80]))

    def search(self):
        q = self.query_entry.get().strip() or "popular fiction"
        start_index = random.choice([0, 10, 20, 30, 40]) if q == self.last_query else 0
        self.last_query = q
        self._search_internal(q, start_index=start_index)

    def _search_internal(self, q: str, start_index: int = 0):
        self.results.delete(0, tk.END)
        def work():
            items = self.client.search(q, max_results=20, start_index=start_index)
            items = self._filter_by_decade(items, self.decade_var.get())
            self.items = items or []
            if not self.items:
                self.results.insert(tk.END, "No books found. Try Shuffle or a different decade.")
                # Also surface admin-provided static suggestions if any
                for b in self.catalog_mgr.all().get("books", [])[:5]:
                    self.results.insert(tk.END, f"• {b}")
                return
            for i, it in enumerate(self.items, start=1):
                info = it.get("volumeInfo", {})
                title = info.get("title", "Untitled")
                authors = ", ".join(info.get("authors", [])[:2]) if info.get("authors") else "Unknown"
                year = self._parse_year(info.get("publishedDate", "")) or ""
                self.results.insert(tk.END, f"{i}. {title} — {authors} ({year})")
        threading.Thread(target=work, daemon=True).start()

    def open_google_books(self, _evt=None):
        sel = self.results.curselection()
        if not sel or not self.items: return
        idx = sel[0]; item = self.items[idx]
        info = item.get("volumeInfo", {})
        url = info.get("infoLink") or info.get("canonicalVolumeLink")
        if url: webbrowser.open(url)

    def save_selected(self):
        sel = self.results.curselection()
        if not sel:
            messagebox.showinfo("History", "Select a book first."); return
        idx = sel[0]
        label = None
        metadata = {}
        # If user picked an API item, save its fields; if they clicked a catalog bullet, save as plain label.
        if self.items and idx < len(self.items):
            it = self.items[idx]; info = it.get("volumeInfo", {})
            label = info.get("title") or "Book"
            metadata = {"source": "google_books", "id": it.get("id"), "infoLink": info.get("infoLink")}
        else:
            label = self.results.get(idx).lstrip("• ").strip()

        app = self.winfo_toplevel()
        weather = getattr(app, "last_weather_snapshot", {})
        app.history.add("book", label, metadata, weather)
        app.tab_history.refresh()  # NEW: instant refresh
        messagebox.showinfo("History", f"Saved to history:\n{label}")

class CocktailsTab(ttk.Frame):
    """Beverages with ideas → results, filter + Save Selected."""
    def __init__(self, master, c_client, weather_tab, catalog_mgr: CatalogManager):
        super().__init__(master)
        self.client = c_client
        self.weather_tab = weather_tab
        self.catalog_mgr = catalog_mgr
        self.items: List[Dict] = []

        row = ttk.Frame(self); row.pack(fill="x", padx=10, pady=(10, 6))
        ttk.Label(row, text="Drink keyword:").pack(side="left")
        self.query_entry = ttk.Entry(row, width=24); self.query_entry.pack(side="left", padx=(6, 6))
        ttk.Button(row, text="Search", command=self.search_direct).pack(side="left")
        ttk.Button(row, text="Use Weather Mood", command=self.populate_ideas).pack(side="left", padx=(8, 0))
        ttk.Button(row, text="Save Selected", command=self.save_selected).pack(side="left", padx=(8, 0))

        ttk.Label(row, text="Filter:").pack(side="left", padx=(10, 4))
        self.filter_var = tk.StringVar(value="All")
        self.filter_box = ttk.Combobox(row, textvariable=self.filter_var, state="readonly",
                                       values=["All", "Non-Alcoholic", "Alcoholic"], width=15)
        self.filter_box.pack(side="left")
        self.filter_box.bind("<<ComboboxSelected>>", lambda _e: self._reapply_filter())

        body = ttk.Frame(self); body.pack(fill="both", expand=True, padx=10, pady=(6, 4))
        left = ttk.Frame(body); left.pack(side="left", fill="both", expand=True)
        ttk.Label(left, text="Drink Ideas").pack(anchor="w")
        self.ideas = tk.Listbox(left, height=12); self.ideas.pack(fill="both", expand=True)
        self.ideas.bind("<Double-Button-1>", self._on_idea)

        right = ttk.Frame(body); right.pack(side="left", fill="both", expand=True, padx=(10, 0))
        ttk.Label(right, text="Results").pack(anchor="w")
        self.results = tk.Listbox(right, height=12); self.results.pack(fill="both", expand=True)
        self.results.bind("<Double-Button-1>", self.open_cocktail_page)

    def populate_ideas(self):
        w = (self.weather_tab.latest or {})
        ideas = mood_drink_ideas(w.get("description", ""), w.get("temp_c"), self.catalog_mgr.all())
        self.ideas.delete(0, tk.END)
        for it in ideas: self.ideas.insert(tk.END, it)

    def _on_idea(self, _evt=None):
        sel = self.ideas.curselection()
        if not sel: return
        idea = self.ideas.get(sel[0]); self.search_for_idea(idea)

    def search_direct(self):
        q = self.query_entry.get().strip()
        if not q:
            messagebox.showinfo("Info", "Enter a drink keyword or use Weather Mood."); return
        self._search_drinks(q)

    def search_for_idea(self, idea_label: str):
        m = re.match(r"^(\w+)\s+drinks$", idea_label.strip(), re.IGNORECASE)
        if m:
            ingredient = m.group(1); self._search_drinks_by_ingredient(ingredient)
        else:
            self._search_drinks(idea_label)

    def _search_drinks_by_ingredient(self, ingredient: str):
        self.results.delete(0, tk.END); self.items = []
        def work():
            base = self.client.filter_by_ingredient(ingredient)
            enriched = []
            for d in base[:40]:
                info = self.client.lookup_by_id(d.get("idDrink"))
                if info: enriched.append(info)
            self.items = self._apply_filter(enriched)
            if not self.items:
                self.results.insert(tk.END, "No drinks found."); return
            for i, d in enumerate(self.items[:50], start=1):
                name = d.get("strDrink", "Drink"); alc = d.get("strAlcoholic", "")
                self.results.insert(tk.END, f"{i}. {name} • {alc or 'Unknown'}")
        threading.Thread(target=work, daemon=True).start()

    def _search_drinks(self, query: str):
        self.results.delete(0, tk.END); self.items = []
        def work():
            drinks = self.client.search_by_name(query) or []
            if len(drinks) < 3:
                fallback = self.client.filter_by_ingredient(query.split()[0])
                for d in fallback[:30]:
                    info = self.client.lookup_by_id(d.get("idDrink"))
                    if info: drinks.append(info)
            drinks = self._apply_filter(drinks); self.items = drinks or []
            if not self.items:
                self.results.insert(tk.END, "No drinks found."); return
            for i, d in enumerate(self.items[:50], start=1):
                name = d.get("strDrink", "Drink"); alc = d.get("strAlcoholic", "")
                self.results.insert(tk.END, f"{i}. {name} • {alc or 'Unknown'}")
        threading.Thread(target=work, daemon=True).start()

    def _apply_filter(self, drinks: List[Dict]) -> List[Dict]:
        mode = self.filter_var.get()
        if mode == "All": return drinks
        target = "Non alcoholic" if mode == "Non-Alcoholic" else "Alcoholic"
        out = [d for d in drinks if (d.get("strAlcoholic") or "").lower() == target.lower()]
        if any(d.get("strAlcoholic") is None for d in drinks):
            enriched = []
            for d in drinks:
                if d.get("strAlcoholic") is None and d.get("idDrink"):
                    info = self.client.lookup_by_id(d["idDrink"])
                    if info: enriched.append(info)
                else:
                    enriched.append(d)
            out = [d for d in enriched if (d.get("strAlcoholic") or "").lower() == target.lower()]
        return out

    def _reapply_filter(self):
        if not self.items: return
        filtered = self._apply_filter(self.items)
        self.results.delete(0, tk.END)
        if not filtered:
            self.results.insert(tk.END, "No drinks match the filter."); return
        self.items = filtered
        for i, d in enumerate(self.items[:50], start=1):
            name = d.get("strDrink", "Drink"); alc = d.get("strAlcoholic", "")
            self.results.insert(tk.END, f"{i}. {name} • {alc or 'Unknown'}")

    def open_cocktail_page(self, _evt=None):
        sel = self.results.curselection()
        if not sel or not self.items: return
        idx = sel[0]; drink = self.items[idx]
        if not drink.get("strInstructions"):
            enriched = self.client.lookup_by_id(drink.get("idDrink"))
            if enriched: drink = enriched
        name = drink.get("strDrink", "Drink")
        instructions = drink.get("strInstructions", "No instructions.")
        ings = []
        for n in range(1, 16):
            ing = drink.get(f"strIngredient{n}"); mea = drink.get(f"strMeasure{n}")
            if ing:
                ings.append(f"{(mea or '').strip()} {ing.strip()}".strip())
        txt = f"{name}\n\nIngredients:\n- " + "\n- ".join(ings) + f"\n\nInstructions:\n{instructions}"
        messagebox.showinfo("Drink Recipe", txt)

    def save_selected(self):
        sel = self.results.curselection()
        if not sel or not self.items:
            messagebox.showinfo("History", "Select a drink first."); return
        idx = sel[0]; d = self.items[idx]
        label = d.get("strDrink") or "Drink"
        metadata = {"source": "cocktaildb", "idDrink": d.get("idDrink"), "alcoholic": d.get("strAlcoholic")}
        app = self.winfo_toplevel()
        weather = getattr(app, "last_weather_snapshot", {})
        app.history.add("drink", label, metadata, weather)
        app.tab_history.refresh()  # NEW: instant refresh
        messagebox.showinfo("History", f"Saved to history:\n{label}")

class HistoryTab(ttk.Frame):
    """View / delete / export history."""
    def __init__(self, master, history: HistoryManager):
        super().__init__(master)
        self.history = history

        top = ttk.Frame(self); top.pack(fill="x", padx=10, pady=(10, 6))
        ttk.Button(top, text="Delete Selected", command=self.delete_selected).pack(side="left")
        ttk.Button(top, text="Export Selected (CSV)", command=lambda: self.export_selected(fmt="csv")).pack(side="left", padx=6)
        ttk.Button(top, text="Export Selected (JSON)", command=lambda: self.export_selected(fmt="json")).pack(side="left", padx=6)
        ttk.Button(top, text="Export All (CSV)", command=lambda: self.export_all(fmt="csv")).pack(side="left", padx=6)
        ttk.Button(top, text="Export All (JSON)", command=lambda: self.export_all(fmt="json")).pack(side="left", padx=6)

        self.tree = ttk.Treeview(self, columns=("time","type","label","weather"), show="headings", height=14)
        self.tree.pack(fill="both", expand=True, padx=10, pady=(4, 10))
        for c in ("time","type","label","weather"):
            self.tree.heading(c, text=c.capitalize())
        self.tree.column("time", width=160)
        self.tree.column("type", width=80)
        self.tree.column("label", width=260)
        self.tree.column("weather", width=340)
        self.refresh()

    def refresh(self):
        for i in self.tree.get_children():
            self.tree.delete(i)
        for idx, it in enumerate(self.history.items):
            w = it.get("weather") or {}
            wtxt = f"{w.get('city','')} • {w.get('description','')} • {w.get('temp_c','')}°C"
            self.tree.insert("", "end", iid=str(idx), values=(it["timestamp"], it["type"], it["label"], wtxt))

    def selected_indices(self) -> List[int]:
        return [int(iid) for iid in self.tree.selection()]

    def delete_selected(self):
        idxs = sorted(self.selected_indices(), reverse=True)
        if not idxs:
            messagebox.showinfo("History", "Select rows to delete."); return
        for i in idxs:
            self.history.delete_index(i)
        self.refresh()

    def export_selected(self, fmt="csv"):
        idxs = self.selected_indices()
        if not idxs:
            messagebox.showinfo("Export", "Select rows to export."); return
        path = filedialog.asksaveasfilename(
            defaultextension=f".{fmt}",
            filetypes=[("CSV","*.csv"),("JSON","*.json"),("All","*.*")]
        )
        if not path: return
        try:
            if fmt == "csv":
                self.history.export_csv(path, selection=idxs)
            else:
                self.history.export_json(path, selection=idxs)
            messagebox.showinfo("Export", f"Exported {len(idxs)} items to {os.path.basename(path)}")
        except Exception as e:
            logging.error(e); messagebox.showerror("Export", "Failed to export.")

    def export_all(self, fmt="csv"):
        path = filedialog.asksaveasfilename(
            defaultextension=f".{fmt}",
            filetypes=[("CSV","*.csv"),("JSON","*.json"),("All","*.*")]
        )
        if not path: return
        try:
            if fmt == "csv":
                self.history.export_csv(path, selection=None)
            else:
                self.history.export_json(path, selection=None)
            messagebox.showinfo("Export", f"Exported all history to {os.path.basename(path)}")
        except Exception as e:
            logging.error(e); messagebox.showerror("Export", "Failed to export.")
