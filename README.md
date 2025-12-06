# Build and Run Instructions

## 1. Prerequisites

- **Python:** 3.8 or newer  
  - Check:
    - `python --version`
- **Tkinter:** usually bundled with Python  
  - Quick check (no error = OK):
    - `python -c "import tkinter; print('Tkinter OK')"`
- **Internet access:** required for:
  - OpenWeatherMap
  - Spoonacular
  - Google Books
  - TheCocktailDB
  - ipgeolocation.io (for Detect Location)

---

## 2. Project Setup

1. Create a folder anywhere on your machine, e.g.:

   ```text
   C:\Projects\weather_recommender
Save your script in that folder as:

text
Copy code
weather_food_books_cocktails_gui.py
Your folder will look like:

text
Copy code
weather_recommender/
└── weather_food_books_cocktails_gui.py
3. Create & Activate a Virtual Environment (recommended)
From inside the project folder:

bash
Copy code
python -m venv venv
Windows (Command Prompt):

bat
Copy code
venv\Scripts\activate
Windows (PowerShell):

powershell
Copy code
venv\Scripts\Activate.ps1
macOS / Linux:

bash
Copy code
source venv/bin/activate
4. Install Dependencies
Only two external libraries are needed (requests and Pillow):

bash
Copy code
pip install requests pillow
Everything else (json, csv, hashlib, tkinter, etc.) comes with Python.

5. Configure API Keys
Your code expects the following environment variables:

OPENWEATHER_API_KEY

SPOONACULAR_API_KEY

GOOGLE_BOOKS_API_KEY

IPGEOLOCATION_API_KEY (for Detect Location button)

Note: Replace YOUR_..._KEY with your actual keys from each service.

Windows (Command Prompt)
Run these in the same terminal after activating the venv:

bat
Copy code
set OPENWEATHER_API_KEY=YOUR_OPENWEATHER_KEY
set SPOONACULAR_API_KEY=YOUR_SPOONACULAR_KEY
set GOOGLE_BOOKS_API_KEY=YOUR_GOOGLE_BOOKS_KEY
set IPGEOLOCATION_API_KEY=YOUR_IPGEOLOCATION_KEY
Windows (PowerShell)
powershell
Copy code
$env:OPENWEATHER_API_KEY="YOUR_OPENWEATHER_KEY"
$env:SPOONACULAR_API_KEY="YOUR_SPOONACULAR_KEY"
$env:GOOGLE_BOOKS_API_KEY="YOUR_GOOGLE_BOOKS_KEY"
$env:IPGEOLOCATION_API_KEY="YOUR_IPGEOLOCATION_KEY"
macOS / Linux
bash
Copy code
export OPENWEATHER_API_KEY=YOUR_OPENWEATHER_KEY
export SPOONACULAR_API_KEY=YOUR_SPOONACULAR_KEY
export GOOGLE_BOOKS_API_KEY=YOUR_GOOGLE_BOOKS_KEY
export IPGEOLOCATION_API_KEY=YOUR_IPGEOLOCATION_KEY
If you change keys later, just update these values in your shell or environment.

6. Run the Application
With the virtual environment active and environment variables set:

bash
Copy code
python weather_food_books_cocktails_gui.py
What you’ll see
A Sign In / Register / Reset dialog:

New user: go to Register, enter email + password (optionally tick Register as Admin), then sign in.

Returning user: enter credentials on Sign In tab.

After login, the main window opens with tabs:

User – change password, sign out, delete account

Weather – city input, Detect Location, weather details + live icon, and three suggestion lists

Comfort Food – weather-based food ideas → Spoonacular recipes → Save to history

Books – weather-based mood, decade filter, book search → Save to history

Beverages – weather-based drink ideas, alcohol filter, drink recipes → Save to history

History – view, delete, export as CSV/JSON

Admin Panel (only if account is admin) – manage local catalogs.json (foods, beverages, books)

7. Files Created at First Run
After you use the app a bit, the folder will typically contain:

text
Copy code
weather_recommender/
├── weather_food_books_cocktails_gui.py   # Your main script
├── users.json                            # Accounts, password hashes, reset tokens, admin flag
├── catalogs.json                         # Admin-managed foods / beverages / books
└── history/
    └── history_<email>.json              # Per-user saved food/book/drink + weather snapshots
You don’t need to create these JSON files manually; the app will create/update them when needed.

8. Quick Troubleshooting
Window closes immediately / error about GOOGLE_BOOKS_API_KEY
→ Make sure GOOGLE_BOOKS_API_KEY is set correctly in the same terminal before running Python.

ModuleNotFoundError: No module named 'requests' or 'PIL'
→ Run:

bash
Copy code
pip install requests pillow
“Detect Location” says key not set
→ Make sure IPGEOLOCATION_API_KEY is defined.

Weather/recipe/book/drink lookups failing
→ Check your internet connection and that the API keys are still valid and not rate-limited.

9. Instructions (Narrative Summary)
To build and run the Weather-Based Comfort Food, Beverage, and Book Recommender, the user must have Python 3.8 or later installed, along with Tkinter (bundled with most standard Python distributions) and an active internet connection for external API calls. The project consists of a single main script, weather_food_books_cocktails_gui.py, which should be placed in a dedicated project directory. From this directory, the user can optionally create and activate a virtual environment, install the required third-party libraries (requests and Pillow) using pip, and configure the necessary environment variables for API access. Specifically, the application expects OPENWEATHER_API_KEY, SPOONACULAR_API_KEY, GOOGLE_BOOKS_API_KEY, and IPGEOLOCATION_API_KEY to be set in the shell so that the system can retrieve current weather conditions, recipes, book data, and approximate user location. Optional SMTP-related environment variables may also be configured if the password-reset feature should send email instead of only copying a reset link to the clipboard.

After the dependencies and environment variables are configured, the application is launched from the terminal with the command python weather_food_books_cocktails_gui.py. On first run, the system automatically creates and maintains JSON-based persistence files in the project folder, including users.json for account data and catalogs.json for admin-managed comfort item catalogs, as well as a history subfolder containing per-user history files. When the application starts, a login dialog is displayed that allows users to register, sign in, or reset passwords. Upon successful authentication, the main GUI window opens with multiple tabs (User, Weather, Comfort Food, Books, Beverages, History, and optionally Admin Panel), and the user can immediately begin fetching weather data, exploring context-aware recommendations, saving selections to history, and exporting their past choices.

Generated Code Documentation
1. Utility Functions
Helper functions for hashing, timestamps, JSON persistence, and clipboard.

now_iso() -> str
Returns current local time as YYYY-MM-DD HH:MM:SS string.

sha256(s: str) -> str
SHA-256 hex digest of a UTF-8 string.

password_hash(password: str, salt: Optional[str] = None) -> tuple[str, str]
Generates or reuses a hex salt and returns (salt, hash) using sha256(salt + password).

load_json(path: str, default)
Safely load JSON from disk; on error or missing file, logs and returns default.

save_json(path: str, data) -> bool
Safely write JSON to disk; returns True if successful.

copy_to_clipboard(root: tk.Tk, text: str) -> bool
Copies text to the Tkinter clipboard; returns True if it succeeds.

2. AdminNotifier Class
Minimal helper to surface operational alerts (e.g., API errors, catalog errors) only to admins who opted in.

Attributes

app_getter: callable returning the current App instance.

Methods

_should_notify() -> bool
Checks whether the current user exists, is admin, and has notifications enabled.

alert(title: str, message: str) -> None
Logs a warning and, if allowed, shows a messagebox.showwarning popup.

3. EmailHelper Class
Optional SMTP-based email sender used for password reset links.

Methods

send_reset_email(to_email: str, reset_link: str) -> bool
Builds a plain-text email and sends via SMTP using env vars:
SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASSWORD, SMTP_FROM.
Returns True on success, False otherwise.

4. AuthManager Class
Manages user registration, login, password change/reset, admin flag, notification preference, and account deletion.

Attributes

path: str — path to users.json.

data: dict — structure:

json
Copy code
{
  "users": {
    "email@example.com": {
      "salt": "...",
      "passhash": "...",
      "created_at": "...",
      "notify": true,
      "is_admin": false,
      "reset": {
        "token": "...",
        "exp": 1234567890
      }
    }
  }
}
Methods

_save() -> bool
Persists self.data to users.json.

exists(email: str) -> bool
Checks if a user record exists.

is_admin(email: str) -> bool
Returns True if user has is_admin flag.

register(email: str, password: str, is_admin: bool = False) -> tuple[bool, str]
Creates a new user with salted hash; fails if email exists.

authenticate(email: str, password: str) -> bool
Verifies credentials using stored salt + hash.

change_password(email: str, current_password: str, new_password: str) -> tuple[bool, str]
Validates current password and updates hash to new password.

start_reset(email: str) -> tuple[bool, str]
Generates a reset token with 1-hour expiry, saves under reset, sends or returns a reset link (app://reset?...).

finish_reset(email: str, token: str, new_password: str) -> tuple[bool, str]
Validates token and expiration, updates password, removes reset record.

set_notify(email: str, notify: bool) -> None
Enables/disables admin alert popups for a user.

get_notify(email: str) -> bool
Reads notification preference.

delete_account(email: str) -> bool
Removes the user from users.json and deletes their history file.

5. HistoryManager Class
Per-user storage of weather-linked picks (food, book, drink) and export utilities.

Attributes

user_email: str — logical owner of the history.

path: str — path to history/history_<email>.json.

items: list[dict] — list of history entries, each:

json
Copy code
{
  "timestamp": "...",
  "type": "food | book | drink",
  "label": "Lasagna",
  "metadata": { },
  "weather": { }
}
Methods

history_path_for(email: str) -> str (static)
Builds sanitized file path from email.

add(item_type: str, label: str, metadata: dict, weather_snapshot: dict) -> None
Appends an entry and saves to disk.

delete_index(idx: int) -> None
Removes an entry by list index.

save() -> None
Persists current items list to disk.

export_csv(filepath: str, selection: Optional[list[int]]) -> None
Writes selected (or all) items to a CSV with columns: timestamp, type, label, metadata, weather.

export_json(filepath: str, selection: Optional[list[int]]) -> None
Writes selected (or all) items as indented JSON.

6. CatalogManager Class
Admin-editable local catalogs for extra comfort foods, beverages, and books.

Attributes

path: str — path to catalogs.json.

notifier: Optional[AdminNotifier] — used to alert on load/save errors.

data: dict — normalized as:

json
Copy code
{
  "foods": [ ... ],
  "beverages": [ ... ],
  "books": [ ... ]
}
Methods

_load_with_guard() -> dict
Loads catalogs; on corruption or error, alerts admin, recreates using default schema.

_save_with_guard(data: dict) -> bool
Saves catalogs to disk; alerts admin if save fails.

all() -> dict
Returns current catalog data.

add_item(category: str, value: str) -> bool
Adds unique item to category; persists to disk.

edit_item(category: str, old_value: str, new_value: str) -> bool
Replaces existing item text and saves.

delete_item(category: str, value: str) -> bool
Removes item from category and saves.

7. WeatherClient Class
Wrapper around OpenWeatherMap “current weather” endpoint with error reporting.

Attributes

api_key: str — OpenWeatherMap API key.

notifier: Optional[AdminNotifier] — sends alerts on repeated failures.

Methods

current_by_city(city: str) -> dict
Calls OpenWeatherMap to get current weather for a city; returns a dict with fields:
city, description, temp_c, icon, feels_like, humidity, wind, and raw.
On error, returns {"error": "..."} and optionally alerts admin.

icon_url(icon_code: str) -> str (static)
Returns URL for weather icon PNG.

8. SpoonacularClient Class
Recipe search client using Spoonacular’s complexSearch.

Attributes

api_key: str — Spoonacular API key.

Methods

search(query: str, number: int = 8, tags: Optional[list[str]] = None) -> list[dict]
Calls complexSearch with addRecipeInformation and instructionsRequired;
returns a list of recipe dicts or [] on error.

9. GoogleBooksClient Class
Simple search wrapper around Google Books Volumes API.

Attributes

api_key: str — Google Books API key.

Methods

search(query: str, max_results: int = 20, start_index: int = 0) -> list[dict]
Queries https://www.googleapis.com/books/v1/volumes and returns items list or [] on error.

10. CocktailDBClient Class
Client for TheCocktailDB for drink search and details.

Attributes

BASE: str — base URL for API (/api/json/v1/1).

Methods

search_by_name(name: str) -> list[dict]
Searches drinks by name.

filter_by_alcoholic(kind: str) -> list[dict]
Filters by alcoholic / non-alcoholic.

filter_by_ingredient(ingredient: str) -> list[dict]
Filters drinks by ingredient.

lookup_by_id(drink_id: str) -> Optional[dict]
Returns full details for a drink id, or None on error.

11. Mood & Suggestion Helpers
Map weather to mood-based queries and lists of ideas.

derive_mood(weather_desc: str, temp_c: float) -> dict
Returns a dict with food_query, book_query, and cocktail_query based on temperature bands and keywords like rain, snow, clear.

mood_food_ideas(weather_desc: str, temp_c: float, catalogs: Optional[dict]) -> list[str]
Builds base comfort-food ideas from mood and prepends admin catalog foods, deduplicated.

mood_drink_ideas(weather_desc: str, temp_c: float, catalogs: Optional[dict]) -> list[str]
Builds base beverage ideas by temperature, then prepends admin beverages, deduplicated.

12. LoginDialog Class
Modal tk.Toplevel handling Sign In, Register (with optional admin flag), and password reset start/finish.

Attributes (main)

auth: AuthManager — backend for account operations.

Various Entry fields for sign in, register, and reset flows.

result_email: Optional[str] — email of successfully signed-in user.

Methods

_do_sign_in()
Authenticates credentials; on success sets result_email and closes dialog.

_do_register()
Registers new user (optionally as admin) after password confirmation.

_do_send_reset()
Calls AuthManager.start_reset, may copy reset link to clipboard.

_do_finish_reset()
Completes password reset with token & new password.

13. WeatherTab Class
Tab for city-based weather lookup, icon display, and quick mood-based previews for food, books, and drinks.

Key Attributes

client: WeatherClient

books_client: GoogleBooksClient

catalog_mgr: CatalogManager

UI elements: city_entry, info label, icon_label, listboxes for food_list, books_list, drinks_list.

latest: Optional[dict] — last successful weather result.

Key Methods

detect_location()
Uses IPGEOLOCATION_API_KEY to auto-detect city via ipgeolocation.io and triggers fetch_weather().

refresh_weather()
Re-fetches weather for current city.

fetch_weather()
Calls WeatherClient.current_by_city, updates labels/icon, and populates mood previews.

_update_previews()
Populates comfort food & drink ideas, then asynchronously loads book suggestions from Google Books.

push_to_others()
Emits <<WeatherUpdated>> event to let other tabs use the latest weather snapshot.

14. RecipesTab Class
Comfort-food tab: shows weather-based food ideas, fetches Spoonacular recipes, and saves selections to history.

Key Attributes

client: SpoonacularClient

weather_tab: WeatherTab

catalog_mgr: CatalogManager

Listboxes: ideas, results; items holds current recipe results.

Key Methods

populate_ideas()
Fills ideas listbox using mood_food_ideas.

search_direct()
Uses user-entered keyword; calls search_for().

search_for(query: str)
Asynchronously calls Spoonacular search; populates results with recipe summaries.

open_recipe()
Attempts to open recipe URL; if not available, fetches detailed info from Spoonacular and shows ingredients + instructions in a popup.

save_selected()
Saves selected recipe to HistoryManager as type "food", attaches last weather snapshot, and refreshes HistoryTab.

15. BooksTab Class
Books tab with genre search, Use Weather Mood, decade filter, Google Books integration, and history save.

Key Attributes

client: GoogleBooksClient

weather_tab: WeatherTab

catalog_mgr: CatalogManager

decade_var + decade_box combobox for filtering.

items: list[dict] — current Google Books results.

Key Methods

use_mood()
Uses derive_mood to set a mood-based book_query and searches.

search() / _search_internal(q, start_index)
Calls GoogleBooksClient.search, filters by decade, populates results list.

shuffle()
Uses different start_index to get a different slice of results.

open_google_books()
Opens the book’s Info or Canonical link in browser.

save_selected()
Saves selected book, either as Google Books result (with metadata) or catalog bullet, to history as "book".

16. CocktailsTab Class
Beverage tab combining weather-based ideas, CocktailDB searches, alcoholic filter, and history saving.

Key Attributes

client: CocktailDBClient

weather_tab: WeatherTab

catalog_mgr: CatalogManager

Listboxes: ideas, results; items holds current drinks.

filter_var, filter_box — filter by All / Non-Alcoholic / Alcoholic.

Key Methods

populate_ideas()
Fills drink ideas from mood_drink_ideas.

search_direct() / search_for_idea()
Searches by drink keyword or by ingredient ("X drinks").

_search_drinks_by_ingredient(ingredient) / _search_drinks(query)
Calls CocktailDB filter/search, enriches with full drink info, applies filter.

_apply_filter(drinks) / _reapply_filter()
Applies alcoholic / non-alcoholic filter to the list.

open_cocktail_page()
Displays drink name, ingredients, and instructions in a popup.

save_selected()
Saves selected drink (with id and alcoholic flag) to history as "drink".

17. HistoryTab Class
Treeview-based view of all saved history items with delete and export actions.

Key Attributes

history: HistoryManager

tree: ttk.Treeview with columns time, type, label, weather.

Key Methods

refresh()
Clears and repopulates the tree from history.items.

selected_indices() -> list[int]
Returns list indices of selected rows.

delete_selected()
Deletes selected entries from HistoryManager and refreshes view.

export_selected(fmt: str) / export_all(fmt: str)
Opens file dialog and exports selections or all entries as CSV/JSON.

18. UserTab Class
Account-management tab for logged-in user: change password, sign out, delete account.

Key Attributes

app: App — reference to main app.

Password fields: curr_pw, new_pw, conf_pw.

Methods

_change_password()
Calls AuthManager.change_password for current user; shows status messages.
(Sign out and delete account buttons delegate directly to App._sign_out and App._delete_account.)

19. AdminPanel Class
Admin-only tab for CRUD on the shared catalogs: foods, beverages, books.

Key Attributes

catalog_mgr: CatalogManager

For each category, a LabelFrame, Listbox, and input entry.

Methods

_make_section(title, category, row_index)
Builds UI for a catalog category and wires Add/Delete/Edit callbacks.

_populate_list(lst, cat)
Loads items from catalog_mgr into a listbox.

20. App Class
Main Tkinter application: handles authentication, builds all tabs, wires events, and manages shared state.

Key Attributes

auth: AuthManager

current_user: Optional[str]

history: HistoryManager (for current user)

catalogs: CatalogManager

API clients: weather_client, spoon_client, gb_client, cocktail_client

notifier: AdminNotifier

Tabs: tab_user, tab_weather, tab_recipes, tab_books, tab_cocktails, tab_history, optional tab_admin

last_weather_snapshot: dict — cached snapshot used for history entries.

notebook: ttk.Notebook — main tab container.

Key Methods

__init__()
Runs login dialog, initializes API clients, history, menu, tabs, admin panel, bindings, and footer.

_run_login_flow()
Shows LoginDialog and waits; sets current_user on success.

_build_menu()
Builds Account menu with notification toggle, Sign Out, Delete Account.

_sign_out()
Confirms, then destroys current window and starts a fresh App instance.

_delete_account()
Confirms, calls AuthManager.delete_account, then restarts app.

on_weather_updated()
Captures latest weather info into last_weather_snapshot and refreshes HistoryTab.

show_api_info()
Shows a popup listing external APIs and required env vars.

21. Dependencies
Python Standard Library
os, io, json, csv, hashlib, hmac, secrets, time, logging, threading, webbrowser, random, re, smtplib, ssl, datetime, typing

tkinter, tkinter.ttk, tkinter.messagebox, tkinter.filedialog, tkinter.simpledialog

Third-Party Libraries
requests — HTTP calls to OpenWeatherMap, ipgeolocation.io, Spoonacular, Google Books, TheCocktailDB, and weather icon download.

Pillow (PIL) — Image, ImageTk for weather icon loading and display.

External Web APIs / Services
OpenWeatherMap — current weather & icons (requires OPENWEATHER_API_KEY).

ipgeolocation.io — IP-based city detection (requires IPGEOLOCATION_API_KEY).

Spoonacular — recipe search and detailed recipe info (SPOONACULAR_API_KEY).

Google Books API — book search & metadata (GOOGLE_BOOKS_API_KEY).

TheCocktailDB — cocktail search & details (public API).

Optional SMTP server — via SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASSWORD, SMTP_FROM for password reset emails.

Workflow
Launch & Authentication
When the user opens the application, they first see a Login dialog asking for email and password.

If they don’t have an account, they switch to Register, enter email and password (twice), optionally tick Register as Admin, and submit. On success, they can then sign in with those credentials.

If they’ve forgotten their password, they go to Reset Password, enter their email, and click Send Reset Link. If SMTP is configured, the app emails a link; otherwise, it provides a token link that can be copied from the message box.

To complete the reset, they paste the token into the Token field, enter a new password, click Reset Password, and then sign in with the new password.

Main Interface & Tabs
After successful login, the main window opens with a tabbed interface and an Account menu at the top.

The tabs are: User, Weather, Comfort Food, Books, Beverages, and History; if the user is an admin, an Admin Panel tab is also shown.

The footer shows the currently logged-in email, whether they’re an Admin or User, and a tip about using weather to drive suggestions.

User Tab: Account Management
In the User tab, the user sees their logged-in email and fields to change their password: current password, new password, and confirmation.

They click Change Password to update it; success or error is shown via a popup.

At the bottom, Sign Out logs them out and restarts the app from the login dialog, while Delete Account removes their account and history (after confirmation) and returns them to a fresh login state.

Weather Tab: Getting Weather & Mood Suggestions
In the Weather tab, the user can type a city and click Get Weather to fetch current conditions via OpenWeatherMap.

Alternatively, they can click Detect Location (if IPGEOLOCATION_API_KEY is configured) to auto-detect their city and immediately fetch weather.

The app displays a short weather summary, temperature, humidity, wind speed, and an icon. Below, three preview lists appear: Comfort Food Ideas, Book Suggestions, and Beverage Ideas, all based on temperature and description (e.g., rain, snow, clear).

When the user clicks Use Result in Other Tabs, the app emits a weather update event and records a snapshot so that subsequent saves in other tabs are tagged with the current weather context.

Comfort Food Tab: From Mood → Ideas → Recipes → History
In the Comfort Food tab, the user can either type a food keyword and click Search, or click Use Weather Mood to auto-fill ideas based on the last weather.

The Food Ideas list is populated with mood-based and admin-managed comfort foods; double-clicking an idea triggers a Spoonacular recipe search and populates the Recipes list with titles, time, and servings.

Double-clicking a recipe attempts to open its web page; if that fails, the app fetches full recipe details (ingredients and step-by-step instructions) and shows them in a popup.

When they find something they like, they select a recipe and click Save Selected. The app creates a "food" history entry containing the recipe title, source metadata, and the last weather snapshot, and the History tab updates immediately.

Books Tab: Weather-Aware Book Discovery & Saving
In the Books tab, the user can type a keyword/genre and click Search, or hit Use Weather Mood to search for mood-aligned genres like “cozy mystery,” “beach read,” or “adventure.”

They can choose a Decade filter (e.g., 1990s, 2000s) to see only books published in that decade; results are pulled from Google Books and listed with title, authors, and year.

Clicking Shuffle re-runs the search with a different starting index to show a different slice of results.

Double-clicking a book opens its Google Books info page in the browser. Selecting a book and clicking Save Selected stores a "book" history entry with title, Google Books ID/link, and the last weather snapshot.

Beverages Tab: Weather-Based Drinks & Cocktail Details
In the Beverages tab, the user can search by drink keyword or click Use Weather Mood to see temperature-based drink ideas like “Masala Chai,” “Lemonade,” or “Watermelon drinks.”

The Drink Ideas list feeds into CocktailDB searches either by name or by ingredient (for ideas like “Mango drinks”).

The user can choose a Filter: All, Non-Alcoholic, or Alcoholic; the results list is filtered accordingly and enriched with full drink data when needed.

Double-clicking a drink shows its name, ingredients, and instructions in a popup, so the user can prepare it.

Clicking Save Selected adds a "drink" entry to history, storing drink name, CocktailDB id, alcoholic flag, and the weather snapshot.

History Tab: Viewing, Cleaning, and Exporting Picks
In the History tab, the user sees a table of all saved items (food, books, drinks) with timestamp, type, label, and a compact summary of the weather at the time it was saved.

They can select rows and click Delete Selected to remove specific entries from their personal history.

They can click Export Selected (CSV/JSON) to export only selected rows, or Export All (CSV/JSON) to dump the entire history to a file, for later analysis or backup.

Admin Panel (Admins Only): Curating Shared Catalogs
If the logged-in user is marked as admin, the Admin Panel tab appears, with sections for Foods, Beverages, and Books.

In each section, admins can add new items via an input box and Add button, see all current catalog items in a list, double-click an item to rename it, or select an item and click Delete Selected to remove it.

These catalogs feed back into the Weather and idea tabs, making admin-curated foods, drinks, and books appear at the top of suggestion lists for all users on that machine.

Account Menu, Notifications & Exit
From the top Account menu, users can toggle Receive Notifications (Admin alerts), which controls whether admin error alerts (e.g., API or catalog save problems) appear as popups.

The same menu provides Sign Out and Delete Account options that mirror the buttons in the User tab.

At any time, the user can close the main window to exit the application; on the next launch, they will again be taken through the login flow.
