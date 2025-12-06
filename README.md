## Build and Run Instructions

### 1. Prerequisites

#### 1.1 Python

- **Required version:** Python **3.8 or newer**
- **Check version:**
  - `python --version`

#### 1.2 Tkinter

- **Tkinter:** usually bundled with Python
- **Quick check (no error = OK):**
  - `python -c "import tkinter; print('Tkinter OK')"`

#### 1.3 Internet Access

- **Internet access is required for:**
  - **OpenWeatherMap**
  - **Spoonacular**
  - **Google Books**
  - **TheCocktailDB**
  - **ipgeolocation.io** (for **Detect Location**)

---

### 2. Project Setup

#### 2.1 Create Project Folder

- **Create a folder anywhere on your machine**, for example:
  - `C:\Projects\weather_recommender`

#### 2.2 Save the Script

- **Save your script in that folder as:**
  - `weather_food_books_cocktails_gui.py`
- **Your folder will look like:**

      weather_recommender/
      └── weather_food_books_cocktails_gui.py

---

### 3. Create & Activate a Virtual Environment (Recommended)

#### 3.1 Create the Virtual Environment

- **From inside the project folder, run:**
  - `python -m venv venv`

#### 3.2 Activate on Windows (Command Prompt)

- **Command:**
  - `venv\Scripts\activate`

#### 3.3 Activate on Windows (PowerShell)

- **Command:**
  - `venv\Scripts\Activate.ps1`

#### 3.4 Activate on macOS / Linux

- **Command:**
  - `source venv/bin/activate`

## 4. Install Dependencies

#### 4.1 Required Libraries

- **External libraries needed:**
  - `requests`
  - `Pillow`
- **Install with pip:**
  - `pip install requests pillow`
- **Note:**
  - Everything else (such as `json`, `csv`, `hashlib`, `tkinter`, etc.) comes bundled with Python.

---

## 5. Configure API Keys

#### 5.1 Required Environment Variables

- **Your code expects these environment variables:**
  - `OPENWEATHER_API_KEY`
  - `SPOONACULAR_API_KEY`
  - `GOOGLE_BOOKS_API_KEY`
  - `IPGEOLOCATION_API_KEY` (for the **“Detect Location”** button)

#### 5.2 Windows (Command Prompt)

- **Run these in the same terminal after activating the venv:**
  - `set OPENWEATHER_API_KEY=1517def1af3a3337eebc71f01ab4e0a8`
  - `set SPOONACULAR_API_KEY=fb3b3454b6c540b7b8b9edfb4d492d46`
  - `set GOOGLE_BOOKS_API_KEY=AIzaSyD275C7Sut00hyeRrAtIqh2p4UrRB84MxU`
  - `set IPGEOLOCATION_API_KEY=09dda02a9e3d4df8b9ab07321efa123d`

#### 5.3 Windows (PowerShell)

- **Run these after activating the venv:**
  - `$env:OPENWEATHER_API_KEY="1517def1af3a3337eebc71f01ab4e0a8"`
  - `$env:SPOONACULAR_API_KEY="fb3b3454b6c540b7b8b9edfb4d492d46"`
  - `$env:GOOGLE_BOOKS_API_KEY="AIzaSyD275C7Sut00hyeRrAtIqh2p4UrRB84MxU"`
  - `$env:IPGEOLOCATION_API_KEY="09dda02a9e3d4df8b9ab07321efa123d"`

#### 5.4 macOS / Linux

- **Run these in your shell (bash / zsh / similar):**
  - `export OPENWEATHER_API_KEY=1517def1af3a3337eebc71f01ab4e0a8`
  - `export SPOONACULAR_API_KEY=fb3b3454b6c540b7b8b9edfb4d492d46`
  - `export GOOGLE_BOOKS_API_KEY=AIzaSyD275C7Sut00hyeRrAtIqh2p4UrRB84MxU`
  - `export IPGEOLOCATION_API_KEY=09dda02a9e3d4df8b9ab07321efa123d`

#### 5.5 Updating Keys Later

- **If you change keys later, just update these environment variable values.**

---

## 6. Run the Application

#### 6.1 Run Command

- **With the virtual environment active and environment variables set, run:**
  - `python weather_food_books_cocktails_gui.py`

#### 6.2 Step 1 – Auth Dialog

- **First screen:** a **Sign In / Register / Reset** dialog.
- **New user flow:**
  - Go to **Register**, enter **email + password**, optionally tick **“Register as Admin”**, then sign in.
- **Returning user flow:**
  - Use the **Sign In** tab and enter your existing **email + password**.

#### 6.3 Step 2 – Main Window Tabs

- **User tab:**
  - Change password, sign out, delete account.
- **Weather tab:**
  - City input, **Detect Location** button, weather details, live icon, and three suggestion lists.
- **Comfort Food tab:**
  - Weather-based food ideas → Spoonacular recipes → **Save to history**.
- **Books tab:**
  - Weather-based mood, decade filter, book search → **Save to history**.
- **Beverages tab:**
  - Weather-based drink ideas, alcohol filter, drink recipes → **Save to history**.
- **History tab:**
  - View saved items, delete items, export as **CSV** or **JSON**.
- **Admin Panel tab (admin accounts only):**
  - Manage local `catalogs.json` for **foods**, **beverages**, and **books**.

---

## 7. Files Created at First Run

#### 7.1 Typical Folder Structure

- **After you use the app, the folder will typically look like:**

      weather_recommender/
      ├── weather_food_books_cocktails_gui.py   # Your main script
      ├── users.json                            # Accounts, password hashes, reset tokens, admin flag
      ├── catalogs.json                         # Admin-managed foods / beverages / books
      └── history/
          └── history_<email>.json              # Per-user saved food/book/drink + weather snapshots

- **Note:** You **do not** need to create these JSON files manually; the app will create and update them when needed.

---

## 8. Quick Troubleshooting

#### 8.1 GOOGLE_BOOKS_API_KEY Error / Window Closes Immediately

- **Symptom:** Window closes immediately or you see an error about `GOOGLE_BOOKS_API_KEY`.
- **Fix:** Make sure `GOOGLE_BOOKS_API_KEY` is set correctly in the **same terminal** before running Python.

#### 8.2 Missing `requests` or `PIL`

- **Symptom:** `ModuleNotFoundError: No module named 'requests'` or `No module named 'PIL'`.
- **Fix:** Install the dependencies:
  - `pip install requests pillow`

#### 8.3 “Detect Location” Key Not Set

- **Symptom:** “Detect Location” says key not set.
- **Fix:** Ensure `IPGEOLOCATION_API_KEY` is defined in your environment.

#### 8.4 Weather / Recipe / Book / Drink Lookups Failing

- **Symptom:** API-based lookups fail or return errors.
- **Fix:**
  - Check your **internet connection**.
  - Verify that all API keys are **valid** and **not rate-limited**.
 
## 9. Instructions

To build and run the Weather-Based Comfort Food, Beverage, and Book Recommender, the user must have Python 3.8 or later installed, along with Tkinter (bundled with most standard Python distributions) and an active internet connection for external API calls. The project consists of a single main script, weather_food_books_cocktails_gui.py, which should be placed in a dedicated project directory. From this directory, the user can optionally create and activate a virtual environment, install the required third-party libraries (requests and Pillow) using pip, and configure the necessary environment variables for API access. Specifically, the application expects OPENWEATHER_API_KEY, SPOONACULAR_API_KEY, GOOGLE_BOOKS_API_KEY, and IPGEOLOCATION_API_KEY to be set in the shell so that the system can retrieve current weather conditions, recipes, book data, and approximate user location. Optional SMTP-related environment variables may also be configured if the password-reset feature should send email instead of only copying a reset link to the clipboard.

After the dependencies and environment variables are configured, the application is launched from the terminal with the command python weather_food_books_cocktails_gui.py. On first run, the system automatically creates and maintains JSON-based persistence files in the project folder, including users.json for account data and catalogs.json for admin-managed comfort item catalogs, as well as a history subfolder containing per-user history files. When the application starts, a login dialog is displayed that allows users to register, sign in, or reset passwords. Upon successful authentication, the main GUI window opens with multiple tabs (User, Weather, Comfort Food, Books, Beverages, History, and optionally Admin Panel), and the user can immediately begin fetching weather data, exploring context-aware recommendations, saving selections to history, and exporting their past choices.
