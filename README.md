## Build and Run Instructions

### 1. Prerequisites

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

### 2. Project Setup

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
PowerShell:

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

IPGEOLOCATION_API_KEY (for “Detect Location” button)

Windows (Command Prompt)
Run these in the same terminal after activating the venv:

bat
Copy code
set OPENWEATHER_API_KEY=1517def1af3a3337eebc71f01ab4e0a8
set SPOONACULAR_API_KEY=fb3b3454b6c540b7b8b9edfb4d492d46
set GOOGLE_BOOKS_API_KEY=AIzaSyD275C7Sut00hyeRrAtIqh2p4UrRB84MxU
set IPGEOLOCATION_API_KEY=09dda02a9e3d4df8b9ab07321efa123d
PowerShell

powershell
Copy code
$env:OPENWEATHER_API_KEY="1517def1af3a3337eebc71f01ab4e0a8"
$env:SPOONACULAR_API_KEY="fb3b3454b6c540b7b8b9edfb4d492d46"
$env:GOOGLE_BOOKS_API_KEY="AIzaSyD275C7Sut00hyeRrAtIqh2p4UrRB84MxU"
$env:IPGEOLOCATION_API_KEY="09dda02a9e3d4df8b9ab07321efa123d"
macOS / Linux

bash
Copy code
export OPENWEATHER_API_KEY=1517def1af3a3337eebc71f01ab4e0a8
export SPOONACULAR_API_KEY=fb3b3454b6c540b7b8b9edfb4d492d46
export GOOGLE_BOOKS_API_KEY=AIzaSyD275C7Sut00hyeRrAtIqh2p4UrRB84MxU
export IPGEOLOCATION_API_KEY=09dda02a9e3d4df8b9ab07321efa123d
If you change keys later, just update these values.

6. Run the Application
With the virtual environment active and environment variables set:

bash
Copy code
python weather_food_books_cocktails_gui.py
What you’ll see:

A Sign In / Register / Reset dialog.

New user: go to Register, enter email + password (optionally tick “Register as Admin”), then sign in.

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

9. Instructions (Narrative)
To build and run the Weather-Based Comfort Food, Beverage, and Book Recommender, the user must have Python 3.8 or later installed, along with Tkinter (bundled with most standard Python distributions) and an active internet connection for external API calls. The project consists of a single main script, weather_food_books_cocktails_gui.py, which should be placed in a dedicated project directory. From this directory, the user can optionally create and activate a virtual environment, install the required third-party libraries (requests and Pillow) using pip, and configure the necessary environment variables for API access. Specifically, the application expects OPENWEATHER_API_KEY, SPOONACULAR_API_KEY, GOOGLE_BOOKS_API_KEY, and IPGEOLOCATION_API_KEY to be set in the shell so that the system can retrieve current weather conditions, recipes, book data, and approximate user location. Optional SMTP-related environment variables may also be configured if the password-reset feature should send email instead of only copying a reset link to the clipboard.
After the dependencies and environment variables are configured, the application is launched from the terminal with the command python weather_food_books_cocktails_gui.py. On first run, the system automatically creates and maintains JSON-based persistence files in the project folder, including users.json for account data and catalogs.json for admin-managed comfort item catalogs, as well as a history subfolder containing per-user history files. When the application starts, a login dialog is displayed that allows users to register, sign in, or reset passwords. Upon successful authentication, the main GUI window opens with multiple tabs (User, Weather, Comfort Food, Books, Beverages, History, and optionally Admin Panel), and the user can immediately begin fetching weather data, exploring context-aware recommendations, saving selections to history, and exporting their past choices.

23. Acknowledgements
I would like to sincerely thank my professor Dave Pitts for their steady guidance, clear expectations, and thoughtful feedback at every stage of this project, which helped shape both the system design and this report. I am also grateful to my classmates and peers, whose questions, suggestions, and informal testing sessions led to several usability improvements in the interface and feature flow. Special appreciation goes to ComfortNest Labs and Director of Wellness Innovation Naga Bhargavi Chakka for inspiring the focus on weather-based comfort decisions and framing the problem around decision fatigue and wellness. Finally, I would like to acknowledge the wider open-source community and the creators of Python, Tkinter/PySide6, and the external services used (OpenWeather, Spoonacular, Google Books, TheCocktailDB, and related libraries), whose tools, documentation, and examples made it possible to implement and refine this recommender system.

24. Conclusions
The Weather-Based Comfort Food + Beverage + Book Recommender demonstrates that a focused, desktop-based tool can meaningfully support everyday lifestyle decisions by linking local weather, personal preferences, and curated content in one place. The system successfully delivers secure user accounts, weather-aware suggestions for meals, drinks, and books, a clear tabbed interface, and a history feature that records choices alongside weather context. Together, these elements address the original problem of app-hopping and decision fatigue by offering a small, relevant set of options instead of overwhelming users. The underlying design—built on modular managers for authentication, catalogs, history, and API access—also makes the application easier to maintain and extend. In the future, this work can be expanded with richer personalization based on user feedback, additional languages and units, and optional integrations with partner services, further strengthening its role as a practical support tool for comfort and wellness-focused decisions.
