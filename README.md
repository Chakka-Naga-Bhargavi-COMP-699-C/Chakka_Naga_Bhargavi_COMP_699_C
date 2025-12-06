# Build and Run Instructions

## 1. Prerequisites

- **Python:** 3.8 or newer  
  - **Check version:**
    - `python --version`
- **Tkinter:** usually bundled with Python  
  - **Quick check (no error = OK):**
    - `python -c "import tkinter; print('Tkinter OK')"`
- **Internet access required for:**
  - OpenWeatherMap  
  - Spoonacular  
  - Google Books  
  - TheCocktailDB  
  - ipgeolocation.io (for **Detect Location**)

---

## 2. Project Setup

### 2.1 Create a Folder

Create a project folder anywhere, for example:

```text
C:\Projects\weather_recommender
2.2 Add the Script
Save your script inside that folder as:

text
Copy code
weather_food_books_cocktails_gui.py
Your folder structure should look like:

text
Copy code
weather_recommender/
└── weather_food_books_cocktails_gui.py
3. Create & Activate a Virtual Environment (Recommended)
From inside the project folder, run:

bash
Copy code
python -m venv venv
Windows (Command Prompt)
bat
Copy code
venv\Scripts\activate
Windows (PowerShell)
powershell
Copy code
venv\Scripts\Activate.ps1
macOS / Linux
bash
Copy code
source venv/bin/activate
4. Install Dependencies
Only two external libraries are required:

bash
Copy code
pip install requests pillow
All other modules (json, csv, hashlib, tkinter, etc.) come with Python.

5. Configure API Keys
Your application requires these environment variables:

OPENWEATHER_API_KEY

SPOONACULAR_API_KEY

GOOGLE_BOOKS_API_KEY

IPGEOLOCATION_API_KEY (for Detect Location)

Windows (Command Prompt)
bat
Copy code
set OPENWEATHER_API_KEY=1517def1af3a3337eebc71f01ab4e0a8
set SPOONACULAR_API_KEY=fb3b3454b6c540b7b8b9edfb4d492d46
set GOOGLE_BOOKS_API_KEY=AIzaSyD275C7Sut00hyeRrAtIqh2p4UrRB84MxU
set IPGEOLOCATION_API_KEY=09dda02a9e3d4df8b9ab07321efa123d
Windows (PowerShell)
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
If you update your API keys later, update these values accordingly.

6. Run the Application
With the virtual environment activated and API keys configured, run:

bash
Copy code
python weather_food_books_cocktails_gui.py
What You Will See
Login window with:

Sign In

Register

Reset Password

Main application tabs:

User – manage account, password, delete account

Weather – fetch weather, detect location

Comfort Food – mood-based food ideas → Spoonacular recipes

Books – mood-based book suggestions + decade filter

Beverages – cocktail ideas, alcoholic filter, recipe details

History – view, delete, export (CSV/JSON)

Admin Panel – (admins only) edit catalogs.json

7. Files Created at First Run
The application automatically creates the following files:

text
Copy code
weather_recommender/
├── weather_food_books_cocktails_gui.py   # Main script
├── users.json                            # Accounts + password hashes
├── catalogs.json                         # Admin-managed foods, beverages, books
└── history/
    └── history_<email>.json              # User-specific saved history
No manual creation is required.

8. Quick Troubleshooting
❗ Window Closes or GOOGLE_BOOKS_API_KEY Error
Make sure the variable is correctly set in the same terminal session.

❗ Missing Dependencies (requests, PIL)
Run:

bash
Copy code
pip install requests pillow
❗ Detect Location Not Working
Ensure:

bash
Copy code
IPGEOLOCATION_API_KEY
is defined.

❗ Weather / Recipes / Books / Drinks Not Loading
Check internet connection

Ensure API keys are valid

Ensure API request limits are not exceeded

9. Instructions (Detailed Overview)
To run the Weather-Based Comfort Food, Beverage, and Book Recommender, you need Python, Tkinter, and an internet connection. The project relies on external APIs such as OpenWeatherMap, Spoonacular, Google Books, and TheCocktailDB to generate real-time recommendations.

Once dependencies and API keys are configured, start the program using:

bash
Copy code
python weather_food_books_cocktails_gui.py
The system automatically creates JSON files (users.json, catalogs.json, and history files). After logging in or registering, the user gains access to all functional tabs, where they can explore weather-based suggestions, search recipes and books, save items to history, and export data.

Admin users can manage custom comfort item catalogs via the Admin Panel, enabling a personalized suggestion experience for all users on that machine.
```
