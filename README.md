1. Prerequisites

Python: 3.8 or newer

Check version:
python --version

Tkinter: usually bundled with Python

Quick check (no error = OK):
python -c "import tkinter; print('Tkinter OK')"

Internet access: required for:

OpenWeatherMap

Spoonacular

Google Books

TheCocktailDB

ipgeolocation.io (for Detect Location)

2. Project Setup

Create a folder anywhere on your machine, for example:
C:\Projects\weather_recommender

Save your script in that folder as:
weather_food_books_cocktails_gui.py

Your folder will look like:

weather_recommender/
└── weather_food_books_cocktails_gui.py

3. Create & Activate a Virtual Environment (recommended)

From inside the project folder:

python -m venv venv


Windows (Command Prompt):

venv\Scripts\activate


Windows (PowerShell):

venv\Scripts\Activate.ps1


macOS / Linux:

source venv/bin/activate
