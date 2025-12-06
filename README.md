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
