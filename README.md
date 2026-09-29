
# PBL-1_Project_1.0-
A real-time phishing URL detector built with Python Flask &amp; Chrome Extension. Analyzes URLs for suspicious patterns, assigns a risk score (0-100%), flags threats with detailed reasoning, and automatically scans all links on any webpage.
# 🛡️ Phishing Website Detector

A real-time phishing URL detection tool built with Python Flask and Chrome Extension.
Built as part of Project Based Learning-1.

---

## 📁 Project Structure

Phishing_detector/

├── extension/          # Chrome Extension files

│   ├── manifest.json

│   ├── popup.html

│   ├── popup.js

│   ├── background.js

│   └── content.js

├── templates/

│   └── index.html      # Web interface

├── venv/               # Virtual environment

├── app.py              # Flask backend server

├── model.py            # Detection engine

├── phishing_model.pkl  # Saved model

└── README.md

---

## ⚙️ Requirements

- Python 3.12
- Google Chrome browser
- VS Code (recommended)
Note: (plz)Open the repo in vs code for better integration.

---

## 🚀 Setup & Run

### Step 1 — Clone or Download the project
Place the `Phishing_detector` folder anywhere on your system (avoid OneDrive).

### Step 2 — Open in VS Code
File → Open Folder → Select Phishing_detector

### Step 3 — Open Terminal in VS Code
Terminal → New Terminal

# 1. to create a venv, run:
python -m venv venv

### Step 4 — Environment Configuration (Choose Option A or B)

🔹 Option A: You are using Windows**
now you can activate it using:

.\venv\Scripts\activate

Note: You should see (venv) appear in your terminal. You can now skip Option B and  proceed directly to Step 5! ➡️

🔸 Option B: You are using Mac, Linux, or hit compatibility issues
If you are on a different operating system, you must delete the existing venv folder and generate a fresh one compatible with your OS:
#  Activate the new environment based on your OS:
# For Mac/Linux Terminal:
source venv/bin/activate

# For Windows (if resetting):
.\venv\Scripts\activate
(Python will automatically regenerate a fresh __pycache__ once the scripts run).

# Step 5 — Install Dependencies
pip install flask flask-cors

### Step 6 — Run the Detection Model
python model.py

Expected output:

Phishing Detector model ready!
URL: https://www.google.com → 0% SAFE
URL: http://192.168.1.1/login/verify → 80% PHISHING

### Step 7 — Start Flask Server
python app.py

Expected output:
Running on http://127.0.0.1:5000
Note:Keep the Flask server (python app.py) running while using the Chrome extension or web interface.

### Step 8 — Open Web Interface
Open Chrome and go to:
http://127.0.0.1:5000

---

## 🔌 Load Chrome Extension

1. Open Chrome → go to `chrome://extensions`
2. Enable **Developer Mode** (top right toggle)
3. Click **Load unpacked**
4. Select the `extension` folder
5. Extension is now active!

---

## 🧪 Test URLs

| URL | Expected Result |
|-----|----------------|
| https://www.google.com | ✅ SAFE |
| http://192.168.1.1/login/verify | 🚨 PHISHING |
| http://paypal-secure-login.xyz/confirm | ⚠️ SUSPICIOUS |

---

## 💡 How It Works

1. User enters or clicks a URL
2. Flask backend analyzes URL features:
   - IP address usage
   - Suspicious keywords
   - HTTPS presence
   - URL length
   - Special characters
3. Risk score (0-100%) is calculated
4. Result shown with explanation

---

## ⚠️ Note

Keep the Flask server (`python app.py`) running while using the Chrome extension or web interface.

---

## 👤 Author

- Name: Patel Unnati Kanubhai
  
