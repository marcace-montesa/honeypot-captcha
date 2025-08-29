# Honeypot Captcha

This project is a simple Python web application that acts as a honeypot.  
It simulates a basic CAPTCHA validation process and records metadata about users who interact with it.

---

## How It Works
1. A user visits the site and clicks a button to start.
2. They are shown a randomized text-based CAPTCHA to solve.
3. After solving it, the site displays a confirmation message.
4. In the background, the app records:
   - Timestamp (UTC)
   - User IP address
   - User-Agent (browser/system info)
   - Entry number (incremental log ID)

The logs are stored in a structured JSON format for later analysis.

---

## Purpose
This project is intended for **cybersecurity research and educational use only**.  
It can be used to:
- Experiment with honeypot concepts  
- Study automated bot interactions  
- Learn about secure Flask development and logging practices  

---

## Usage

# 1. Clone the repository
git clone https://github.com/MarcAce-Montesa/Honeypot-Captcha.git\
cd Honeypot-Captcha

# 2. Create and activate a Python virtual environment
python3 -m venv venv\
source venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Run the app
flask run

Then visit http://localhost:5000 in your browser to interact with the honeypot.

---

## Disclaimer

# This software is provided for educational and research purposes only.
# Do not deploy it in production systems where real user data may be collected without consent.
