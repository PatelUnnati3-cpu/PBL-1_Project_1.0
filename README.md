# Phishing Website Detector

A real-time phishing and malicious link detection system that identifies suspicious URLs before you interact with them — combining rule-based heuristic analysis, real-time threat intelligence, domain-age verification, and local caching, with full transparency into why a URL is flagged.

---

## Features

- **Heuristic URL Analysis Engine** — checks each URL against 9 weighted rules: IP-based hostnames, `@` symbol usage, double-slash redirects, suspicious keywords (login, verify, banking, etc.), dash usage, dot count, URL length, HTTPS presence, and subdomain count
- **Real-Time Threat Intelligence** — live lookup against URLhaus (abuse.ch), a free, community-maintained database of confirmed malicious URLs
- **WHOIS Domain-Age Verification** — flags domains registered within the last 30 days, a common phishing indicator
- **Local Caching (SQLite)** — stores previously checked results locally for instant repeat lookups and offline resilience if the threat-intelligence service is unavailable
- **Weighted, Transparent Explainability** — every flagged URL shows the exact point contribution of each triggered rule, not just a final score
- **Web Dashboard** — manual URL checker with live risk visualization and a session-based check history log
- **Chrome Extension** — real-time scanning of links on any webpage, plus a standalone popup checker with auto-fill of the current tab's URL

---

## Project Structure
Phishing_detector/
├── extension/ # Chrome Extension files
│ ├── manifest.json
│ ├── popup.html
│ ├── popup.js
│ ├── content.js
│ └── background.js
├── templates/
│ └── index.html # Web dashboard
├── app.py # Flask backend / API server
├── model.py # Detection engine (heuristics + URLhaus + WHOIS + caching)
└── README.md

---

## Setup

**1. Install dependencies:**
pip install flask flask-cors requests python-whois

**2. Run the application:**
python app.py

That's it — the server starts at `http://127.0.0.1:5000`, initializing the local threat cache automatically on first run.

**3. Use it:**
- **Web Dashboard:** open `http://127.0.0.1:5000` in your browser
- **Chrome Extension:** go to `chrome://extensions`, enable Developer Mode, click "Load unpacked," and select the `extension` folder. Keep `python app.py` running in the background while using the extension.

---

## How It Works

1. A URL is submitted via the web dashboard or Chrome Extension
2. The system checks its local SQLite cache first — if already verified, the cached result is returned instantly
3. If not cached, the URL is checked against URLhaus's live threat database
4. The domain's registration age is checked via WHOIS
5. The URL is run through the 9 heuristic checks
6. All triggered signals are combined into a weighted risk score (0–100%), classified as SAFE, SUSPICIOUS, or PHISHING, with every contributing reason listed individually

---

## Output Example
URL: http://192.168.1.1/login/verify
Risk Score: 80% — PHISHING (threat intel: live, domain age: None days)
Reasons (weighted):
+35 — Uses IP address instead of domain name
+25 — Contains suspicious keywords (login, verify, banking, etc.)
+20 — No HTTPS — connection is not secure

---

## Future Scope

- Machine learning classifier trained on a public phishing-URL dataset
- Multi-source threat-intelligence aggregation (additional APIs alongside URLhaus)
- Browsing-history risk-log dashboard
- Native mobile app with real-time QR-code phishing detection