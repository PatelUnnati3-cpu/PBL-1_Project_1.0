# model.py
# Phishing Detector - Pure Python heuristic engine + URLhaus threat-intel lookup
# + local SQLite cache + domain-age (WHOIS) check + weighted explainability

import re
import math
import pickle
import sqlite3
import requests
import whois
from datetime import datetime, timezone
from urllib.parse import urlparse

DB_PATH = 'threat_cache.db'
NEW_DOMAIN_THRESHOLD_DAYS = 30  # domains younger than this are treated as high-risk


def init_cache_db():
    """Creates the local cache table if it doesn't already exist."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS threat_cache (
            url TEXT PRIMARY KEY,
            is_threat INTEGER,
            threat_type TEXT,
            checked_at TEXT
        )
    ''')
    conn.commit()
    conn.close()


def get_cached_result(url):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('SELECT is_threat, threat_type FROM threat_cache WHERE url = ?', (url,))
    row = cursor.fetchone()
    conn.close()
    if row:
        return bool(row[0]), row[1]
    return None


def save_to_cache(url, is_threat, threat_type):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        INSERT OR REPLACE INTO threat_cache (url, is_threat, threat_type, checked_at)
        VALUES (?, ?, ?, ?)
    ''', (url, int(is_threat), threat_type, datetime.now().isoformat()))
    conn.commit()
    conn.close()


def extract_features(url):
    features = {}
    features['url_length'] = len(url)
    features['has_ip'] = 1 if re.search(r'\d+\.\d+\.\d+\.\d+', url) else 0
    features['has_at_symbol'] = 1 if '@' in url else 0
    features['has_double_slash'] = 1 if '//' in url[7:] else 0
    features['has_dash'] = 1 if '-' in url else 0
    features['num_dots'] = url.count('.')
    features['has_https'] = 1 if url.startswith('https') else 0
    features['num_subdomains'] = len(url.split('.')) - 2
    features['has_suspicious_words'] = 1 if any(word in url.lower() for word in ['login', 'verify', 'secure', 'account', 'update', 'banking', 'confirm', 'signin', 'paypal', 'password']) else 0
    features['url_entropy'] = len(set(url)) / len(url) if len(url) > 0 else 0
    return features


def check_urlhaus(url):
    """
    Checks local cache first (offline-resilient). If not cached, queries
    URLhaus (abuse.ch) — free, no API key required — and caches the result.
    Returns (is_confirmed_threat: bool, threat_type: str or None, source: str).
    """
    cached = get_cached_result(url)
    if cached is not None:
        is_threat, threat_type = cached
        return is_threat, threat_type, 'cache'

    try:
        response = requests.post(
            'https://urlhaus-api.abuse.ch/v1/url/',
            data={'url': url},
            timeout=5
        )
        data = response.json()
        if data.get('query_status') == 'ok':
            threat_type = data.get('threat', 'malware_download')
            save_to_cache(url, True, threat_type)
            return True, threat_type, 'live'
        else:
            save_to_cache(url, False, None)
            return False, None, 'live'
    except Exception:
        return False, None, 'unavailable'


def check_domain_age(url):
    """
    Looks up the registration age of the URL's domain via WHOIS.
    Returns (age_in_days: int or None, is_newly_registered: bool).
    A domain younger than NEW_DOMAIN_THRESHOLD_DAYS is flagged as high-risk,
    since attackers commonly register a domain shortly before using it in a
    phishing campaign. Fails silently (returns None, False) if the WHOIS
    lookup is unavailable or the domain has no public registration date
    (e.g., an IP-based URL already caught by the has_ip heuristic).
    """
    try:
        domain = urlparse(url).netloc.split(':')[0]
        if re.match(r'^\d+\.\d+\.\d+\.\d+$', domain):
            return None, False  # IP address, not a registrable domain

        w = whois.whois(domain)
        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if creation_date is None:
            return None, False

        if creation_date.tzinfo is None:
            creation_date = creation_date.replace(tzinfo=timezone.utc)

        age_days = (datetime.now(timezone.utc) - creation_date).days
        return age_days, age_days < NEW_DOMAIN_THRESHOLD_DAYS
    except Exception:
        return None, False


def calculate_risk_score(url):
    features = extract_features(url)
    score = 0
    reasons = []          # kept for backward compatibility (plain text)
    reason_details = []   # new: [{'reason': str, 'points': int}], for explainability

    def add(points, text):
        nonlocal score
        score += points
        reasons.append(text)
        reason_details.append({'reason': text, 'points': points})

    # --- Real-time threat intelligence check (URLhaus + local cache) ---
    is_confirmed_threat, threat_type, source = check_urlhaus(url)
    if is_confirmed_threat:
        source_label = "cached local database" if source == 'cache' else "URLhaus live database"
        score = 100
        text = f"Confirmed active threat in {source_label} ({threat_type})"
        reasons.append(text)
        reason_details.append({'reason': text, 'points': 100})

    # --- Domain-age check (WHOIS) ---
    domain_age_days, is_new_domain = check_domain_age(url)
    if is_new_domain:
        add(20, f"Domain registered recently ({domain_age_days} days ago) — common phishing pattern")

    # --- Heuristic rule-based checks (each contributes its own weight) ---
    if features['has_ip']:
        add(35, "Uses IP address instead of domain name")
    if features['has_at_symbol']:
        add(25, "Contains @ symbol — tricks browsers")
    if features['has_double_slash']:
        add(20, "Contains double slash redirect")
    if features['has_suspicious_words']:
        add(25, "Contains suspicious keywords (login, verify, banking, etc.)")
    if features['has_dash']:
        add(10, "Contains dash in domain — common in fake sites")
    if features['num_dots'] > 3:
        add(15, "Too many dots — likely a subdomain attack")
    if features['url_length'] > 75:
        add(15, "URL is unusually long")
    if not features['has_https']:
        add(20, "No HTTPS — connection is not secure")
    if features['num_subdomains'] > 2:
        add(15, "Too many subdomains")

    score = min(score, 100)

    if score >= 70:
        verdict = "PHISHING"
    elif score >= 40:
        verdict = "SUSPICIOUS"
    else:
        verdict = "SAFE"

    return {
        'score': score,
        'verdict': verdict,
        'reasons': reasons,                # flat text list (unchanged interface)
        'reason_details': reason_details,  # NEW: weighted breakdown for explainability
        'features': features,
        'domain_age_days': domain_age_days,
        'threat_intel_source': source
    }


def predict_url(url):
    result = calculate_risk_score(url)
    is_phishing = 1 if result['verdict'] == 'PHISHING' else 0
    probability_phishing = result['score'] / 100
    probability_safe = 1 - probability_phishing
    return is_phishing, [probability_safe, probability_phishing]


# Initialize the local cache database on import
init_cache_db()

with open('phishing_model.pkl', 'wb') as f:
    pickle.dump({'type': 'rule_based_plus_urlhaus_whois_cached', 'version': '1.3'}, f)

print("Phishing Detector model ready! (heuristics + URLhaus + WHOIS domain-age + local cache)")
print("Testing with sample URLs:")
print()

test_urls = [
    "https://www.google.com",
    "http://192.168.1.1/login/verify",
    "http://paypal-secure-login.xyz/account/confirm"
]

for url in test_urls:
    result = calculate_risk_score(url)
    print(f"URL: {url}")
    print(f"Risk Score: {result['score']}% — {result['verdict']} (threat intel: {result['threat_intel_source']}, domain age: {result['domain_age_days']} days)")
    if result['reason_details']:
        print("Reasons (weighted):")
        for r in result['reason_details']:
            print(f"  +{r['points']} — {r['reason']}")
    print()