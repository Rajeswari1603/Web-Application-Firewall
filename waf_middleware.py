import re
import os
import smtplib
import json
import time
from flask import abort, request
from email.message import EmailMessage
from ml_predictor import predict_payload
from datetime import datetime
from collections import defaultdict

rules = []

# === Whitelist for domains or substrings ===
WHITELIST_DOMAINS = ["youtube.com", "google.com", "wikipedia.org", "openai.com"]

# === Load rules from rules.json ===
def load_rules():
    global rules
    try:
        with open("rules.json", "r") as f:
            rule_patterns = json.load(f)
            rules = [re.compile(r, re.IGNORECASE) for r in rule_patterns]
            print(f"[✓] Loaded {len(rules)} WAF rules.")
    except Exception as e:
        print(f"[X] Failed to load WAF rules: {e}")
        rules = []

# === Rate Limiting ===
rate_limit_store = defaultdict(list)
RATE_LIMIT = 10
RATE_WINDOW = 60

def check_rate_limit(req):
    ip = req.remote_addr
    endpoint = req.path
    key = f"{ip}:{endpoint}"
    now = time.time()
    timestamps = rate_limit_store[key]
    rate_limit_store[key] = [ts for ts in timestamps if now - ts < RATE_WINDOW]

    if len(rate_limit_store[key]) >= RATE_LIMIT:
        reason = "Blocked due to Rate Limiting"
        log_blocked_request(req, f"Endpoint={endpoint}", reason)
        send_alert_email(req, f"Endpoint={endpoint}", reason)
        abort(403, description=reason)

    rate_limit_store[key].append(now)

# === Main WAF Function ===
def waf_check(req):
    check_rate_limit(req)
    inputs = list(req.args.values()) + list(req.form.values())

    for param in inputs:
        # Rule-based Detection
        for rule in rules:
            if rule.search(str(param)):
                reason = f"Blocked by Rule: Pattern '{rule.pattern}' matched."
                log_blocked_request(req, param, reason)
                send_alert_email(req, param, reason)
                abort(403, description=reason)

        # Skip ML check if whitelisted
        if any(domain in str(param) for domain in WHITELIST_DOMAINS):
            continue

        # ML-based Detection
        if predict_payload(str(param)) == 1:
            reason = "Blocked by ML Model"
            log_blocked_request(req, param, reason)
            send_alert_email(req, param, reason)
            abort(403, description=reason)

# === Logger ===
def log_blocked_request(req, payload, reason):
    os.makedirs("logs", exist_ok=True)
    timestamp = datetime.now().isoformat()
    with open("logs/waf.log", "a") as f:
        f.write(f"[BLOCKED] Time={timestamp}, IP={req.remote_addr}, Payload={payload}, Reason={reason}\n")

# === Email Alert ===
EMAIL_FROM = "12chinnu.89@gmail.com"
EMAIL_TO = "12chinnu.89@gmail.com"
EMAIL_SUBJECT = "🚨 WAF Alert: Suspicious Request Blocked"
EMAIL_PASSWORD = "eujw xwfa cehs vtaw"
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587

def send_alert_email(req, payload, reason):
    try:
        msg = EmailMessage()
        msg.set_content(f"""
Blocked Suspicious Request

IP Address: {req.remote_addr}
Payload: {payload}
Reason: {reason}
""")
        msg["Subject"] = EMAIL_SUBJECT
        msg["From"] = EMAIL_FROM
        msg["To"] = EMAIL_TO

        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(EMAIL_FROM, EMAIL_PASSWORD)
            server.send_message(msg)

        print("[✓] Email alert sent.")
    except Exception as e:
        print(f"[X] Email sending failed: {e}")
