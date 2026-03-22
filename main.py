# main.py

import re
import requests
from bs4 import BeautifulSoup
from email import policy
from email.parser import BytesParser

def extract_urls_from_text(text):
    url_regex = r'(https?://[^\s]+)'
    return re.findall(url_regex, text)

def is_suspicious_url(url):
    # Very basic check — you can expand with more logic
    return any(keyword in url for keyword in ['login', 'verify', 'update', 'secure'])

def analyze_email(file_path):
    phishing_score = 0
    suspicious_keywords = ['verify', 'account', 'login', 'password', 'urgent', 'click here', 'suspicious activity']

    result = []

    with open(file_path, 'rb') as f:
        msg = BytesParser(policy=policy.default).parse(f)

    # === Header Analysis ===
    result.append("=== Email Header Analysis ===")
    from_ = msg['From']
    reply_to = msg['Reply-To']
    received = msg.get_all('Received', [])

    result.append(f"From: {from_}")
    result.append(f"Reply-To: {reply_to}")
    result.append(f"Received: {received}")

    reply_mismatch = reply_to and reply_to not in from_
    domain = from_.split('@')[-1] if '@' in from_ else "unknown"
    suspicious_domain = domain.lower() in ['gmail.com', 'yahoo.com', 'hotmail.com']  # adjust for your case

    if reply_mismatch:
        result.append("⚠️ Reply-To address does not match sender!")
        phishing_score += 2
    if suspicious_domain:
        result.append("⚠️ Sender domain is public or suspicious.")
        phishing_score += 1

    result.append(f"reply_mismatch: {reply_mismatch}")
    result.append(f"suspicious_domain: {suspicious_domain}")
    result.append(f"domain: {domain}\n")

    # === URL Analysis ===
    result.append("=== URL Analysis ===")
    body = ""
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == 'text/plain':
                body += part.get_content()
    else:
        body = msg.get_content()

    urls = extract_urls_from_text(body)
    suspicious_urls = [url for url in urls if is_suspicious_url(url)]
    result.append(f"Found URLs: {urls}")
    result.append(f"Suspicious URLs: {suspicious_urls}")

    phishing_score += 3 * len(suspicious_urls)

    # === Live URL Check ===
    result.append("\n=== Live URL Status ===")
    for url in urls:
        try:
            r = requests.get(url, timeout=5)
            result.append(f"URL: {url} - Status: {r.status_code}")
        except Exception as e:
            result.append(f"URL: {url} - Status: Error: {e}")

    # === Keyword Analysis ===
    result.append("\n=== Keyword Analysis ===")
    found_keywords = [kw for kw in suspicious_keywords if kw.lower() in body.lower()]
    result.append(f"Suspicious Keywords Found: {found_keywords}")
    phishing_score += len(found_keywords)

    # === Phishing Score ===
    result.append("\n=== Phishing Score ===")
    result.append(f"Phishing Score: {phishing_score}")
    if phishing_score >= 6:
        result.append("⚠️ This email is highly suspicious and likely phishing!")
    elif phishing_score >= 3:
        result.append("⚠️ This email has signs of phishing.")
    else:
        result.append("✅ This email looks safe.")

    return "\n".join(result)
