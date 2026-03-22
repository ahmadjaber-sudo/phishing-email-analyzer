import re
import requests

# Patterns to match suspicious URLs
SUSPICIOUS_PATTERNS = [
    r"https?://(?:\d{1,3}\.){3}\d{1,3}",       # IP address URLs
    r"https?://[^\s]*\.(ru|cn|tk|ml)",         # Suspicious TLDs
    r"https?://(bit\.ly|tinyurl\.com|t\.co)",  # URL shorteners
    r"http://",                                # Non-HTTPS
    r"https?://.*g00gle\.com",                 # Misspelled brand domains
]

def extract_urls(email_body):
    """Extract all URLs from the email body"""
    url_regex = r'https?://[^\s]+'
    return re.findall(url_regex, email_body)

def check_suspicious_urls(urls):
    """Check URLs against suspicious patterns"""
    flagged = []
    for url in urls:
        for pattern in SUSPICIOUS_PATTERNS:
            if re.search(pattern, url):
                flagged.append(url)
                break
    return flagged

def check_url_status(url):
    """Check the status of a URL to see if it's reachable and valid"""
    try:
        response = requests.get(url, timeout=5)
        
        # Check for suspicious status codes
        if response.status_code == 404:
            return "Not Found (404)"
        elif response.status_code == 500:
            return "Server Error (500)"
        elif response.status_code != 200:
            return f"Suspicious Status Code: {response.status_code}"
        else:
            return "URL is alive and working"
    except requests.exceptions.RequestException as e:
        return f"Error: {e}"

