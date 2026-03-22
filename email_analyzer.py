from email import message_from_string
from email.parser import Parser
import re

SUSPICIOUS_DOMAINS = ['gmail.com', 'yahoo.com', 'hotmail.com']  # You can expand this

def analyze_headers(raw_email):
    headers = Parser().parsestr(raw_email)

    analysis = {}

    from_header = headers.get('From', '')
    reply_to = headers.get('Reply-To', '')
    received = headers.get_all('Received', [])

    analysis['From'] = from_header
    analysis['Reply-To'] = reply_to
    analysis['Received'] = received

    # Check if Reply-To is different from From
    if reply_to and reply_to != from_header:
        analysis['reply_mismatch'] = True
    else:
        analysis['reply_mismatch'] = False

    # Check for suspicious domains
    domain_match = re.search(r'@([A-Za-z0-9.-]+)', from_header)
    if domain_match:
        domain = domain_match.group(1)
        analysis['suspicious_domain'] = domain in SUSPICIOUS_DOMAINS
        analysis['domain'] = domain
    else:
        analysis['suspicious_domain'] = False
        analysis['domain'] = None

    return analysis
