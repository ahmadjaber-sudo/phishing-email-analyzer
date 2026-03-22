import re

KEYWORDS = [
    'urgent', 'verify', 'click here', 'sensitive', 'account', 'compromised', 
    'limited time offer', 'verify your identity', 'we need your help', 
    'click to claim', 'suspicious activity'
]

def detect_keywords(email_body):
    flagged_keywords = []
    for keyword in KEYWORDS:
        if re.search(r'\b' + re.escape(keyword) + r'\b', email_body, re.IGNORECASE):
            flagged_keywords.append(keyword)
    return flagged_keywords
