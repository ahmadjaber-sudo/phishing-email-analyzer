# Phishing Email Analyzer

## Overview
Developed a phishing detection tool that analyzes email files to identify suspicious behavior based on headers, URLs, and content patterns.

## Features
- Email header analysis (From, Reply-To mismatch)
- URL extraction and suspicious link detection
- Keyword-based phishing detection
- Phishing scoring system
- Live URL status checking
- Simple GUI for file selection and analysis

## Detection Capabilities
- Mismatch between sender and reply address
- Suspicious or public email domains
- Malicious or deceptive URLs
- Phishing-related keywords (e.g., "verify", "urgent", "account")
- URL anomalies (IP-based links, shorteners, fake domains)

## Technologies Used
- Python
- Tkinter (GUI)
- Requests (HTTP checks)
- Regex (pattern matching)

## Example Output
- Phishing Score: 8  
- ⚠️ This email is highly suspicious and likely phishing  

## Purpose
This project simulates how security analysts detect phishing attempts by analyzing email structure, links, and content patterns.

## Future Improvements
- Machine learning-based detection
- Integration with email servers
- Real-time analysis
