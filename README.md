# HeaderShield 🛡️

A smart Python CLI tool to audit HTTP & HTTPS protocols, detecting active, missing, and deprecated Request & Response security headers with compliance scoring.

## Features
- Audits 21+ HTTP/HTTPS security headers (e.g., HSTS, CSP, X-Frame-Options, CORS).
- Identifies missing and ignored security header configurations during execution.
- Highlights potential security risks and suggests possible attack vectors (e.g., XSS, Clickjacking, MIME-sniffing, MITM).
- Handles HTTP/HTTPS fallbacks automatically.
- Analyzes both Request and Response header configurations.
- Calculates overall security posture scores and compliance grades.
- Flexible input support: test security headers using either a full URL (`https://example.com`) or a plain domain (`example.com`).

## Installation

```bash
git clone https://github.com/Radhika-0135/HeaderShield.git
cd HeaderShield
pip install -r requirements.txt

## 𝗨𝘀𝗮𝗴𝗲

```bash
# Scan using a domain name
python3 Sheader_scanner.py example.com

# Scan using a full URL
python3 Sheader_scanner.py [https://example.com]
