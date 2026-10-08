import sys
import urllib3
import requests
from colorama import Fore, Style, init

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
init(autoreset=True)

# Total 12 Response Security Headers (10 Active + 2 Deprecated)
RESPONSE_SECURITY_HEADERS = {
    "Content-Security-Policy": {"risk": "High (Susceptible to XSS and Data Injection)"},
    "Strict-Transport-Security": {"risk": "High (Susceptible to MITM and SSL Strip)"},
    "X-Frame-Options": {"risk": "Medium (Susceptible to Clickjacking)"},
    "X-Content-Type-Options": {"risk": "Low/Medium (MIME-Sniffing vulnerabilities)"},
    "Referrer-Policy": {"risk": "Low (Sensitive URL info exposure)"},
    "Permissions-Policy": {"risk": "Low (Unauthorized Browser APIs/Feature Access)"},
    "Cross-Origin-Embedder-Policy": {"risk": "Low/Medium (Cross-origin data exposure)"},
    "Cross-Origin-Opener-Policy": {"risk": "Low/Medium (XS-Leaks and Spectre attacks)"},
    "Cross-Origin-Resource-Policy": {"risk": "Low (Cross-origin data leaks)"},
    "Clear-Site-Data": {"risk": "Info (Not enforcing data clearance on logout)"},
}

DEPRECATED_HEADERS = ["X-XSS-Protection", "Expect-CT"]

# Total 9 Request Security Headers (Informational tracking)
REQUEST_HEADERS_INFO = [
    "Sec-Fetch-Site", "Sec-Fetch-Mode", "Sec-Fetch-Dest", "Sec-Fetch-User",
    "Origin", "Referer", "Sec-CH-UA", "Sec-CH-UA-Mobile", "Sec-CH-UA-Platform"
]

def scan_security_headers(target_domain: str):
    domain = target_domain.replace("https://", "").replace("http://", "").strip("/")
    
    print(f"\n{Style.BRIGHT}{'=' * 70}")
    print(f"{Fore.CYAN}[*] Target Domain: {Style.BRIGHT}{domain}")
    print(f"{Style.BRIGHT}{'=' * 70}\n")

    # Request headers simulating modern browser client hints & metadata
    headers_req = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-User": "?1",
        "Sec-CH-UA": '"Not_A Brand";v="8", "Chromium";v="120"',
        "Sec-CH-UA-Mobile": "?0",
        "Sec-CH-UA-Platform": '"Windows"'
    }

    response = None
    protocols = [f"https://{domain}", f"http://{domain}"]
    
    for url in protocols:
        try:
            print(f"{Fore.YELLOW}[*] Trying connection to {url} ...")
            response = requests.get(url, headers=headers_req, timeout=12, verify=False, allow_redirects=True)
            print(f"{Fore.GREEN}[+] Connected successfully to {response.url}\n")
            break
        except requests.exceptions.Timeout:
            print(f"{Fore.RED}[!] Timeout on {url}")
        except requests.exceptions.RequestException:
            print(f"{Fore.RED}[!] Could not connect to {url}")

    if not response:
        print(f"\n{Fore.RED}[X] Error: Target website is unreachable or timed out.")
        return

    response_headers = {k.lower(): v for k, v in response.headers.items()}
    found_count = 0
    total_headers = len(RESPONSE_SECURITY_HEADERS)

    # 1. Active Response Headers Check
    print(f"{Style.BRIGHT}[+] Present Response Security Headers:\n" + "-" * 70)
    for header in RESPONSE_SECURITY_HEADERS:
        header_lower = header.lower()
        if header_lower in response_headers:
            found_count += 1
            val = response_headers[header_lower]
            display_val = val if len(val) <= 50 else val[:47] + "..."
            print(f"{Fore.GREEN}[✓] {header:<32} : {display_val}")

    print(f"\n{Style.BRIGHT}[-] Missing Response Security Headers:\n" + "-" * 70)
    for header, info in RESPONSE_SECURITY_HEADERS.items():
        if header.lower() not in response_headers:
            print(f"{Fore.RED}[✗] {header:<32} -> Risk: {info['risk']}")

    # 2. Deprecated Headers Check
    print(f"\n{Style.BRIGHT}[!] Deprecated Response Headers Check:\n" + "-" * 70)
    dep_found = False
    for dep in DEPRECATED_HEADERS:
        if dep.lower() in response_headers:
            dep_found = True
            print(f"{Fore.YELLOW}[!] {dep:<32} : Present (Deprecated - consider removing)")
    if not dep_found:
        print(f"{Fore.LIGHTBLACK_EX}No deprecated headers detected.")

    # 3. Request Headers Overview
    print(f"\n{Style.BRIGHT}[i] Simulated Client Request Headers (Sent during scan):\n" + "-" * 70)
    for req_h in REQUEST_HEADERS_INFO:
        print(f"{Fore.CYAN}[i] {req_h:<32} : Configured in Scanner")

    # Score Calculation
    score = int((found_count / total_headers) * 100)
    print(f"\n{Style.BRIGHT}{'=' * 70}")
    print(f"Compliance Score : {found_count}/{total_headers} ({score}%)")
    if score >= 80:
        print(f"Overall Grade    : {Fore.GREEN}A (Secure)")
    elif score >= 50:
        print(f"Overall Grade    : {Fore.YELLOW}B/C (Moderate Risk)")
    else:
        print(f"Overall Grade    : {Fore.RED}F (High Vulnerability)")
    print(f"{Style.BRIGHT}{'=' * 70}\n")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        target = sys.argv[1]
    else:
        target = input("Enter target website (e.g. www.google.com): ").strip()

    if target:
        scan_security_headers(target)
