#!/usr/bin/env python3
import argparse
import requests
import whois
import time
import random
from pyfiglet import Figlet
from colorama import Fore, Style, init
from urllib.parse import urlparse

# Initialize Colorama
init(autoreset=True)

# ------------------- CONFIG -------------------
VIRUSTOTAL_API_KEY = "d28fe5015cb0b34fb9b644721c3fac7f6b5254cf5ca86fb052c2792332b461f2"
VT_URL = "https://www.virustotal.com/api/v3/urls"
# ----------------------------------------------

# Animated Banner
def animated_banner():
    styles = ["slant", "block", "banner", "larry3d", "3-d"]
    f = Figlet(font=random.choice(styles))
    print(Fore.GREEN + f.renderText("DPhish"))

# VirusTotal URL Check
import base64

def virustotal_check(url):
    try:
        # Encode URL in base64 (VT v3 requirement)
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")

        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        analysis = requests.get(f"{VT_URL}/{url_id}", headers=headers)

        if analysis.status_code != 200:
            return {"error": f"Status {analysis.status_code}", "text": analysis.text}

        return analysis.json()
    except Exception as e:
        return {"error": str(e)}


# WHOIS Lookup
def whois_lookup(domain):
    try:
        info = whois.whois(domain)
        return info
    except Exception as e:
        return {"error": str(e)}

# Fake Traffic Info (since Alexa API is dead, simulate logic)
def get_traffic_info(domain):
    try:
        # Placeholder simulation
        popular_sites = ["google.com", "youtube.com", "facebook.com", "twitter.com"]
        if domain in popular_sites:
            return "HIGH TRAFFIC"
        else:
            return "UNKNOWN DOMAIN"
    except Exception as e:
        return f"Error fetching traffic: {e}"

# URL Structure Analysis
def analyze_url_structure(url):
    parsed = urlparse(url)
    issues = []
    if not parsed.scheme.startswith("http"):
        issues.append("No HTTP/HTTPS scheme")
    if len(parsed.netloc) < 4:
        issues.append("Suspiciously short domain")
    return issues if issues else ["No basic structural issues found"]

# Verdict Function
def verdict(vt_result, traffic_info):
    if isinstance(vt_result, dict) and "data" in vt_result:
        stats = vt_result["data"]["attributes"]["last_analysis_stats"]
        malicious = stats.get("malicious", 0)
        if malicious > 0:
            return "UNSAFE 🚨 (Malicious detections found)"
        elif stats.get("undetected", 0) > 0:
            return "LIKELY SAFE ✅ (No malicious detections)"
    if traffic_info == "UNKNOWN DOMAIN":
        return "UNKNOWN ⚠️ (No traffic info, might be new domain)"
    return "SAFE ✅ (No issues found)"

# Main
def main():
    parser = argparse.ArgumentParser(description="DPhish - Phishing URL Analyzer")
    parser.add_argument("-u", "--url", required=True, help="URL to analyze")
    parser.add_argument("-a", "--all", action="store_true", help="Run full analysis")
    args = parser.parse_args()

    url = args.url
    domain = urlparse(url).netloc

    animated_banner()
    print(Fore.CYAN + f"[+] Analyzing: {url}")
    print("Domain:", domain)

    # VirusTotal
    if args.all:
        print(Fore.YELLOW + "\n[+] VirusTotal Check:" + Style.RESET_ALL)
        vt_result = virustotal_check(url)
        if "error" in vt_result:
            print(Fore.RED + f"[!] VirusTotal Error: {vt_result['error']}")
        else:
            stats = vt_result["data"]["attributes"]["last_analysis_stats"]
            print("Malicious:", stats.get("malicious", 0))
            print("Suspicious:", stats.get("suspicious", 0))
            print("Undetected:", stats.get("undetected", 0))
    else:
        vt_result = {}

    # WHOIS Info
    print(Fore.YELLOW + "\n[+] WHOIS Info:" + Style.RESET_ALL)
    whois_info = whois_lookup(domain)
    if "error" in whois_info:
        print(Fore.RED + f"[!] WHOIS Error: {whois_info['error']}")
    else:
        print("Registrar:", whois_info.get("registrar"))
        print("Creation Date:", whois_info.get("creation_date"))
        print("Expiration Date:", whois_info.get("expiration_date"))

    # Traffic Info
    print(Fore.YELLOW + "\n[+] Traffic Info:" + Style.RESET_ALL)
    traffic_info = get_traffic_info(domain)
    print("Estimated Traffic:", traffic_info)

    # URL Structure
    print(Fore.YELLOW + "\n[+] URL Structure Analysis:" + Style.RESET_ALL)
    issues = analyze_url_structure(url)
    for issue in issues:
        print("✔", issue)

    # Final Verdict
    print(Fore.CYAN + "\n[+] Final Verdict:" + Style.RESET_ALL)
    result = verdict(vt_result, traffic_info)
    print(Fore.YELLOW + f"[*] Verdict: {result}" + Style.RESET_ALL)

if __name__ == "__main__":
    main()
