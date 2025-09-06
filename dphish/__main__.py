#!/usr/bin/env python3
import argparse
import requests
import whois
import random
from pyfiglet import Figlet
from colorama import Fore, Style, init
from urllib.parse import urlparse
import base64

# Initialize Colorama
init(autoreset=True)

VT_URL = "https://www.virustotal.com/api/v3/urls"

# Animated Banner
def animated_banner():
    styles = ["slant", "block", "banner", "larry3d", "3-d"]
    f = Figlet(font=random.choice(styles))
    print(Fore.GREEN + f.renderText("DPhish"))

# VirusTotal URL Check
def virustotal_check(url, api_key):
    try:
        if not api_key:
            return {"error": "No API key provided. Use --vt_key <API_KEY>"}

        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        headers = {"x-apikey": api_key}
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

# Fake Traffic Info
def get_traffic_info(domain):
    popular_sites = ["google.com", "youtube.com", "facebook.com", "twitter.com"]
    return "HIGH TRAFFIC" if domain in popular_sites else "UNKNOWN DOMAIN"

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
    parser.add_argument("-v", "--vt", action="store_true", help="Run only VirusTotal analysis")
    parser.add_argument("--vt_key", help="Your VirusTotal API Key")
    args = parser.parse_args()

    url = args.url
    domain = urlparse(url).netloc

    animated_banner()
    print(Fore.CYAN + f"[+] Analyzing: {url}")
    print("Domain:", domain)

    vt_result = {}

    # VirusTotal (if -v or -a is used)
    if args.vt or args.all:
        print(Fore.YELLOW + "\n[+] VirusTotal Check:" + Style.RESET_ALL)
        vt_result = virustotal_check(url, args.vt_key)
        if "error" in vt_result:
            print(Fore.RED + f"[!] VirusTotal Error: {vt_result['error']}")
        else:
            stats = vt_result["data"]["attributes"]["last_analysis_stats"]
            print("Malicious:", stats.get("malicious", 0))
            print("Suspicious:", stats.get("suspicious", 0))
            print("Undetected:", stats.get("undetected", 0))

    # If only -v was given, exit after VT check
    if args.vt and not args.all:
        return

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
