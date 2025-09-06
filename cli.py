#!/usr/bin/env python3
import argparse
import base64
import json
import os
import random
import sys
import time
from datetime import datetime, timedelta
from urllib.parse import urlparse

import requests
import tldextract
import whois
from colorama import Fore, Style, init
from pyfiglet import Figlet

init(autoreset=True)

SAFE_FONTS = ["slant", "block", "standard", "doom"]

def banner():
    f = Figlet(font=random.choice(SAFE_FONTS))
    art = f.renderText("DPhish")
    for ch in art:
        sys.stdout.write(Fore.GREEN + ch + Style.RESET_ALL)
        sys.stdout.flush()
        time.sleep(0.008)
    print()

def vt_check(url: str, api_key: str):
    """VirusTotal v3: submit then fetch report using base64-url id."""
    if not api_key:
        return {"error": "No VT API key provided"}
    headers = {"x-apikey": api_key}
    try:
        # 1) Submit
        sub = requests.post("https://www.virustotal.com/api/v3/urls",
                            headers=headers, data={"url": url}, timeout=20)
        # 2) Encode URL -> id
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        rep = requests.get(f"https://www.virustotal.com/api/v3/urls/{url_id}",
                           headers=headers, timeout=20)
        if rep.status_code != 200:
            return {"error": f"VT status {rep.status_code}", "text": rep.text}
        return rep.json()
    except Exception as e:
        return {"error": str(e)}

def whois_info(domain: str):
    try:
        w = whois.whois(domain)
        return {
            "registrar": getattr(w, "registrar", None),
            "creation_date": str(w.creation_date),
            "expiration_date": str(w.expiration_date),
        }
    except Exception as e:
        return {"error": str(e)}

def analyze_url_structure(url: str):
    parsed = urlparse(url)
    issues = []
    if parsed.scheme not in ("http", "https"):
        issues.append("⚠ Unusual scheme")
    if len(url) > 90:
        issues.append("⚠ Very long URL")
    if "-" in parsed.netloc:
        issues.append("⚠ Hyphen in domain")
    if parsed.query and any(k in parsed.query.lower() for k in ["login", "verify", "update"]):
        issues.append("⚠ Suspicious keywords in query")
    return issues or ["✓ No basic structural issues found"]

def quick_traffic_signal(domain: str):
    """Free placeholder: mark a few well-known as HIGH, others UNKNOWN."""
    popular = {"google.com", "youtube.com", "facebook.com", "twitter.com", "wikipedia.org", "amazon.com"}
    return "HIGH TRAFFIC" if domain.lower() in popular else "UNKNOWN"

def verdict(vt_json, whois_dict, url_issues, traffic_sig):
    # New domain check (WHOIS creation < 90 days)
    try:
        cd = whois_dict.get("creation_date")
        # python-whois sometimes gives list/str
        if isinstance(cd, list): cd = cd[0]
        if isinstance(cd, str) and cd != "None":
            try:
                # try a few common date formats
                for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d", "%a %b %d %H:%M:%S %Z %Y"):
                    try: dt = datetime.strptime(cd[:len(fmt)], fmt); break
                    except: continue
            except: dt = None
        elif hasattr(cd, "year"):
            dt = cd
        else:
            dt = None
        if dt and dt > datetime.now() - timedelta(days=90):
            return "❓ UNKNOWN (Newly registered domain)"
    except Exception:
        pass

    # VT stats
    if isinstance(vt_json, dict) and "data" in vt_json:
        stats = vt_json["data"]["attributes"].get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        if malicious > 0:
            return "❌ UNSAFE (Malicious detections present)"
        if suspicious > 0:
            return "⚠ Medium risk (Suspicious flags)"
    else:
        # No VT -> we stay cautious
        return "❓ UNKNOWN (No VirusTotal data)"

    # Traffic fallback
    if traffic_sig == "UNKNOWN":
        return "❓ UNKNOWN (No traffic signal)"

    # URL issues
    risky = any(x.startswith("⚠") for x in url_issues)
    if risky:
        return "⚠ Medium risk (Structural warnings)"
    return "✅ SAFE (No issues found)"

def pretty_print_vt(vt_json):
    if not isinstance(vt_json, dict) or "data" not in vt_json:
        print("  Could not fetch VirusTotal report"); return
    stats = vt_json["data"]["attributes"].get("last_analysis_stats", {})
    print(f"  Malicious: {stats.get('malicious',0)} | Suspicious: {stats.get('suspicious',0)} | "
          f"Harmless: {stats.get('harmless',0)} | Undetected: {stats.get('undetected',0)}")

def analyze(url: str, do_vt: bool, do_whois: bool, do_traffic: bool, api_key: str):
    out = {"url": url}
    extracted = tldextract.extract(url)
    domain = f"{extracted.domain}.{extracted.suffix}" if extracted.suffix else urlparse(url).netloc
    out["domain"] = domain

    print(Fore.CYAN + f"[+] Analyzing: {url}" + Style.RESET_ALL)
    print(f"Domain: {domain}")

    vt_json = None
    if do_vt:
        print(Fore.YELLOW + "\n[+] VirusTotal:" + Style.RESET_ALL)
        vt_json = vt_check(url, api_key)
        out["virustotal_raw"] = vt_json
        if "error" in (vt_json or {}):
            print(Fore.RED + f"  Error: {vt_json['error']}")
            if "text" in vt_json: print(vt_json["text"])
        else:
            pretty_print_vt(vt_json)

    who = None
    if do_whois:
        print(Fore.YELLOW + "\n[+] WHOIS:" + Style.RESET_ALL)
        who = whois_info(domain)
        out["whois"] = who
        if "error" in who:
            print(f"  Error: {who['error']}")
        else:
            print(f"  Registrar: {who.get('registrar')}")
            print(f"  Creation:  {who.get('creation_date')}")
            print(f"  Expiry:    {who.get('expiration_date')}")

    traffic_sig = None
    if do_traffic:
        print(Fore.YELLOW + "\n[+] Traffic:" + Style.RESET_ALL)
        traffic_sig = quick_traffic_signal(domain)
        out["traffic"] = traffic_sig
        print(f"  Signal: {traffic_sig}")

    print(Fore.YELLOW + "\n[+] URL Structure:" + Style.RESET_ALL)
    issues = analyze_url_structure(url)
    out["url_issues"] = issues
    for i in issues: print(f"  {i}")

    print(Fore.CYAN + "\n[+] Final Verdict:" + Style.RESET_ALL)
    final = verdict(vt_json or {}, who or {}, issues, traffic_sig or "UNKNOWN")
    out["verdict"] = final
    print(Fore.MAGENTA + f"  {final}" + Style.RESET_ALL)

    return out

def main():
    banner()
    parser = argparse.ArgumentParser(
        prog="dphish",
        description="DPhish — Phishing URL analyzer (VT + WHOIS + Structure + Traffic-signal)"
    )
    parser.add_argument("-u", "--url", required=True, help="Target URL")
    parser.add_argument("-a", "--all", action="store_true", help="Run all checks")
    parser.add_argument("-v", "--virustotal", action="store_true", help="VirusTotal check")
    parser.add_argument("-w", "--whois", action="store_true", help="WHOIS check")
    parser.add_argument("-t", "--traffic", action="store_true", help="Traffic signal (coarse)")
    parser.add_argument("--json", action="store_true", help="Print JSON output")
    parser.add_argument("--save", help="Save output to file (txt/json)")
    parser.add_argument("--vt-key", help="VirusTotal API key (or set env VT_API_KEY)")
    args = parser.parse_args()

    do_vt = args.all or args.virustotal
    do_whois = args.all or args.whois
    do_traffic = args.all or args.traffic
    vt_api_key = args.vt_key or os.environ.get("VT_API_KEY", "")

    result = analyze(args.url, do_vt, do_whois, do_traffic, vt_api_key)

    if args.json:
        print(json.dumps(result, indent=2))
    if args.save:
        with open(args.save, "w", encoding="utf-8") as f:
            if args.json or args.save.lower().endswith(".json"):
                json.dump(result, f, indent=2)
            else:
                f.write(json.dumps(result, indent=2))
        print(Fore.GREEN + f"\n[+] Saved -> {args.save}" + Style.RESET_ALL)

if __name__ == "__main__":
    main()
