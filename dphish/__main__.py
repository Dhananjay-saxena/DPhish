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
        # Submit (harmless if VT already knows the URL)
        requests.post("https://www.virustotal.com/api/v3/urls",
                      headers=headers, data={"url": url}, timeout=20)
        # Encode URL -> id
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
            "creation_date": getattr(w, "creation_date", None),
            "expiration_date": getattr(w, "expiration_date", None),
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
    # return empty list when clean
    return issues


def quick_traffic_signal(domain: str):
    """Placeholder traffic signal; NOT used in verdict unless you explicitly want it."""
    popular = {"google.com", "youtube.com", "facebook.com", "twitter.com", "wikipedia.org", "amazon.com"}
    return "HIGH TRAFFIC" if domain.lower() in popular else "UNKNOWN"


def parse_whois_date(cd):
    """Normalize whois creation_date into a datetime or None."""
    if not cd:
        return None
    try:
        if isinstance(cd, list) and cd:
            cd = cd[0]
        if hasattr(cd, "year"):
            return cd
        if isinstance(cd, str):
            for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d", "%d-%b-%Y", "%a %b %d %H:%M:%S %Z %Y"):
                try:
                    return datetime.strptime(cd[:len(fmt)], fmt)
                except Exception:
                    continue
    except Exception:
        return None
    return None


def decide_from_whois_and_url(whois_dict, url_issues, recent_days=90):
    """Decision helper when VT is not available or when VT is clean but we still require
       WHOIS+URL to be OK before declaring SAFE.
    """
    # URL structure warnings -> not safe
    if any(x.startswith("⚠") for x in url_issues):
        return ("❌ NOT SAFE to visit (Structural issues detected in URL)", "url_structural")

    # WHOIS errors -> not safe
    if not isinstance(whois_dict, dict) or "error" in whois_dict:
        err = whois_dict.get("error") if isinstance(whois_dict, dict) else "WHOIS lookup failed"
        return (f"❌ NOT SAFE to visit (WHOIS lookup problem: {err})", "whois_error")

    # Check creation date
    cd_raw = whois_dict.get("creation_date")
    cd = parse_whois_date(cd_raw)
    if cd:
        try:
            if cd > datetime.now() - timedelta(days=recent_days):
                return ("❌ NOT SAFE to visit (Newly registered domain)", "whois_new")
        except Exception:
            # parsing error -> conservative choice
            return ("❌ NOT SAFE to visit (WHOIS creation date parse error)", "whois_parse_error")
    else:
        # missing creation date considered suspicious
        return ("❌ NOT SAFE to visit (WHOIS missing creation date)", "whois_no_creation_date")

    # Passed both WHOIS and URL structure checks
    return ("✅ NOT MALICIOUS — Safe to visit", "safe")


def make_verdict(vt_json, url_issues, whois_dict):
    """Combined logic:
       - If VT has data: any malicious/suspicious -> NOT SAFE.
         If VT clean -> still require WHOIS+URL to be clean to return SAFE.
       - If VT missing/error -> decide based on WHOIS+URL (fallback).
    """
    # If VT returned a proper report
    if isinstance(vt_json, dict) and "data" in vt_json:
        stats = vt_json["data"]["attributes"].get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)

        if malicious > 0:
            return ("❌ NOT SAFE to visit (VirusTotal: malicious detections present)", "vt_malicious")
        if suspicious > 0:
            return ("❌ NOT SAFE to visit (VirusTotal: suspicious detections present)", "vt_suspicious")

        # VT says clean -> still require WHOIS + URL to be OK
        return decide_from_whois_and_url(whois_dict, url_issues)

    # VT missing or returned an error -> fallback to WHOIS + URL
    if isinstance(vt_json, dict) and "error" in vt_json:
        # print-able reason will be shown by caller; here we fallback
        return decide_from_whois_and_url(whois_dict, url_issues)

    # Any other case (no VT data) -> fallback
    return decide_from_whois_and_url(whois_dict, url_issues)


def pretty_print_vt(vt_json):
    if not isinstance(vt_json, dict) or "data" not in vt_json:
        print("  Could not fetch VirusTotal report")
        return
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

    # 1) VirusTotal (first check if requested)
    vt_json = None
    if do_vt:
        print(Fore.YELLOW + "\n[+] VirusTotal:" + Style.RESET_ALL)
        vt_json = vt_check(url, api_key)
        out["virustotal_raw"] = vt_json
        if isinstance(vt_json, dict) and "error" in vt_json:
            print(Fore.RED + f"  Error: {vt_json['error']}")
            if "text" in vt_json:
                print(f"  {vt_json['text']}")
        else:
            pretty_print_vt(vt_json)
    else:
        vt_json = {"error": "VirusTotal check disabled"}

    # 2) URL Structure (next step)
    print(Fore.YELLOW + "\n[+] URL Structure:" + Style.RESET_ALL)
    issues = analyze_url_structure(url)
    out["url_issues"] = issues
    if not issues:
        print("  ✓ No basic structural issues found")
    else:
        for i in issues:
            print(f"  {i}")

    # 3) WHOIS (last step)
    who = {}
    if do_whois:
        print(Fore.YELLOW + "\n[+] WHOIS:" + Style.RESET_ALL)
        who = whois_info(domain)
        out["whois"] = who
        if isinstance(who, dict) and "error" in who:
            print(Fore.RED + f"  Error: {who['error']}")
        else:
            print(f"  Registrar: {who.get('registrar')}")
            print(f"  Creation:  {who.get('creation_date')}")
            print(f"  Expiry:    {who.get('expiration_date')}")
    else:
        who = {"error": "WHOIS check disabled"}

    # Traffic info (optional)
    traffic_sig = None
    if do_traffic:
        print(Fore.YELLOW + "\n[+] Traffic:" + Style.RESET_ALL)
        traffic_sig = quick_traffic_signal(domain)
        out["traffic"] = traffic_sig
        print(f"  Signal: {traffic_sig}")

    # Final verdict
    print(Fore.CYAN + "\n[+] Final Verdict:" + Style.RESET_ALL)
    final_text, final_code = make_verdict(vt_json or {}, issues, who or {})
    out["verdict"] = {"text": final_text, "code": final_code}
    print(Fore.MAGENTA + f"  {final_text}" + Style.RESET_ALL)

    return out


def main():
    banner()
    parser = argparse.ArgumentParser(
        prog="dphish",
        description="DPhish — Phishing URL analyzer (VT + WHOIS + Structure). VT missing -> fallback to WHOIS+URL."
    )
    parser.add_argument("-u", "--url", required=True, help="Target URL")
    parser.add_argument("-a", "--all", action="store_true", help="Run all checks")
    parser.add_argument("-v", "--virustotal", action="store_true", help="VirusTotal check")
    parser.add_argument("-w", "--whois", action="store_true", help="WHOIS check")
    parser.add_argument("-t", "--traffic", action="store_true", help="Traffic signal (coarse) -- NOT used in verdict by default")
    parser.add_argument("--json", action="store_true", help="Print JSON output")
    parser.add_argument("--save", help="Save output to file (txt/json)")
    # Accept both --vt-key and --vt_key and store in args.vt_key
    parser.add_argument("--vt-key", "--vt_key", dest="vt_key", help="VirusTotal API key (or set env VT_API_KEY)")
    args = parser.parse_args()

    do_vt = args.all or args.virustotal
    do_whois = args.all or args.whois
    do_traffic = args.all or args.traffic
    vt_api_key = args.vt_key or os.environ.get("VT_API_KEY", "")

    result = analyze(args.url, do_vt, do_whois, do_traffic, vt_api_key)

    if args.json:
        print(json.dumps(result, indent=2, default=str))
    if args.save:
        with open(args.save, "w", encoding="utf-8") as f:
            if args.json or args.save.lower().endswith(".json"):
                json.dump(result, f, indent=2, default=str)
            else:
                f.write(json.dumps(result, indent=2, default=str))
        print(Fore.GREEN + f"\n[+] Saved -> {args.save}" + Style.RESET_ALL)


if __name__ == "__main__":
    main()
