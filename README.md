# DPhish

CLI phishing URL analyzer (VirusTotal + WHOIS + structure + traffic signal).

## Install
```bash
pip install dphish-analyzer



#using api key from virus total
#dphish -u https://example.com -a
#dphish -u https://example.com -v --vt_key YOUR_KEY
#dphish -u https://example.com -w -t --json --save result.json
