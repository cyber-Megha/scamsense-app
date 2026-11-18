import os
import re
import requests
import base64
from urllib.parse import urlparse

VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
GSB_API_KEY = os.getenv("GEMINI_API_KEY")

def inspect_url_forensics(raw_url: str):
    target = raw_url.strip()
    if not target.startswith(("http://", "https://")):
        target = "http://" + target

    parsed = urlparse(target)
    domain = parsed.netloc.partition(":").lower()
    full_path = (parsed.path + "?" + parsed.query).lower()
    parts = domain.split(".")
    root_domain = f"{parts[-2]}.{parts[-1]}" if len(parts) >= 2 else domain

    embedded_domains = re.findall(r'[a-z0-9-]+\.(?:com|net|org|in|co|io|gov|bank|sbi)\b', full_path)
    spoofed_paths = [d for d in embedded_domains if d != root_domain and d != domain]
    has_hex = bool(re.search(r'/[a-f0-9]{20,}/', full_path))
    sus_paths = [p for p in ["cgi-bin", "verification", "verify", "login", "signin", "webscr", "update", "secure", "account", "banking"] if p in full_path]

    final_url = target
    try:
        resp = requests.get(target, timeout=4, allow_redirects=True)
        final_url = resp.url
    except Exception:
        pass

    return {
        "domain": domain,
        "root_domain": root_domain,
        "url_length": len(raw_url),
        "spoofed_domains_in_path": spoofed_paths,
        "has_random_hex_folder": has_hex,
        "suspicious_path_keywords": sus_paths,
        "final_destination": final_url
    }

def check_google_safe_browsing(url: str):
    if not GSB_API_KEY:
        return {"is_dangerous": False}
    try:
        endpoint = f"https://googleapis.com{GSB_API_KEY}"
        payload = {
            "client": {"clientId": "scamsense-app", "clientVersion": "3.0"},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}]
            }
        }
        res = requests.post(endpoint, json=payload, timeout=4)
        if res.status_code == 200:
            matches = res.json().get("matches", [])
            first_match = next(iter(matches), None)
            if first_match:
                return {"is_dangerous": True, "threat_type": first_match.get("threatType", "MALICIOUS")}
        return {"is_dangerous": False}
    except Exception:
        return {"is_dangerous": False}

def check_virustotal_url(url: str):
    forensics = inspect_url_forensics(url)
    gsb = check_google_safe_browsing(forensics["final_destination"])
    vt = {"malicious": 0}
    if VT_API_KEY:
        try:
            url_id = base64.urlsafe_b64encode(forensics["final_destination"].encode()).decode().strip("=")
            res = requests.get("https://virustotal.com" + url_id, headers={"x-apikey": VT_API_KEY}, timeout=5)
            if res.status_code == 200:
                stats = res.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                vt["malicious"] = stats.get("malicious", 0)
        except Exception:
            pass
    return {"deep_url_forensics": forensics, "google_safe_browsing": gsb, "virustotal": vt}
