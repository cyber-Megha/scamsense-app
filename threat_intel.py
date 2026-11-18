import os
import re
import socket
import ssl
import requests
import base64
from urllib.parse import urlparse, unquote
from datetime import datetime

VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
GSB_API_KEY = os.getenv("GEMINI_API_KEY")

def inspect_url_forensics(raw_url: str):
    try:
        decoded_url = unquote(raw_url.strip())
        target = decoded_url if decoded_url.startswith(("http://", "https://")) else "http://" + decoded_url
        parsed = urlparse(target)

        # ১. '@' সিম্বল ট্র্যাপ ডিটেকশন (যেমন: https://phishing.com)
        has_at_symbol_trap = "@" in parsed.netloc
        true_netloc = parsed.netloc.split("@")[-1].lower()
        domain = true_netloc.split(":")[0]

        full_path = (parsed.path + "?" + parsed.query).lower()
        parts = [p for p in domain.split(".") if p]
        root_domain = f"{parts[-2]}.{parts[-1]}" if len(parts) >= 2 else domain

        # ২. পাথের ভেতরে লুকানো ফেক ডোমেইন ও হেক্স হ্যাশ ডিটেকশন
        embedded_domains = re.findall(r'[a-z0-9-]+\.(?:com|net|org|in|co|io|gov|bank|sbi|uk|it|de|ru|xyz|top)\b', full_path)
        spoofed_paths = [d for d in embedded_domains if d != root_domain and d != domain]
        has_hex = bool(re.search(r'/[a-f0-9]{16,}/', full_path))
        sus_paths = [p for p in ["cgi-bin", "verification", "verify", "login", "signin", "webscr", "update", "secure", "account", "banking", "confirm", "wallet", "kyc"] if p in full_path]

        # ৩. লাইভ HTTP রিডাইরেক্ট চেইন ট্রেসিং
        final_url = target
        redirect_hops = []
        http_status = None
        try:
            headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) ScamSense-Forensic/4.0"}
            resp = requests.get(target, headers=headers, timeout=5, allow_redirects=True)
            redirect_hops = [r.url for r in resp.history] + [resp.url]
            final_url = resp.url
            http_status = resp.status_code
        except Exception:
            pass

        # ৪. লাইভ ডোমেইন বয়স (RDAP Domain Age) যাচাই
        domain_age_days = None
        created_date = "Unknown"
        try:
            rdap = requests.get(f"https://rdap.org{root_domain}", timeout=4)
            if rdap.status_code == 200:
                for ev in rdap.json().get("events", []):
                    if ev.get("eventAction") == "registration":
                        created_date = ev.get("eventDate", "")[:10]
                        reg_dt = datetime.strptime(created_date, "%Y-%m-%d")
                        domain_age_days = (datetime.utcnow() - reg_dt).days
                        break
        except Exception:
            pass

        # ৫. লাইভ SSL/TLS সার্টিফিকেট যাচাই
        ssl_status = "No Valid HTTPS/SSL"
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=4) as sock:
                with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    issuer_info = {}
                    for item in cert.get("issuer", ()):
                        for k, v in item:
                            issuer_info[k] = v
                    ssl_status = f"Valid ({issuer_info.get('organizationName', 'Trusted CA')})"
        except Exception:
            ssl_status = "Missing or Invalid SSL Certificate"

        return {
            "protocol": parsed.scheme.upper(),
            "domain": domain,
            "root_domain": root_domain,
            "subdomain_depth": max(0, len(parts) - 2),
            "url_length": len(raw_url),
            "has_at_symbol_trap": has_at_symbol_trap,
            "has_punycode": "xn--" in domain,
            "uses_raw_ip": bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", domain)),
            "spoofed_domains_in_path": spoofed_paths,
            "has_random_hex_folder": has_hex,
            "suspicious_path_keywords": sus_paths,
            "redirect_hops": redirect_hops,
            "final_destination": final_url,
            "http_status": http_status,
            "domain_created_date": created_date,
            "domain_age_days": domain_age_days,
            "ssl_status": ssl_status
        }
    except Exception:
        return {
            "protocol": "UNKNOWN",
            "domain": raw_url,
            "root_domain": raw_url,
            "subdomain_depth": 0,
            "url_length": len(raw_url),
            "has_at_symbol_trap": "@" in raw_url,
            "has_punycode": False,
            "uses_raw_ip": False,
            "spoofed_domains_in_path": [],
            "has_random_hex_folder": False,
            "suspicious_path_keywords": [],
            "redirect_hops": [],
            "final_destination": raw_url,
            "domain_created_date": "Unknown",
            "domain_age_days": None,
            "ssl_status": "Unverified"
        }

def check_google_safe_browsing(url: str):
    if not GSB_API_KEY:
        return {"is_dangerous": False}
    try:
        endpoint = f"https://googleapis.com{GSB_API_KEY}"
        payload = {
            "client": {"clientId": "scamsense-app", "clientVersion": "4.0"},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
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
    final_url = forensics.get("final_destination", url)
    
    # শুরু এবং শেষ—দুটো লিংকই Google Safe Browsing দিয়ে চেক হবে
    gsb_initial = check_google_safe_browsing(url)
    gsb_final = check_google_safe_browsing(final_url) if final_url != url else gsb_initial
    is_gsb_bad = gsb_initial.get("is_dangerous") or gsb_final.get("is_dangerous")
    threat_type = gsb_final.get("threat_type") or gsb_initial.get("threat_type")

    vt = {"malicious": 0, "suspicious": 0}
    if VT_API_KEY:
        try:
            url_id = base64.urlsafe_b64encode(final_url.encode()).decode().strip("=")
            res = requests.get("https://virustotal.com" + url_id, headers={"x-apikey": VT_API_KEY}, timeout=5)
            if res.status_code == 200:
                stats = res.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                vt["malicious"] = stats.get("malicious", 0)
                vt["suspicious"] = stats.get("suspicious", 0)
        except Exception:
            pass

    return {
        "deep_url_forensics": forensics,
        "google_safe_browsing": {"is_dangerous": is_gsb_bad, "threat_type": threat_type},
        "virustotal": vt
    }
