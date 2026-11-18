import os
import re
import socket
import ssl
import requests
import base64
from urllib.parse import urlparse
from datetime import datetime

VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
GSB_API_KEY = os.getenv("GEMINI_API_KEY")

def inspect_url_forensics(raw_url: str):
    target = raw_url.strip()
    if not target.startswith(("http://", "https://")):
        target = "https://" + target

    parsed = urlparse(target)
    domain = parsed.netloc.split(":")[0].lower()
    forensics = {
        "original_url": raw_url,
        "normalized_url": target,
        "domain": domain,
        "subdomain_count": max(0, len(domain.split(".")) - 2),
        "has_punycode": "xn--" in domain,
        "uses_ip": bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", domain)),
        "redirect_chain": [],
        "final_destination": target,
        "domain_created_date": "Unknown",
        "domain_age_days": None,
        "ssl_issuer": "Unknown",
        "dns_resolved": False
    }

    # 1. DNS Resolution Check
    try:
        ip = socket.gethostbyname(domain)
        forensics["dns_resolved"] = True
        forensics["resolved_ip"] = ip
    except Exception:
        forensics["dns_resolved"] = False

    # 2. Live HTTP Redirect Chain Tracing (Catches hidden masked links)
    try:
        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) ScamSense-ForensicBot/2.0"}
        resp = requests.get(target, headers=headers, timeout=6, allow_redirects=True)
        forensics["redirect_chain"] = [r.url for r in resp.history] + [resp.url]
        forensics["final_destination"] = resp.url
        forensics["http_status"] = resp.status_code
    except Exception as e:
        forensics["connection_note"] = f"Unreachable or blocked probe: {str(e)[:80]}"

    # 3. RDAP Domain Age Lookup (Catches brand-new phishing domains pretending to be old banks/brands)
    try:
        parts = domain.split(".")
        root_domain = ".".join(parts[-2:]) if len(parts) >= 2 else domain
        rdap_res = requests.get(f"https://rdap.org{root_domain}", timeout=4)
        if rdap_res.status_code == 200:
            events = rdap_res.json().get("events", [])
            for ev in events:
                if ev.get("eventAction") == "registration":
                    reg_str = ev.get("eventDate", "")[:10]
                    forensics["domain_created_date"] = reg_str
                    reg_dt = datetime.strptime(reg_str, "%Y-%m-%d")
                    forensics["domain_age_days"] = (datetime.utcnow() - reg_dt).days
                    break
    except Exception:
        pass

    # 4. SSL Certificate Inspection
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=4) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                issuer = dict(x[0] for x in cert.get("issuer", []))
                forensics["ssl_issuer"] = issuer.get("organizationName", "Verified TLS")
    except Exception:
        forensics["ssl_issuer"] = "No Valid HTTPS/SSL Certificate"

    return forensics

def check_google_safe_browsing(url: str):
    if not GSB_API_KEY:
        return {"status": "skipped", "is_dangerous": False}
    try:
        endpoint = f"https://googleapis.com{GSB_API_KEY}"
        payload = {
            "client": {"clientId": "scamsense-app", "clientVersion": "2.0"},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}]
            }
        }
        res = requests.post(endpoint, json=payload, timeout=5)
        if res.status_code == 200:
            data = res.json()
            if "matches" in data and len(data["matches"]) > 0:
                return {
                    "is_dangerous": True,
                    "threat_type": data["matches"].get("threatType", "MALICIOUS"),
                    "source": "Google Safe Browsing"
                }
            return {"is_dangerous": False, "source": "Google Safe Browsing"}
        return {"status": "gsb_error", "is_dangerous": False}
    except Exception as e:
        return {"status": "gsb_exception", "error": str(e), "is_dangerous": False}

def check_virustotal_url(url: str):
    forensic_data = inspect_url_forensics(url)
    gsb_result = check_google_safe_browsing(forensic_data["final_destination"])
    vt_result = {"status": "skipped", "malicious": 0}

    if VT_API_KEY:
        try:
            target_to_check = forensic_data["final_destination"]
            url_id = base64.urlsafe_b64encode(target_to_check.encode()).decode().strip("=")
            headers = {"x-apikey": VT_API_KEY}
            api_endpoint = "https://virustotal.com" + url_id
            response = requests.get(api_endpoint, headers=headers, timeout=6)
            if response.status_code == 200:
                stats = response.json()['data']['attributes']['last_analysis_stats']
                vt_result = {
                    "malicious": stats.get('malicious', 0),
                    "suspicious": stats.get('suspicious', 0),
                    "harmless": stats.get('harmless', 0)
                }
        except Exception as e:
            vt_result = {"status": "vt_error", "error": str(e), "malicious": 0}

    return {
        "deep_url_forensics": forensic_data,
        "google_safe_browsing": gsb_result,
        "virustotal": vt_result
    }
