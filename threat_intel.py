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
    domain = parsed.netloc.partition(":")[0].lower()
    parts = domain.split(".")
    root_domain = f"{parts[-2]}.{parts[-1]}" if len(parts) >= 2 else domain

    forensics = {
        "original_url": raw_url,
        "normalized_url": target,
        "domain": domain,
        "subdomain_count": max(0, len(parts) - 2),
        "has_punycode": "xn--" in domain,
        "uses_ip": bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", domain)),
        "is_shortener": any(s in domain for s in ["bit.ly", "tinyurl.com", "t.co", "rb.gy", "is.gd", "cutt.ly", "shorturl.at", "ow.ly"]),
        "redirect_chain": [],
        "final_destination": target,
        "domain_created_date": "Unknown",
        "domain_age_days": None,
        "ssl_issuer": "Unknown",
        "dns_resolved": False
    }

    try:
        ip = socket.gethostbyname(domain)
        forensics["dns_resolved"] = True
        forensics["resolved_ip"] = ip
    except Exception:
        forensics["dns_resolved"] = False

    try:
        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) ScamSense-ForensicBot/3.0"}
        resp = requests.get(target, headers=headers, timeout=6, allow_redirects=True)
        forensics["redirect_chain"] = [r.url for r in resp.history] + [resp.url]
        forensics["final_destination"] = resp.url
        forensics["http_status"] = resp.status_code
    except Exception as e:
        forensics["connection_note"] = f"Probe blocked or unreachable: {str(e)[:70]}"

    try:
        rdap_res = requests.get(f"https://rdap.org{root_domain}", timeout=4)
        if rdap_res.status_code == 200:
            for ev in rdap_res.json().get("events", []):
                if ev.get("eventAction") == "registration":
                    reg_str = ev.get("eventDate", "")[:10]
                    forensics["domain_created_date"] = reg_str
                    reg_dt = datetime.strptime(reg_str, "%Y-%m-%d")
                    forensics["domain_age_days"] = (datetime.utcnow() - reg_dt).days
                    break
    except Exception:
        pass

    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=4) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                issuer_dict = {}
                for item in cert.get("issuer", ()):
                    for k, v in item:
                        issuer_dict[k] = v
                forensics["ssl_issuer"] = issuer_dict.get("organizationName", "Verified TLS")
    except Exception:
        forensics["ssl_issuer"] = "No Valid HTTPS/SSL Certificate"

    return forensics

def check_google_safe_browsing(url: str):
    if not GSB_API_KEY:
        return {"status": "skipped", "is_dangerous": False}
    try:
        endpoint = f"https://googleapis.com{GSB_API_KEY}"
        payload = {
            "client": {"clientId": "scamsense-app", "clientVersion": "3.0"},
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
            matches = data.get("matches", [])
            first_match = next(iter(matches), None)
            if first_match:
                return {
                    "is_dangerous": True,
                    "threat_type": first_match.get("threatType", "MALICIOUS"),
                    "source": "Google Safe Browsing"
                }
            return {"is_dangerous": False, "source": "Google Safe Browsing"}
        return {"status": "gsb_error", "is_dangerous": False}
    except Exception as e:
        return {"status": "gsb_exception", "error": str(e), "is_dangerous": False}

def check_virustotal_url(url: str):
    forensic_data = inspect_url_forensics(url)
    final_url = forensic_data.get("final_destination", url)
    gsb_result = check_google_safe_browsing(final_url)
    vt_result = {"status": "skipped", "malicious": 0}

    if VT_API_KEY:
        try:
            url_id = base64.urlsafe_b64encode(final_url.encode()).decode().strip("=")
            headers = {"x-apikey": VT_API_KEY}
            api_endpoint = "https://virustotal.com" + url_id
            response = requests.get(api_endpoint, headers=headers, timeout=6)
            if response.status_code == 200:
                stats = response.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                vt_result = {
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "harmless": stats.get("harmless", 0)
                }
        except Exception as e:
            vt_result = {"status": "vt_error", "error": str(e), "malicious": 0}

    return {
        "deep_url_forensics": forensic_data,
        "google_safe_browsing": gsb_result,
        "virustotal": vt_result
    }
