import os
import re
import math
import socket
import ssl
import requests
import base64
import dns.resolver
from bs4 import BeautifulSoup
from urllib.parse import urlparse, unquote
from datetime import datetime

VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
GSB_API_KEY = os.getenv("GEMINI_API_KEY")

def calculate_shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    freq = {}
    for ch in text:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(text)
    return round(-sum((c / length) * math.log2(c / length) for c in freq.values()), 2)

def inspect_url_forensics(raw_url: str):
    try:
        decoded_url = unquote(raw_url.strip())
        target = decoded_url if decoded_url.startswith(("http://", "https://")) else "http://" + decoded_url
        parsed = urlparse(target)

        has_at_trap = "@" in parsed.netloc
        true_netloc = parsed.netloc.split("@")[-1].lower()
        domain = true_netloc.partition(":")[0]

        full_path = (parsed.path + "?" + parsed.query).lower()
        parts = [p for p in domain.split(".") if p]
        root_domain = f"{parts[-2]}.{parts[-1]}" if len(parts) >= 2 else domain

        embedded_domains = re.findall(r'[a-z0-9-]+\.(?:com|net|org|in|co|io|gov|bank|sbi|uk|it|de|ru|xyz|top)\b', full_path)
        spoofed_paths = [d for d in embedded_domains if d != root_domain and d != domain]
        has_hex = bool(re.search(r'/[a-f0-9]{16,}/', full_path))
        sus_paths = [p for p in ["cgi-bin", "verification", "verify", "login", "signin", "webscr", "update", "secure", "account", "banking", "confirm", "wallet", "kyc"] if p in full_path]

        final_url = target
        redirect_hops = []
        dom_forensics = {"has_password_form": False, "external_form_action": False, "hidden_iframes": 0}

        try:
            headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) ScamSense-Sandbox/5.0"}
            resp = requests.get(target, headers=headers, timeout=6, allow_redirects=True)
            redirect_hops = [r.url for r in resp.history] + [resp.url]
            final_url = resp.url

            if "text/html" in resp.headers.get("Content-Type", "").lower():
                soup = BeautifulSoup(resp.text[:80000], "html.parser")
                if soup.find("input", {"type": "password"}):
                    dom_forensics["has_password_form"] = True
                for form in soup.find_all("form"):
                    action = (form.get("action") or "").lower()
                    if action.startswith("http") and root_domain not in action:
                        dom_forensics["external_form_action"] = True
                for iframe in soup.find_all("iframe"):
                    style = (iframe.get("style") or "").lower()
                    if "display:none" in style or "visibility:hidden" in style or iframe.get("width") == "0":
                        dom_forensics["hidden_iframes"] += 1
        except Exception:
            pass

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

        ssl_status = "Missing or Invalid SSL"
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=4) as sock:
                with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    issuer_info = {k: v for item in cert.get("issuer", ()) for k, v in item}
                    ssl_status = f"Valid ({issuer_info.get('organizationName', 'Trusted CA')})"
        except Exception:
            ssl_status = "No Valid HTTPS/SSL Certificate"

        return {
            "protocol": parsed.scheme.upper(),
            "domain": domain,
            "root_domain": root_domain,
            "subdomain_depth": max(0, len(parts) - 2),
            "url_length": len(raw_url),
            "shannon_entropy": calculate_shannon_entropy(raw_url),
            "has_at_symbol_trap": has_at_trap,
            "has_punycode": "xn--" in domain,
            "uses_raw_ip": bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", domain)),
            "spoofed_domains_in_path": spoofed_paths,
            "has_random_hex_folder": has_hex,
            "suspicious_path_keywords": sus_paths,
            "redirect_hops": redirect_hops,
            "final_destination": final_url,
            "domain_created_date": created_date,
            "domain_age_days": domain_age_days,
            "ssl_status": ssl_status,
            "active_dom_inspection": dom_forensics
        }
    except Exception:
        return {"protocol": "UNKNOWN", "domain": raw_url, "root_domain": raw_url, "url_length": len(raw_url), "shannon_entropy": 0.0, "has_at_symbol_trap": "@" in raw_url, "spoofed_domains_in_path": [], "has_random_hex_folder": False, "suspicious_path_keywords": [], "final_destination": raw_url, "domain_age_days": None, "ssl_status": "Unverified", "active_dom_inspection": {}}

def check_email_domain_dns(sender_email: str):
    if not sender_email or "@" not in sender_email:
        return {"status": "no_sender_provided"}
    domain = sender_email.split("@")[-1].strip().lower()
    report = {"sender_domain": domain, "has_mx_records": False, "has_spf_record": False, "has_dmarc_record": False}
    try:
        if len(dns.resolver.resolve(domain, "MX", lifetime=4)) > 0:
            report["has_mx_records"] = True
    except Exception:
        pass
    try:
        for r in dns.resolver.resolve(domain, "TXT", lifetime=4):
            if "v=spf1" in str(r).lower():
                report["has_spf_record"] = True
                break
    except Exception:
        pass
    try:
        for r in dns.resolver.resolve(f"_dmarc.{domain}", "TXT", lifetime=4):
            if "v=dmarc1" in str(r).lower():
                report["has_dmarc_record"] = True
                break
    except Exception:
        pass
    return report

def check_urlhaus_feed(url: str):
    try:
        res = requests.post("https://abuse.ch", data={"url": url}, timeout=4)
        if res.status_code == 200 and res.json().get("query_status") == "ok":
            return {"listed": True, "threat": res.json().get("threat", "Malware/Phishing")}
    except Exception:
        pass
    return {"listed": False}

def check_google_safe_browsing(url: str):
    if not GSB_API_KEY:
        return {"is_dangerous": False}
    try:
        endpoint = f"https://googleapis.com{GSB_API_KEY}"
        payload = {
            "client": {"clientId": "scamsense-app", "clientVersion": "5.0"},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}]
            }
        }
        res = requests.post(endpoint, json=payload, timeout=4)
        if res.status_code == 200:
            first_match = next(iter(res.json().get("matches", [])), None)
            if first_match:
                return {"is_dangerous": True, "threat_type": first_match.get("threatType", "MALICIOUS")}
    except Exception:
        pass
    return {"is_dangerous": False}

def check_virustotal_url(url: str):
    forensics = inspect_url_forensics(url)
    final_url = forensics.get("final_destination", url)
    gsb_init = check_google_safe_browsing(url)
    gsb_final = check_google_safe_browsing(final_url) if final_url != url else gsb_init
    is_gsb_bad = gsb_init.get("is_dangerous") or gsb_final.get("is_dangerous")
    threat_type = gsb_final.get("threat_type") or gsb_init.get("threat_type")

    urlhaus = check_urlhaus_feed(final_url)
    vt = {"malicious": 0, "suspicious": 0, "total_engines": 70}
    if VT_API_KEY:
        try:
            url_id = base64.urlsafe_b64encode(final_url.encode()).decode().strip("=")
            headers = {"x-apikey": VT_API_KEY}
            res = requests.get("https://virustotal.com" + url_id, headers=headers, timeout=5)
            if res.status_code == 200:
                stats = res.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                vt["malicious"] = stats.get("malicious", 0)
                vt["suspicious"] = stats.get("suspicious", 0)
            elif res.status_code == 404:
                requests.post("https://virustotal.com", headers=headers, data={"url": final_url}, timeout=4)
        except Exception:
            pass

    return {
        "deep_url_forensics": forensics,
        "google_safe_browsing": {"is_dangerous": is_gsb_bad, "threat_type": threat_type},
        "urlhaus_threat_feed": urlhaus,
        "virustotal": vt
    }
