import os, re, math, socket, ssl, requests, base64, dns.resolver
from bs4 import BeautifulSoup
from urllib.parse import urlparse, unquote
from datetime import datetime

VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
GSB_API_KEY = os.getenv("GEMINI_API_KEY")

def calc_entropy(s: str) -> float:
    if not s: return 0.0
    freq = {c: s.count(c) for c in set(s)}
    return round(-sum((n / len(s)) * math.log2(n / len(s)) for n in freq.values()), 2)

def check_crtsh_age(domain: str):
    try:
        r = requests.get(f"https://crt.sh{domain}&output=json", timeout=5)
        if r.status_code == 200 and isinstance(r.json(), list):
            ts = next(iter(r.json()), {}).get("entry_timestamp", "")[:10]
            if ts: return (datetime.utcnow() - datetime.strptime(ts, "%Y-%m-%d")).days
    except Exception: pass
    return None

def inspect_url_forensics(raw_url: str):
    try:
        decoded = unquote(raw_url.strip())
        target = decoded if decoded.startswith(("http://", "https://")) else "http://" + decoded
        parsed = urlparse(target)
        has_at = "@" in parsed.netloc
        domain = parsed.netloc.split("@")[-1].lower().partition(":")[0]
        full_path = (parsed.path + "?" + parsed.query).lower()
        parts = [p for p in domain.split(".") if p]
        root_dom = f"{parts[-2]}.{parts[-1]}" if len(parts) >= 2 else domain

        emb = re.findall(r'[a-z0-9-]+\.(?:com|net|org|in|co|io|gov|bank|sbi|uk|it|de|ru|xyz|top)\b', full_path)
        spoofed = [d for d in emb if d not in (root_dom, domain)]
        has_hex = bool(re.search(r'/[a-f0-9]{16,}/', full_path))
        sus_kw = [p for p in ["cgi-bin", "verification", "verify", "login", "signin", "webscr", "update", "secure", "account", "banking", "confirm", "kyc"] if p in full_path]

        final_url, cloaking, dom_info = target, False, {"has_password_form": False, "external_form_action": False, "hidden_iframes": 0}
        try:
            hdrs = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/124.0.0.0 Safari/537.36", "Accept-Language": "en-US,en;q=0.9"}
            resp = requests.get(target, headers=hdrs, timeout=6, allow_redirects=True)
            final_url = resp.url
            if resp.status_code in (403, 406, 503) or len(resp.text.strip()) < 250: cloaking = True
            if "text/html" in resp.headers.get("Content-Type", "").lower():
                soup = BeautifulSoup(resp.text[:80000], "html.parser")
                dom_info["has_password_form"] = bool(soup.find("input", {"type": "password"}))
                dom_info["external_form_action"] = any((f.get("action") or "").lower().startswith("http") and root_dom not in (f.get("action") or "").lower() for f in soup.find_all("form"))
                dom_info["hidden_iframes"] = sum(1 for i in soup.find_all("iframe") if "none" in (i.get("style") or "").lower() or i.get("width") == "0")
        except Exception: cloaking = True

        ssl_stat = "Missing or Invalid SSL"
        try:
            with socket.create_connection((domain, 443), timeout=4) as sock:
                with ssl.create_default_context().wrap_socket(sock, server_hostname=domain) as ssock:
                    issuer = {k: v for item in ssock.getpeercert().get("issuer", ()) for k, v in item}
                    ssl_stat = f"Valid ({issuer.get('organizationName', 'Trusted CA')})"
        except Exception: pass

        return {
            "protocol": parsed.scheme.upper(), "domain": domain, "root_domain": root_dom, "url_length": len(raw_url),
            "shannon_entropy": calc_entropy(raw_url), "has_at_symbol_trap": has_at, "spoofed_domains_in_path": spoofed,
            "has_random_hex_folder": has_hex, "suspicious_path_keywords": sus_kw, "final_destination": final_url,
            "cloaking_or_bot_block": cloaking, "domain_age_days": check_crtsh_age(domain), "ssl_status": ssl_stat, "active_dom_inspection": dom_info
        }
    except Exception:
        return {"protocol": "UNKNOWN", "domain": raw_url, "root_domain": raw_url, "shannon_entropy": 0.0, "has_at_symbol_trap": "@" in raw_url, "spoofed_domains_in_path": [], "has_random_hex_folder": False, "suspicious_path_keywords": [], "final_destination": raw_url, "cloaking_or_bot_block": True, "domain_age_days": None, "ssl_status": "Unverified", "active_dom_inspection": {}}

def check_email_domain_dns(sender: str):
    if not sender or "@" not in sender: return {"status": "no_sender"}
    dom = sender.split("@")[-1].strip().lower()
    rep = {"sender_domain": dom, "has_mx_records": False, "has_spf_record": False, "has_dmarc_record": False}
    try: rep["has_mx_records"] = len(dns.resolver.resolve(dom, "MX", lifetime=4)) > 0
    except Exception: pass
    try: rep["has_spf_record"] = any("v=spf1" in str(r).lower() for r in dns.resolver.resolve(dom, "TXT", lifetime=4))
    except Exception: pass
    try: rep["has_dmarc_record"] = any("v=dmarc1" in str(r).lower() for r in dns.resolver.resolve(f"_dmarc.{dom}", "TXT", lifetime=4))
    except Exception: pass
    return rep

def check_virustotal_url(url: str):
    f = inspect_url_forensics(url)
    final_u = f.get("final_destination", url)
    gsb_bad, threat = False, None
    if GSB_API_KEY:
        try:
            pl = {"client": {"clientId": "scamsense", "clientVersion": "5.0"}, "threatInfo": {"threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"], "platformTypes": ["ANY_PLATFORM"], "threatEntryTypes": ["URL"], "threatEntries": [{"url": url}, {"url": final_u}]}}
            r = requests.post(f"https://googleapis.com{GSB_API_KEY}", json=pl, timeout=4)
            m = next(iter(r.json().get("matches", [])), None) if r.status_code == 200 else None
            if m: gsb_bad, threat = True, m.get("threatType", "MALICIOUS")
        except Exception: pass

    uh = {"listed": False}
    try:
        ur = requests.post("https://abuse.ch", data={"url": final_u}, timeout=4)
        if ur.status_code == 200 and ur.json().get("query_status") == "ok": uh = {"listed": True, "threat": ur.json().get("threat")}
    except Exception: pass

    vt = {"malicious": 0, "suspicious": 0, "total_engines": 70}
    if VT_API_KEY:
        try:
            uid = base64.urlsafe_b64encode(final_u.encode()).decode().strip("=")
            hdr = {"x-apikey": VT_API_KEY}
            vr = requests.get("https://virustotal.com" + uid, headers=hdr, timeout=5)
            if vr.status_code == 200:
                st = vr.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                vt["malicious"], vt["suspicious"] = st.get("malicious", 0), st.get("suspicious", 0)
            elif vr.status_code == 404:
                requests.post("https://virustotal.com", headers=hdr, data={"url": final_u}, timeout=4)
        except Exception: pass

    return {"deep_url_forensics": f, "google_safe_browsing": {"is_dangerous": gsb_bad, "threat_type": threat}, "urlhaus_threat_feed": uh, "virustotal": vt}
