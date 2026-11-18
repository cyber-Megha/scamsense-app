import os, re, math, socket, ssl, requests, base64, dns.resolver
from bs4 import BeautifulSoup
from urllib.parse import urlparse, unquote

VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
GSB_API_KEY = os.getenv("GEMINI_API_KEY")

def calc_entropy(s: str) -> float:
    if not s: return 0.0
    freq = {c: s.count(c) for c in set(s)}
    return round(-sum((n / len(s)) * math.log2(n / len(s)) for n in freq.values()), 2)

def inspect_url_forensics(raw_url: str):
    try:
        decoded = unquote(raw_url.strip())
        target = decoded if decoded.startswith(("http://", "https://")) else "http://" + decoded
        parsed = urlparse(target)
        has_at = "@" in parsed.netloc
        domain = parsed.netloc.split("@")[-1].lower().partition(":")
        parts = [p for p in domain.split(".") if p]
        root_dom = f"{parts[-2]}.{parts[-1]}" if len(parts) >= 2 else domain

        final_url, status_code = target, None
        page_intel = {
            "page_title": "", "meta_description": "", "visible_text_sample": "",
            "asks_password_or_pin": False, "external_form_targets": [], "external_links_sample": []
        }

        try:
            hdrs = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/125.0.0.0 Safari/537.36"}
            resp = requests.get(target, headers=hdrs, timeout=6, allow_redirects=True)
            final_url, status_code = resp.url, resp.status_code
            if "text/html" in resp.headers.get("Content-Type", "").lower():
                soup = BeautifulSoup(resp.text[:100000], "html.parser")
                if soup.title and soup.title.string:
                    page_intel["page_title"] = soup.title.string.strip()[:100]
                meta = soup.find("meta", attrs={"name": re.compile("description", re.I)})
                if meta and meta.get("content"):
                    page_intel["meta_description"] = meta["content"].strip()[:200]
                for tag in soup(["script", "style", "noscript"]):
                    tag.decompose()
                clean_text = re.sub(r"\s+", " ", soup.get_text(" ")).strip()
                page_intel["visible_text_sample"] = clean_text[:1800]
                page_intel["asks_password_or_pin"] = bool(soup.find("input", {"type": "password"}))
                page_intel["external_form_targets"] = [f.get("action") for f in soup.find_all("form") if (f.get("action") or "").startswith("http") and root_dom not in f.get("action", "")][:3]
                ext_links = [a.get("href") for a in soup.find_all("a", href=True) if a["href"].startswith("http") and root_dom not in a["href"]]
                page_intel["external_links_sample"] = list(dict.fromkeys(ext_links))[:5]
        except Exception as e:
            page_intel["fetch_note"] = f"Page unreachable or blocked automated access ({status_code or 'Timeout'})"

        ssl_stat = "No Valid SSL"
        try:
            with socket.create_connection((domain, 443), timeout=3) as sock:
                with ssl.create_default_context().wrap_socket(sock, server_hostname=domain) as ssock:
                    issuer = {k: v for item in ssock.getpeercert().get("issuer", ()) for k, v in item}
                    ssl_stat = f"Valid ({issuer.get('organizationName', 'Trusted CA')})"
        except Exception: pass

        return {
            "protocol": parsed.scheme.upper(), "domain": domain, "root_domain": root_dom,
            "path": parsed.path, "shannon_entropy": calc_entropy(raw_url),
            "has_at_symbol_trap": has_at, "final_destination": final_url,
            "http_status": status_code, "ssl_status": ssl_stat, "live_page_content": page_intel
        }
    except Exception:
        return {"protocol": "UNKNOWN", "domain": raw_url, "root_domain": raw_url, "final_destination": raw_url, "ssl_status": "Unverified", "live_page_content": {}}

def check_email_domain_dns(sender: str):
    if not sender or "@" not in sender: return {"status": "no_sender"}
    dom = sender.split("@")[-1].strip().lower()
    rep = {"sender_domain": dom, "has_mx_records": False, "has_spf_record": False, "has_dmarc_record": False}
    try: rep["has_mx_records"] = len(dns.resolver.resolve(dom, "MX", lifetime=3)) > 0
    except Exception: pass
    try: rep["has_spf_record"] = any("v=spf1" in str(r).lower() for r in dns.resolver.resolve(dom, "TXT", lifetime=3))
    except Exception: pass
    try: rep["has_dmarc_record"] = any("v=dmarc1" in str(r).lower() for r in dns.resolver.resolve(f"_dmarc.{dom}", "TXT", lifetime=3))
    except Exception: pass
    return rep

def check_virustotal_url(url: str):
    f = inspect_url_forensics(url)
    final_u = f.get("final_destination", url)
    gsb_bad, threat = False, None
    if GSB_API_KEY:
        try:
            pl = {"client": {"clientId": "scamsense", "clientVersion": "7.0"}, "threatInfo": {"threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"], "platformTypes": ["ANY_PLATFORM"], "threatEntryTypes": ["URL"], "threatEntries": [{"url": url}, {"url": final_u}]}}
            r = requests.post(f"https://googleapis.com{GSB_API_KEY}", json=pl, timeout=4)
            m = next(iter(r.json().get("matches", [])), None) if r.status_code == 200 else None
            if m: gsb_bad, threat = True, m.get("threatType", "MALICIOUS")
        except Exception: pass

    uh = {"listed": False}
    try:
        ur = requests.post("https://abuse.ch", data={"url": final_u}, timeout=4)
        if ur.status_code == 200 and ur.json().get("query_status") == "ok": uh = {"listed": True, "threat": ur.json().get("threat")}
    except Exception: pass

    vt = {"malicious": 0, "suspicious": 0}
    if VT_API_KEY:
        try:
            uid = base64.urlsafe_b64encode(final_u.encode()).decode().strip("=")
            hdr = {"x-apikey": VT_API_KEY}
            vr = requests.get("https://virustotal.com" + uid, headers=hdr, timeout=4)
            if vr.status_code == 200:
                st = vr.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                vt["malicious"], vt["suspicious"] = st.get("malicious", 0), st.get("suspicious", 0)
        except Exception: pass

    return {"deep_url_forensics": f, "google_safe_browsing": {"is_dangerous": gsb_bad, "threat_type": threat}, "urlhaus_threat_feed": uh, "virustotal": vt}
