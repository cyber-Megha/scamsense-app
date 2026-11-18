import os, re, math, socket, ssl, requests, base64, dns.resolver
from concurrent.futures import ThreadPoolExecutor
from bs4 import BeautifulSoup
from urllib.parse import urlparse, unquote

VT_API_KEY = (os.getenv("VIRUSTOTAL_API_KEY") or "").strip()
GSB_API_KEY = (os.getenv("GEMINI_API_KEY") or "").strip()

def calc_entropy(s: str) -> float:
    if not s: return 0.0
    freq = {c: s.count(c) for c in set(s)}
    return round(-sum((n / len(s)) * math.log2(n / len(s)) for n in freq.values()), 2)

def fetch_live_page(target: str, root_dom: str):
    info = {"title": "", "text": "", "has_password_or_file_upload": False, "external_forms": []}
    try:
        hdrs = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/126.0.0.0 Safari/537.36"}
        r = requests.get(target, headers=hdrs, timeout=4, allow_redirects=True)
        if "text/html" in r.headers.get("Content-Type", "").lower():
            soup = BeautifulSoup(r.text[:60000], "html.parser")
            if soup.title and soup.title.string: info["title"] = soup.title.string.strip()[:90]
            for t in soup(["script", "style", "noscript"]): t.decompose()
            info["text"] = re.sub(r"\s+", " ", soup.get_text(" ")).strip()[:1400]
            info["has_password_or_file_upload"] = bool(soup.find("input", {"type": re.compile("password|file", re.I)}))
            info["external_forms"] = [f.get("action") for f in soup.find_all("form") if (f.get("action") or "").startswith("http") and root_dom not in f.get("action", "")][:2]
        return r.url, r.status_code, info
    except Exception:
        return target, None, info

def check_gsb(urls: list):
    if not GSB_API_KEY: return {"is_dangerous": False}
    try:
        pl = {"client": {"clientId": "scamsense", "clientVersion": "8.0"}, "threatInfo": {"threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"], "platformTypes": ["ANY_PLATFORM"], "threatEntryTypes": ["URL"], "threatEntries": [{"url": u} for u in set(urls)]}}
        r = requests.post(f"https://googleapis.com{GSB_API_KEY}", json=pl, timeout=3)
        if r.status_code == 200 and r.json().get("matches"):
            return {"is_dangerous": True, "threat_type": r.json()["matches"][0].get("threatType", "MALICIOUS")}
    except Exception: pass
    return {"is_dangerous": False}

def check_vt(final_u: str):
    if not VT_API_KEY: return {"malicious": 0}
    try:
        uid = base64.urlsafe_b64encode(final_u.encode()).decode().strip("=")
        r = requests.get("https://virustotal.com" + uid, headers={"x-apikey": VT_API_KEY}, timeout=3)
        if r.status_code == 200:
            st = r.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            return {"malicious": st.get("malicious", 0), "suspicious": st.get("suspicious", 0)}
    except Exception: pass
    return {"malicious": 0}

def check_urlhaus(final_u: str):
    try:
        r = requests.post("https://abuse.ch", data={"url": final_u}, timeout=3)
        if r.status_code == 200 and r.json().get("query_status") == "ok":
            return {"listed": True, "threat": r.json().get("threat")}
    except Exception: pass
    return {"listed": False}

def check_email_domain_dns(sender: str):
    if not sender or "@" not in sender: return {"status": "no_sender"}
    dom = sender.split("@")[-1].strip().lower()
    rep = {"sender_domain": dom, "has_mx": False, "has_spf": False}
    try: rep["has_mx"] = len(dns.resolver.resolve(dom, "MX", lifetime=3)) > 0
    except Exception: pass
    try: rep["has_spf"] = any("v=spf1" in str(r).lower() for r in dns.resolver.resolve(dom, "TXT", lifetime=3))
    except Exception: pass
    return rep

def check_virustotal_url(url: str):
    decoded = unquote(url.strip())
    target = decoded if decoded.startswith(("http://", "https://")) else "http://" + decoded
    parsed = urlparse(target)
    domain = parsed.netloc.split("@")[-1].lower().split(":")[0]
    parts = [p for p in domain.split(".") if p]
    root_dom = f"{parts[-2]}.{parts[-1]}" if len(parts) >= 2 else domain

    final_u, status, page_info = fetch_live_page(target, root_dom)

    with ThreadPoolExecutor(max_workers=3) as ex:
        f_gsb = ex.submit(check_gsb, [target, final_u])
        f_vt = ex.submit(check_vt, final_u)
        f_uh = ex.submit(check_urlhaus, final_u)
        gsb_res, vt_res, uh_res = f_gsb.result(), f_vt.result(), f_uh.result()

    forensics = {
        "protocol": parsed.scheme.upper(), "domain": domain, "root_domain": root_dom,
        "entropy": calc_entropy(url), "has_at_trap": "@" in parsed.netloc,
        "final_url": final_u, "http_status": status, "live_page": page_info
    }
    return {"deep_url_forensics": forensics, "google_safe_browsing": gsb_res, "urlhaus_threat_feed": uh_res, "virustotal": vt_res}
