import os
import re
import math
import socket
import ssl
import base64
import requests
import dns.resolver
from urllib.parse import urlparse, unquote, parse_qs
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor

VT_API_KEY = (os.getenv("VIRUSTOTAL_API_KEY") or "").strip()
GSB_API_KEY = (os.getenv("SAFE_BROWSING_API_KEY") or os.getenv("GSB_API_KEY") or "").strip()

RISKY_TLDS = (".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".cfd", ".sbs", ".icu", ".click", ".link", ".work", ".zip", ".mov")
SUSPICIOUS_HOSTS = ("ngrok", "trycloudflare", "pages.dev", "workers.dev", "supabase.co", "herokuapp.com", "000webhostapp.com")
URGENCY_WORDS = (
    "urgent", "immediately", "suspended", "verify your account", "kyc", "otp",
    "password", "reset", "locked", "unauthorized", "refund", "prize", "won",
    "invoice", "legal notice", "aadhaar", "pan", "cpf", "cnpj", "ssn", "card"
)

def calc_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {c: s.count(c) for c in set(s)}
    length = len(s)
    return round(-sum((n / length) * math.log2(n / length) for n in freq.values()), 2)

def is_ip_address(host: str) -> bool:
    try:
        socket.inet_aton(host)
        return True
    except OSError:
        return False

def get_ssl_info(domain: str, port: int = 443) -> dict:
    info = {"tls_valid": False, "issuer": None, "not_after": None}
    if not domain or is_ip_address(domain):
        return info
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, port), timeout=3.5) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                info["tls_valid"] = True
                info["not_after"] = cert.get("notAfter")
                issuer_pairs = cert.get("issuer", ())
                for tup in issuer_pairs:
                    for k, v in tup:
                        if k == "organizationName":
                            info["issuer"] = v
                            break
    except Exception:
        pass
    return info

def inspect_oauth_and_params(target_url: str, host: str) -> dict:
    parsed = urlparse(target_url)
    qs = parse_qs(parsed.query)
    lower_url = target_url.lower()

    is_oauth = any(k in lower_url for k in ("/oauth2/", "/authorize", "client_id=", "response_type="))
    redirect_targets = []
    for key in ("redirect_uri", "redirect_url", "next", "url", "dest", "destination", "return_to", "continue", "r", "target"):
        for val in qs.get(key, []):
            redirect_targets.append(unquote(val))

    external_redirects = []
    for rt in redirect_targets:
        rt_host = (urlparse(rt).hostname or "").lower()
        if rt_host and host and not rt_host.endswith(host) and not host.endswith(rt_host):
            external_redirects.append(rt[:160])

    scopes_raw = " ".join(qs.get("scope", [])).lower()
    risky_scopes = [
        s for s in ("mail.read", "mail.send", "files.read", "offline_access", "user.readwrite", "contacts.read", "mailboxsettings")
        if s in scopes_raw
    ]

    return {
        "is_oauth_or_auth_flow": is_oauth,
        "has_truncated_ellipsis": "..." in target_url or "…" in target_url,
        "external_redirect_params": external_redirects,
        "risky_oauth_scopes": risky_scopes,
        "client_id_present": "client_id" in qs
    }

def fetch_live_behaviour(target: str, root_dom: str) -> dict:
    behaviour = {
        "final_url": target,
        "http_status": None,
        "redirect_count": 0,
        "redirect_chain": [],
        "cross_domain_redirect": False,
        "title": "",
        "text_snippet": "",
        "has_password_field": False,
        "has_file_upload": False,
        "external_form_actions": [],
        "suspicious_form_actions": [],
        "script_obfuscation_hits": [],
        "hidden_iframes": 0,
        "urgency_keywords_found": []
    }
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
    }
    try:
        resp = requests.get(target, headers=headers, timeout=5, allow_redirects=True)
        behaviour["http_status"] = resp.status_code
        behaviour["final_url"] = resp.url

        chain = [h.url for h in resp.history] + [resp.url]
        behaviour["redirect_chain"] = chain[:8]
        behaviour["redirect_count"] = len(resp.history)

        final_host = (urlparse(resp.url).hostname or "").lower()
        final_parts = [p for p in final_host.split(".") if p]
        final_root = f"{final_parts[-2]}.{final_parts[-1]}" if len(final_parts) >= 2 else final_host
        if root_dom and final_root and root_dom != final_root:
            behaviour["cross_domain_redirect"] = True

        content_type = resp.headers.get("Content-Type", "").lower()
        if "text/html" in content_type and resp.text:
            html_chunk = resp.text[:120000]
            soup = BeautifulSoup(html_chunk, "html.parser")

            if soup.title and soup.title.string:
                behaviour["title"] = soup.title.string.strip()[:100]

            script_blob = "\n".join((s.get_text(" ") or "") for s in soup.find_all("script"))[:40000]
            obf_patterns = [
                (r"eval\s*\(", "eval()"),
                (r"unescape\s*\(", "unescape()"),
                (r"fromCharCode", "String.fromCharCode"),
                (r"atob\s*\(", "atob() base64 decode"),
                (r"document\.write\s*\(", "document.write()"),
                (r"oncontextmenu\s*=|preventDefault\(\)", "context-menu/event block")
            ]
            for pat, label in obf_patterns:
                if re.search(pat, script_blob, re.IGNORECASE):
                    behaviour["script_obfuscation_hits"].append(label)

            for iframe in soup.find_all("iframe"):
                style_attr = (iframe.get("style") or "").lower().replace(" ", "")
                w = str(iframe.get("width") or "").strip()
                h = str(iframe.get("height") or "").strip()
                if "display:none" in style_attr or "visibility:hidden" in style_attr or w in ("0", "1") or h in ("0", "1"):
                    behaviour["hidden_iframes"] += 1

            for form in soup.find_all("form"):
                action = (form.get("action") or "").strip()
                if action.startswith(("http://", "https://")):
                    act_host = (urlparse(action).hostname or "").lower()
                    if root_dom and root_dom not in act_host:
                        behaviour["external_form_actions"].append(action[:120])
                elif action in ("", "#") or action.lower().startswith("javascript:"):
                    behaviour["suspicious_form_actions"].append(action or "<empty>")

            behaviour["has_password_field"] = bool(soup.find("input", {"type": re.compile(r"^password$", re.I)}))
            behaviour["has_file_upload"] = bool(soup.find("input", {"type": re.compile(r"^file$", re.I)}))

            for tag in soup(["script", "style", "noscript"]):
                tag.decompose()

            clean_text = re.sub(r"\s+", " ", soup.get_text(" ")).strip()
            behaviour["text_snippet"] = clean_text[:1500]

            lower_all = f"{behaviour['title']} {clean_text}".lower()
            behaviour["urgency_keywords_found"] = [kw for kw in URGENCY_WORDS if kw in lower_all][:8]

    except Exception as e:
        behaviour["fetch_error"] = str(e)[:120]

    return behaviour

def check_gsb(urls: list) -> dict:
    if not GSB_API_KEY:
        return {"checked": False, "is_dangerous": False, "threat_type": None}
    unique_urls = [u for u in set(urls) if u]
    if not unique_urls:
        return {"checked": False, "is_dangerous": False, "threat_type": None}
    try:
        endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GSB_API_KEY}"
        payload = {
            "client": {"clientId": "scamsense-soc", "clientVersion": "5.0"},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": u} for u in unique_urls]
            }
        }
        r = requests.post(endpoint, json=payload, timeout=4)
        if r.status_code == 200:
            matches = r.json().get("matches") or []
            if matches:
                return {"checked": True, "is_dangerous": True, "threat_type": matches[0].get("threatType", "MALICIOUS")}
            return {"checked": True, "is_dangerous": False, "threat_type": None}
    except Exception:
        pass
    return {"checked": False, "is_dangerous": False, "threat_type": None}

def check_vt(target_url: str) -> dict:
    if not VT_API_KEY or not target_url:
        return {"checked": False, "malicious": 0, "suspicious": 0}
    try:
        url_id = base64.urlsafe_b64encode(target_url.encode()).decode().strip("=")
        endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        r = requests.get(endpoint, headers={"x-apikey": VT_API_KEY}, timeout=4)
        if r.status_code == 200:
            stats = r.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {}) or {}
            return {
                "checked": True,
                "malicious": int(stats.get("malicious", 0)),
                "suspicious": int(stats.get("suspicious", 0))
            }
    except Exception:
        pass
    return {"checked": False, "malicious": 0, "suspicious": 0}

def check_urlhaus(target_url: str) -> dict:
    if not target_url:
        return {"checked": False, "listed": False, "threat": None}
    try:
        r = requests.post("https://urlhaus-api.abuse.ch/v1/url/", data={"url": target_url}, timeout=4)
        if r.status_code == 200:
            data = r.json() or {}
            if data.get("query_status") == "ok":
                return {"checked": True, "listed": True, "threat": data.get("threat") or "malware_url"}
            return {"checked": True, "listed": False, "threat": None}
    except Exception:
        pass
    return {"checked": False, "listed": False, "threat": None}

def check_email_domain_dns(sender: str) -> dict:
    if not sender or "@" not in sender:
        return {"status": "no_sender", "sender_domain": None, "has_mx": False, "has_spf": False, "has_dmarc": False}
    dom = sender.split("@")[-1].strip().lower()
    rep = {"status": "checked", "sender_domain": dom, "has_mx": False, "has_spf": False, "has_dmarc": False}
    try:
        rep["has_mx"] = len(dns.resolver.resolve(dom, "MX", lifetime=3)) > 0
    except Exception:
        pass
    try:
        txts = [str(r).lower() for r in dns.resolver.resolve(dom, "TXT", lifetime=3)]
        rep["has_spf"] = any("v=spf1" in t for t in txts)
    except Exception:
        pass
    try:
        dmarc_txts = [str(r).lower() for r in dns.resolver.resolve(f"_dmarc.{dom}", "TXT", lifetime=3)]
        rep["has_dmarc"] = any("v=dmarc1" in t for t in dmarc_txts)
    except Exception:
        pass
    return rep

def analyze_url_deep(url: str) -> dict:
    decoded = unquote((url or "").strip())
    target = decoded if decoded.startswith(("http://", "https://")) else "http://" + decoded
    parsed = urlparse(target)
    host = (parsed.hostname or "").lower()
    parts = [p for p in host.split(".") if p]
    root_dom = f"{parts[-2]}.{parts[-1]}" if len(parts) >= 2 else host

    behaviour = fetch_live_behaviour(target, root_dom)
    final_u = behaviour.get("final_url") or target

    with ThreadPoolExecutor(max_workers=4) as ex:
        f_gsb = ex.submit(check_gsb, [target, final_u])
        f_vt = ex.submit(check_vt, final_u)
        f_uh = ex.submit(check_urlhaus, final_u)
        f_ssl = ex.submit(get_ssl_info, host)

        gsb_res = f_gsb.result()
        vt_res = f_vt.result()
        uh_res = f_uh.result()
        ssl_res = f_ssl.result()

    heuristics = {
        "protocol": parsed.scheme.upper(),
        "domain": host,
        "root_domain": root_dom,
        "is_ip_host": is_ip_address(host),
        "is_punycode": "xn--" in host,
        "subdomain_count": max(0, len(parts) - 2),
        "has_at_trap": "@" in (parsed.netloc or ""),
        "risky_tld": any(host.endswith(tld) for tld in RISKY_TLDS),
        "free_or_cloud_host": any(h in host for h in SUSPICIOUS_HOSTS),
        "url_entropy": calc_entropy(target),
        "path_length": len(parsed.path or ""),
        "ssl": ssl_res,
        "oauth_analysis": inspect_oauth_and_params(target, host)
    }

    return {
        "input_url": url,
        "normalized_url": target,
        "heuristics": heuristics,
        "behaviour": behaviour,
        "google_safe_browsing": gsb_res,
        "virustotal": vt_res,
        "urlhaus_threat_feed": uh_res
    }
