import os
import re
import math
import socket
import ssl
import base64
import requests
import dns.resolver
from datetime import datetime, timezone
from urllib.parse import urlparse, unquote, parse_qs
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor

VT_API_KEY = (os.getenv("VIRUSTOTAL_API_KEY") or "").strip()
GSB_API_KEY = (os.getenv("SAFE_BROWSING_API_KEY") or os.getenv("GSB_API_KEY") or "").strip()

RISKY_TLDS = (
    ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".cfd", ".sbs",
    ".icu", ".click", ".link", ".work", ".zip", ".mov", ".rest", ".cam",
    ".live", ".shop", ".online", ".site", ".website", ".pw", ".cc", ".buzz"
)
TUNNEL_AND_CLOUD_HOSTS = (
    "ngrok", "ngrok-free", "trycloudflare", "loclx", "serveo", "localtunnel",
    "pages.dev", "workers.dev", "supabase.co", "herokuapp.com", "000webhostapp.com",
    "vercel.app", "netlify.app", "firebaseapp.com", "web.app", "duckdns.org", "glitch.me", "replit.dev"
)
UGC_OR_PROFILE_HOSTS = (
    "cake.me", "notion.site", "medium.com", "substack.com", "sites.google.com",
    "docs.google.com", "weebly.com", "wixsite.com", "blogspot.com", "wordpress.com",
    "github.io", "canva.site", "linktr.ee", "bio.link"
)
LOGIN_LURE_TOKENS = (
    "login", "signin", "sign-in", "log-in", "webmail", "mail-login", "att-mail",
    "verify", "verification", "password", "reset", "auth", "oauth", "account",
    "billing", "invoice", "update-kyc", "kyc", "unlock", "security-check",
    "wallet", "claim", "trade", "session", "confirm", "recover", "portal"
)
BRAND_IMPERSONATION_TOKENS = (
    "microsoft", "office365", "outlook", "onedrive", "sharepoint", "google",
    "gmail", "apple", "icloud", "amazon", "netflix", "paypal", "facebook",
    "instagram", "whatsapp", "bank", "sbi", "hdfc", "icici", "att", "steam", "binance"
)
SMUGGLE_AND_TRACK_PARAMS = (
    "referrer", "af_tranid", "click_id", "clickid", "subid", "aff_id", "pid",
    "redirect_uri", "redirect_url", "next", "url", "dest", "destination",
    "return_to", "continue", "goto", "token", "sid", "state", "code", "link", "to"
)
URGENCY_WORDS = (
    "urgent", "immediately", "suspended", "verify your account", "kyc", "otp",
    "password", "reset", "locked", "unauthorized", "refund", "prize", "won",
    "invoice", "legal notice", "aadhaar", "pan", "cpf", "cnpj", "ssn", "card",
    "confirm identity", "session expired", "sign in", "log in", "enter code"
)
COMMON_BENIGN_SUBDOMAINS = {
    "www", "mail", "webmail", "login", "signin", "auth", "accounts", "account",
    "admin", "portal", "api", "cdn", "static", "assets", "img", "images",
    "media", "blog", "news", "shop", "store", "support", "help", "docs",
    "dev", "staging", "test", "app", "m", "mobile", "cloud", "vpn", "sso"
}

def calc_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {c: s.count(c) for c in set(s)}
    length = len(s)
    return round(-sum((n / length) * math.log2(n / length) for n in freq.values()), 2)

def is_gibberish_label(label: str) -> bool:
    """Detects random/gibberish host labels regardless of TLD (e.g., uidqaxan, x9k2m7p)."""
    s = (label or "").strip().lower()
    if len(s) < 6 or s in COMMON_BENIGN_SUBDOMAINS:
        return False
    # Ignore obvious all-digit IDs unless very long and mixed
    alpha_only = re.sub(r"[^a-z]", "", s)
    if len(alpha_only) < 5:
        return False
    vowels = sum(1 for c in alpha_only if c in "aeiou")
    consonant_runs = len(re.findall(r"[bcdfghjklmnpqrstvwxyz]{4,}", alpha_only))
    has_mixed_alnum = bool(re.search(r"[a-z]", s) and re.search(r"[0-9]", s)) and len(s) >= 7
    low_vowel_ratio = vowels <= max(1, len(alpha_only) // 4)
    high_label_entropy = calc_entropy(s) >= 2.75

    return (
        (high_label_entropy and low_vowel_ratio)
        or consonant_runs >= 1
        or (has_mixed_alnum and high_label_entropy)
    )

def is_ip_address(host: str) -> bool:
    try:
        socket.inet_aton(host)
        return True
    except OSError:
        return False

def get_domain_age_rdap(root_domain: str) -> dict:
    info = {"checked": False, "age_days": None, "created_date": None, "is_newly_registered": False}
    if not root_domain or is_ip_address(root_domain):
        return info
    try:
        r = requests.get(f"https://rdap.org/domain/{root_domain}", timeout=3.5, headers={"Accept": "application/rdap+json"})
        if r.status_code == 200:
            data = r.json() or {}
            for ev in data.get("events") or []:
                if ev.get("eventAction") == "registration" and ev.get("eventDate"):
                    raw_dt = ev["eventDate"].replace("Z", "+00:00")
                    created = datetime.fromisoformat(raw_dt)
                    age_days = max(0, (datetime.now(timezone.utc) - created).days)
                    info["checked"] = True
                    info["age_days"] = age_days
                    info["created_date"] = created.strftime("%Y-%m-%d")
                    info["is_newly_registered"] = age_days <= 90
                    break
    except Exception:
        pass
    return info

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
                for tup in cert.get("issuer", ()):
                    for k, v in tup:
                        if k == "organizationName":
                            info["issuer"] = v
                            break
    except Exception:
        pass
    return info

def inspect_wrapper_and_cloak(target_url: str, host: str) -> dict:
    once = unquote(target_url or "")
    twice = unquote(once)
    parsed = urlparse(target_url)
    qs = parse_qs(parsed.query)

    nested_urls = []
    decoded_b64_urls = []

    for key, vals in qs.items():
        for v in vals:
            u1 = unquote(v)
            u2 = unquote(u1)
            for candidate in (v, u1, u2):
                if "http://" in candidate.lower() or "https://" in candidate.lower():
                    nested_urls.append(candidate[:160])
                cleaned_b64 = re.sub(r"[^A-Za-z0-9+/=_-]", "", candidate)
                if len(cleaned_b64) >= 16:
                    try:
                        padded = cleaned_b64.replace("-", "+").replace("_", "/")
                        padded += "=" * ((4 - len(padded) % 4) % 4)
                        dec = base64.b64decode(padded, validate=False).decode("utf-8", errors="ignore")
                        if any(tok in dec.lower() for tok in ("http://", "https://", "login", "signin", "verify", "oauth", "redirect")):
                            decoded_b64_urls.append(dec[:140])
                    except Exception:
                        pass

    path_and_frag = f"{parsed.path or ''}#{parsed.fragment or ''}"
    for m in re.findall(r"https?://[^\s\"'<>]+", unquote(path_and_frag), flags=re.IGNORECASE):
        nested_urls.append(m[:160])

    external_wrapped_hosts = []
    for nu in nested_urls + decoded_b64_urls:
        nh = (urlparse(nu).hostname or "").lower()
        if nh and host and not nh.endswith(host) and not host.endswith(nh):
            external_wrapped_hosts.append(nh)

    double_encoded = (twice != once) and ("%" in once)

    return {
        "has_nested_wrapped_url": bool(nested_urls or decoded_b64_urls),
        "nested_urls_found": nested_urls[:4],
        "decoded_base64_lures": decoded_b64_urls[:3],
        "external_wrapped_hosts": list(dict.fromkeys(external_wrapped_hosts))[:4],
        "double_encoded_url": double_encoded,
        "has_fragment_payload": bool(parsed.fragment and len(parsed.fragment) > 8)
    }

def inspect_oauth_and_params(target_url: str, host: str) -> dict:
    parsed = urlparse(target_url)
    qs = parse_qs(parsed.query)
    lower_url = target_url.lower()
    query_lower = (parsed.query or "").lower()

    is_oauth = any(k in lower_url for k in ("/oauth2/", "/authorize", "client_id=", "response_type="))
    redirect_targets = []
    for key in (
        "redirect_uri", "redirect_url", "next", "url", "dest", "destination",
        "return_to", "continue", "r", "target", "goto", "referrer", "link", "to"
    ):
        for val in qs.get(key, []):
            redirect_targets.append(unquote(val))

    external_redirects = []
    suspicious_param_values = []
    for rt in redirect_targets:
        rt_lower = rt.lower()
        if rt_lower.startswith(("javascript:", "data:", "vbscript:")):
            suspicious_param_values.append(rt[:120])
            continue
        rt_host = (urlparse(rt).hostname or "").lower()
        if rt_host and host and not rt_host.endswith(host) and not host.endswith(rt_host):
            external_redirects.append(rt[:160])

    scopes_raw = " ".join(qs.get("scope", [])).lower()
    risky_scopes = [
        s for s in (
            "mail.read", "mail.send", "mail.readwrite", "files.read", "files.readwrite",
            "offline_access", "user.readwrite", "contacts.read", "mailboxsettings"
        )
        if s in scopes_raw
    ]

    smuggle_hits = [p for p in SMUGGLE_AND_TRACK_PARAMS if p in query_lower]
    has_base64_blob = bool(re.search(r"(?:[A-Za-z0-9+/]{20,}(?:==|=|%3D%3D|%3D))", parsed.query or ""))

    return {
        "is_oauth_or_auth_flow": is_oauth,
        "has_truncated_ellipsis": "..." in target_url or "…" in target_url,
        "external_redirect_params": external_redirects,
        "suspicious_param_values": suspicious_param_values,
        "risky_oauth_scopes": risky_scopes,
        "smuggle_or_affiliate_params": smuggle_hits,
        "has_base64_query_blob": has_base64_blob,
        "query_param_count": len(qs)
    }

def inspect_path_and_deception(target_url: str, host: str, root_dom: str) -> dict:
    parsed = urlparse(target_url)
    path_str = (parsed.path or "").lower()
    query_str = (parsed.query or "").lower()
    path_q = f"{path_str} {query_str}"

    lure_hits = [tok for tok in LOGIN_LURE_TOKENS if tok in path_q]
    is_ugc_host = any(h in host for h in UGC_OR_PROFILE_HOSTS)
    is_tunnel_or_cloud = any(h in host for h in TUNNEL_AND_CLOUD_HOSTS)

    brand_hits = []
    for b in BRAND_IMPERSONATION_TOKENS:
        if b in host or b in path_str:
            if b not in root_dom:
                brand_hits.append(b)

    has_double_dash_trick = "--" in host or "---" in path_str
    encoded_percent_count = len(re.findall(r"%[0-9a-fA-F]{2}", target_url))

    path_segments = [seg for seg in path_str.split("/") if seg]
    gibberish_path_segments = [seg for seg in path_segments if is_gibberish_label(seg)]

    return {
        "login_or_lure_tokens": lure_hits[:6],
        "is_ugc_or_profile_host": is_ugc_host,
        "is_tunnel_or_cloud_host": is_tunnel_or_cloud,
        "lure_on_ugc_or_profile_path": bool(lure_hits and is_ugc_host),
        "lure_on_tunnel_or_cloud_host": bool(lure_hits and is_tunnel_or_cloud),
        "brand_mismatch_tokens": brand_hits[:5],
        "has_double_dash_trick": has_double_dash_trick,
        "encoded_percent_count": encoded_percent_count,
        "gibberish_path_segments": gibberish_path_segments[:4]
    }

def fetch_live_behaviour(target: str, root_dom: str) -> dict:
    behaviour = {
        "final_url": target,
        "http_status": None,
        "bot_blocked_or_evasive": False,
        "redirect_count": 0,
        "redirect_chain": [],
        "cross_domain_redirect": False,
        "meta_refresh_detected": False,
        "title": "",
        "text_snippet": "",
        "has_password_field": False,
        "has_credential_inputs": False,
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

        if resp.status_code in (403, 429, 503):
            behaviour["bot_blocked_or_evasive"] = True

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
            html_chunk = resp.text[:130000]
            soup = BeautifulSoup(html_chunk, "html.parser")

            if soup.title and soup.title.string:
                behaviour["title"] = soup.title.string.strip()[:100]

            meta_ref = soup.find("meta", attrs={"http-equiv": re.compile(r"^refresh$", re.I)})
            if meta_ref:
                behaviour["meta_refresh_detected"] = True

            lower_all_check = f"{behaviour['title']} {html_chunk}".lower()
            if any(w in lower_all_check for w in (
                "just a moment", "cf-browser-verification", "attention required",
                "access denied", "enable javascript", "checking your browser"
            )):
                behaviour["bot_blocked_or_evasive"] = True

            script_blob = "\n".join((s.get_text(" ") or "") for s in soup.find_all("script"))[:45000]
            obf_patterns = [
                (r"eval\s*\(", "eval()"),
                (r"unescape\s*\(", "unescape()"),
                (r"fromCharCode", "String.fromCharCode"),
                (r"atob\s*\(", "atob() base64 decode"),
                (r"document\.write\s*\(", "document.write()"),
                (r"oncontextmenu\s*=|preventDefault\(\)", "context-menu/event block"),
                (r"window\.location\s*=|location\.replace\s*\(|location\.href\s*=|window\.open\s*\(", "JS redirect/popup")
            ]
            for pat, label in obf_patterns:
                if re.search(pat, script_blob, re.IGNORECASE):
                    behaviour["script_obfuscation_hits"].append(label)

            for iframe in soup.find_all("iframe"):
                style_attr = (iframe.get("style") or "").lower().replace(" ", "")
                w = str(iframe.get("width") or "").strip()
                h = str(iframe.get("height") or "").strip()
                if "display:none" in style_attr or "visibility:hidden" in style_attr or "opacity:0" in style_attr or w in ("0", "1") or h in ("0", "1"):
                    behaviour["hidden_iframes"] += 1

            for form in soup.find_all("form"):
                action = (form.get("action") or "").strip()
                method = (form.get("method") or "get").strip().lower()
                if action.startswith(("http://", "https://")):
                    act_host = (urlparse(action).hostname or "").lower()
                    if root_dom and root_dom not in act_host:
                        behaviour["external_form_actions"].append(action[:120])
                elif action in ("", "#") or action.lower().startswith("javascript:"):
                    behaviour["suspicious_form_actions"].append(action or "<empty>")
                if method == "get" and (form.find("input", {"type": re.compile(r"password|email", re.I)}) or re.search(r"pass|login|user|otp", str(form), re.I)):
                    behaviour["suspicious_form_actions"].append("GET method on login/credential form")

            behaviour["has_password_field"] = bool(soup.find("input", {"type": re.compile(r"^password$", re.I)}))
            cred_input_hits = False
            for inp in soup.find_all("input"):
                attrs_blob = f"{inp.get('type') or ''} {inp.get('name') or ''} {inp.get('id') or ''} {inp.get('placeholder') or ''}".lower()
                if any(k in attrs_blob for k in ("password", "pass", "email", "username", "user_id", "otp", "pin", "cvv", "card")):
                    cred_input_hits = True
                    break
            behaviour["has_credential_inputs"] = behaviour["has_password_field"] or cred_input_hits
            behaviour["has_file_upload"] = bool(soup.find("input", {"type": re.compile(r"^file$", re.I)}))

            for tag in soup(["script", "style", "noscript"]):
                tag.decompose()

            clean_text = re.sub(r"\s+", " ", soup.get_text(" ")).strip()
            behaviour["text_snippet"] = clean_text[:1500]

            lower_all = f"{behaviour['title']} {clean_text}".lower()
            behaviour["urgency_keywords_found"] = [kw for kw in URGENCY_WORDS if kw in lower_all][:8]

    except Exception as e:
        behaviour["fetch_error"] = str(e)[:120]
        behaviour["bot_blocked_or_evasive"] = True

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
            "client": {"clientId": "scamsense-soc", "clientVersion": "9.0"},
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

    subdomain_labels = parts[:-2] if len(parts) > 2 else []
    gibberish_subs = [lbl for lbl in subdomain_labels if is_gibberish_label(lbl)]

    behaviour = fetch_live_behaviour(target, root_dom)
    final_u = behaviour.get("final_url") or target

    with ThreadPoolExecutor(max_workers=5) as ex:
        f_rdap = ex.submit(get_domain_age_rdap, root_dom)
        f_gsb = ex.submit(check_gsb, [target, final_u])
        f_vt = ex.submit(check_vt, final_u)
        f_uh = ex.submit(check_urlhaus, final_u)
        f_ssl = ex.submit(get_ssl_info, host)

        rdap_res = f_rdap.result()
        gsb_res = f_gsb.result()
        vt_res = f_vt.result()
        uh_res = f_uh.result()
        ssl_res = f_ssl.result()

    heuristics = {
        "protocol": parsed.scheme.upper(),
        "domain": host,
        "root_domain": root_dom,
        "domain_age": rdap_res,
        "is_ip_host": is_ip_address(host),
        "is_punycode": "xn--" in host,
        "subdomain_count": len(subdomain_labels),
        "gibberish_subdomains": gibberish_subs[:4],
        "has_gibberish_subdomain": bool(gibberish_subs),
        "has_at_trap": "@" in (parsed.netloc or ""),
        "risky_tld": any(host.endswith(tld) for tld in RISKY_TLDS),
        "tunnel_or_cloud_host": any(h in host for h in TUNNEL_AND_CLOUD_HOSTS),
        "url_entropy": calc_entropy(target),
        "path_length": len(parsed.path or ""),
        "ssl": ssl_res,
        "wrapper_cloak": inspect_wrapper_and_cloak(target, host),
        "oauth_analysis": inspect_oauth_and_params(target, host),
        "path_context": inspect_path_and_deception(target, host, root_dom)
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
