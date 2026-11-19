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
    "vercel.app", "netlify.app", "firebaseapp.com", "web.app", "duckdns.org",
    "glitch.me", "replit.dev"
)
SCHEDULING_AND_FORM_HOSTS = (
    "calendly.com", "cal.com", "savvycal.com", "hubspot.com", "typeform.com",
    "jotform.com", "tally.so", "forms.gle", "docs.google.com", "calendly"
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
APK_CHEAT_LURE_TOKENS = (
    "apk", "panel", "mod", "cheat", "cheats", "hack", "hacks", "aimbot",
    "headshot", "bypass", "crack", "cracked", "keygen", "injector", "script",
    "freefire", "pubg", "bgmi", "diamond", "diamonds", "uc", "robux"
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
    "confirm identity", "session expired", "sign in", "log in", "enter code",
    "download apk", "free diamonds", "headshot", "aimbot", "panel"
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
    s = (label or "").strip().lower()
    if len(s) < 6 or s in COMMON_BENIGN_SUBDOMAINS:
        return False
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
        r = requests.get(
            f"https://rdap.org/domain/{root_domain}",
            timeout=3.5,
            headers={"Accept": "application/rdap+json"}
        )
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

    for _, vals in qs.items():
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
        "has_fragment_
    }
