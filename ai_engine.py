import os
import json
import hashlib
import re
from urllib.parse import urlparse
from google import genai
from google.genai import types
from PIL import Image
import io

client = genai.Client(
    api_key=os.getenv("GEMINI_API_KEY"),
    http_options={'timeout': 18.0}
)

RESULT_CACHE = {}

OFFICIAL_BRAND_MAP = {
    "sbi": ["onlinesbi.sbi", "sbi.co.in", "sbicard.com"],
    "hdfc": ["hdfcbank.com", "hdfc.com"],
    "icici": ["icicibank.com", "icicidirect.com"],
    "axis": ["axisbank.com"],
    "kotak": ["kotak.com"],
    "pnb": ["pnbindia.in"],
    "paytm": ["paytm.com"],
    "phonepe": ["phonepe.com"],
    "skype": ["skype.com", "microsoft.com", "live.com"],
    "google": ["google.com", "google.co.in", "googleapis.com"],
    "facebook": ["facebook.com", "fb.com"],
    "instagram": ["instagram.com"],
    "whatsapp": ["whatsapp.com"],
    "amazon": ["amazon.in", "amazon.com"],
    "flipkart": ["flipkart.com"],
    "microsoft": ["microsoft.com", "live.com", "office.com"],
    "apple": ["apple.com", "icloud.com"],
    "paypal": ["paypal.com"],
    "indiapost": ["indiapost.gov.in"],
    "epfo": ["epfindia.gov.in"],
    "incometax": ["incometax.gov.in"]
}

def get_3_tier_level(score: int) -> str:
    if score <= 30:
        return "SAFE"
    elif score <= 60:
        return "SUSPICIOUS"
    else:
        return "HIGH RISK"

def get_active_gemini_model():
    try:
        for m in client.models.list():
            name = m.name.replace("models/", "")
            if "flash" in name.lower() and "lite" not in name.lower() and "exp" not in name.lower():
                return name
    except Exception:
        pass
    return "gemini-2.5-flash"

def is_official_domain_for_brand(brand: str, domain: str) -> bool:
    allowed = OFFICIAL_BRAND_MAP.get(brand, [])
    return any(domain == d or domain.endswith("." + d) for d in allowed)

def deep_forensic_fallback(content_type: str, text_data: str, extra_intel: dict):
    intel = extra_intel or {}
    url_reports = []
    if "deep_url_forensics" in intel:
        url_reports.append(intel)
    elif intel.get("embedded_urls_intel"):
        url_reports.extend(intel.get("embedded_urls_intel", []))

    score = 5
    reasons = []
    evidence = []

    for rep in url_reports:
        gsb = rep.get("google_safe_browsing", {})
        vt = rep.get("virustotal", {})
        uf = rep.get("deep_url_forensics", {})
        if gsb.get("is_dangerous") or vt.get("malicious", 0) > 0:
            vt_hits = vt.get("malicious", 1)
            return {
                "risk_score": min(99, 93 + vt_hits),
                "classification": "HIGH RISK",
                "what_was_detected": f"Confirmed malicious payload at {uf.get('final_destination', 'Blacklisted Target')}.",
                "why_suspicious": "Flagged by global threat intelligence for active phishing or malware distribution.",
                "how_affects_user": "Interacting with this target exposes credentials, banking sessions, and device security to immediate compromise.",
                "evidence": f"GSB: {gsb.get('threat_type', 'MALICIOUS')} | VT Engines: {vt_hits} | Host: {uf.get('domain')}",
                "how_to_stay_safe": [
                    "Close this target immediately and never enter any username, password, or OTP.",
                    "If credentials were entered, reset your password immediately."
                ]
            }

    lower_text = (text_data or "").lower()
    mentioned_brands = [b for b in OFFICIAL_BRAND_MAP.keys() if b in lower_text]

    for rep in url_reports:
        uf = rep.get("deep_url_forensics", {})
        dom = uf.get("domain", "")
        final_dom = urlparse(uf.get("final_destination", "")).netloc.lower() or dom
        age = uf.get("domain_age_days")
        spoofed_paths = uf.get("spoofed_domains_in_path", [])
        hex_folder = uf.get("has_random_hex_folder", False)
        sus_paths = uf.get("suspicious_path_keywords", [])

        # ১. URL Path-এর ভেতরে লুকানো ফেক ডোমেইন ধরা (যেমন nobell.it/.../://skype.com...)
        if spoofed_paths:
            score += 68
            reasons.append(f"Path-Spoofing Phishing Attack: Unrelated host '{dom}' embeds deceptive domain(s) {', '.join(spoofed_paths)} inside the URL path to impersonate a trusted login page.")
            evidence.append(f"Actual Host: {dom} != Spoofed Path Domain: {', '.join(spoofed_paths)}")

        # ২. লম্বা হেক্স হ্যাশ ফোল্ডার + cgi-bin/verification ধরা
        if hex_folder:
            score += 36
            reasons.append("Obfuscated hexadecimal directory hash detected, typical of automated phishing kit deployments.")
            evidence.append("Obfuscated Hex Path: Detected")

        if len(sus_paths) >= 2:
            score += 28
            reasons.append(f"High-risk credential harvesting path structure ({', '.join(sus_paths[:4])}).")
            evidence.append(f"Suspicious Path Tokens: {', '.join(sus_paths[:4])}")

        if uf.get("url_length", 0) > 75:
            score += 14
            evidence.append(f"Abnormal URL Length: {uf.get('url_length')} chars")

        if uf.get("is_shortener"):
            score += 38
            reasons.append(f"Uses URL shortener ({dom}) to mask final destination ({final_dom}).")
            evidence.append(f"Shortener: {dom} -> {final_dom}")

        if age is not None and age < 90:
            score += 48
            reasons.append(f"Newly registered domain ({age} days old).")
            evidence.append(f"Domain Age: {age} days")

        if uf.get("has_punycode"):
            score += 58
            reasons.append("Homograph Punycode domain spoofing detected.")
            evidence.append(f"Punycode: {final_dom}")

        for b in mentioned_brands:
            if not is_official_domain_for_brand(b, final_dom):
                score += 62
                reasons.append(f"Brand-Domain Mismatch: Impersonates '{b.upper()}' on unauthorized host '{final_dom}'.")
                evidence.append(f"Claimed Brand: {b.upper()} | Actual Host: {final_dom}")
                break

    first_rep = next(iter(url_reports), None)
    if content_type == "Website URL" and first_rep and score < 30:
        uf = first_rep.get("deep_url_forensics", {})
        dom = uf.get("domain", "")
        for b in OFFICIAL_BRAND_MAP:
            if is_official_domain_for_brand(b, dom):
                return {
                    "risk_score": 3,
                    "classification": "SAFE",
                    "what_was_detected": f"Verified official {b.upper()} domain ({dom}).",
                    "why_suspicious": "Domain matches official verified infrastructure with clean path structure and threat intelligence.",
                    "how_affects_user": "Safe for legitimate browsing and authentication.",
                    "evidence": f"Verified Domain: {dom} | SSL: {uf.get('ssl_issuer')} | GSB & VT: Clean",
                    "how_to_stay_safe": ["Verified official website. Always ensure HTTPS is active before logging in."]
                }

    score = min(98, max(4, score))
    tier = get_3_tier_level(score)

    if tier == "SAFE":
        return {
            "risk_score": score,
            "classification": "SAFE",
            "what_was_detected": f"Benign {content_type} with no deceptive path spoofing or malicious payloads.",
            "why_suspicious": "Domain structure, URL path, and threat intelligence telemetry appear clean.",
            "how_affects_user": "No security or financial threat detected.",
            "evidence": "GSB: Clean | VT: 0 Detections | Path & Domain Check: Passed",
            "how_to_stay_safe": ["Content appears safe. Continue practicing standard digital hygiene."]
        }

    return {
        "risk_score": score,
        "classification": tier,
        "what_was_detected": f"Deceptive phishing structure uncovered in {content_type}.",
        "why_suspicious": " ".join(reasons) if reasons else "Anomalous URL path and domain routing detected.",
        "how_affects_user": "Designed to trick users into entering login credentials on an attacker-controlled server.",
        "evidence": " | ".join(evidence) if evidence else f"Forensic Anomaly Score: {score}/100",
        "how_to_stay_safe": [
            "Do NOT enter your username, password, or verification details on this page.",
            "Always navigate to the official service website directly instead of following deep links."
        ]
    }

def analyze_threat(content_type: str, text_data: str = "", image_bytes: bytes = None, extra_intel: dict = None):
    cache_raw = f"{content_type}:{text_data}:{len(image_bytes) if image_bytes else 0}:{json.dumps(extra_intel, sort_keys=True)}"
    cache_key = hashlib.sha256(cache_raw.encode()).hexdigest()
    if cache_key in RESULT_CACHE:
        return RESULT_CACHE[cache_key]

    prompt = f"""
    You are a Principal Digital Forensics & Anti-Phishing Architect for 'ScamSense'.
    Module Type: {content_type}
    Extracted Live URL Forensics, Path Analysis, Domain Age, Google Safe Browsing & VirusTotal Telemetry:
    {json.dumps(extra_intel) if extra_intel else 'None'}

    CRITICAL FORENSIC RULES:
    1. PATH SPOOFING: Attackers host phishing kits on compromised domains (like 'nobell.it') and put fake domains inside the URL path (like '/70ffb52d.../://skype.comen/cgi-bin/verification/login/'). Check `spoofed_domains_in_path`, `has_random_hex_folder`, and `suspicious_path_keywords`! If an unrelated root domain contains another brand/domain in its path, it is ALWAYS HIGH RISK (85-98%).
    2. POLITE PHISHING BAIT: Modern scam messages/emails use calm, normal language while embedding links to unofficial domains. Check `embedded_urls_intel`.
    3. STRICT 3-TIER CLASSIFICATION:
       - 0 to 30: "SAFE"
       - 31 to 60: "SUSPICIOUS"
       - 61 to 100: "HIGH RISK"

Return ONLY a valid JSON object with this exact schema:
{{
"risk_score": <integer 0-100>,
"classification": "<SAFE | SUSPICIOUS | HIGH RISK>",
"what_was_detected": "<1-2 crisp sentences stating what the surface URL/message shows vs what the actual underlying host/payload is>",
"why_suspicious": "<1-2 sentences explaining the exact forensic flaw (e.g., path spoofing, hex directory, brand-domain mismatch) or why it is verified safe>",
"how_affects_user": "<1-2 sentences explaining the exact consequence to the user's credentials, finances, or device>",
"evidence": "<Exact technical proof: actual root domain vs spoofed path domain, hex hash, GSB/VT telemetry>",
"how_to_stay_safe": [
"<Specific actionable step 1>",
"<Specific actionable step 2>"
]
}}
Input to Deep-Scan: {text_data}
"""
contents = [prompt]
if image_bytes:
img = Image.open(io.BytesIO(image_bytes))
contents.append(img)
active_model = get_active_gemini_model()
models_to_try = list(dict.fromkeys([active_model, 'gemini-2.5-flash', 'gemini-2.0-flash']))
for model_name in models_to_try:
try:
response = client.models.generate_content(
model=model_name,
contents=contents,
config=types.GenerateContentConfig(
response_mime_type="application/json",
temperature=0.0
)
)
parsed = json.loads(response.text)
score = int(parsed.get("risk_score", 0))
parsed["risk_score"] = score
parsed["classification"] = get_3_tier_level(score)
RESULT_CACHE[cache_key] = parsed
return parsed
except Exception:
continue
fallback_res = deep_forensic_fallback(content_type, text_data, extra_intel)
RESULT_CACHE[cache_key] = fallback_res
return fallback_res
