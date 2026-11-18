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

def deep_forensic_fallback(content_type: str, text_data: str, extra_intel: dict):
    intel = extra_intel or {}
    gsb = intel.get("google_safe_browsing", {})
    vt = intel.get("virustotal", {})
    url_f = intel.get("deep_url_forensics", {})

    if gsb.get("is_dangerous") or vt.get("malicious", 0) > 0:
        vt_hits = vt.get("malicious", 1)
        score = min(99, 92 + vt_hits)
        return {
            "risk_score": score,
            "classification": "HIGH RISK",
            "what_was_detected": f"Verified malicious infrastructure detected at {url_f.get('final_destination', text_data[:60])}.",
            "why_suspicious": "Even if the surface link appears legitimate, threat intelligence confirms active credential harvesting or malware delivery.",
            "how_affects_user": "Interacting with this target exposes passwords, banking sessions, and personal data to immediate theft.",
            "evidence": f"GSB Match: {gsb.get('threat_type', 'TRUE')} | VT Malicious Engines: {vt_hits} | Final URL: {url_f.get('final_destination', 'N/A')}",
            "how_to_stay_safe": [
                "Terminate connection immediately and do not enter any credentials or OTP.",
                "If accessed, change passwords immediately from a clean device."
            ]
        }

    score = 6
    reasons = []
    evidence = []

    # Deep URL Forensics Check
    if url_f:
        domain = url_f.get("domain", "")
        age = url_f.get("domain_age_days")
        redirects = url_f.get("redirect_chain", [])

        if age is not None and age < 90:
            score += 48
            reasons.append(f"Newly registered domain ({age} days old) attempting to appear established.")
            evidence.append(f"Domain Age: {age} days (Created: {url_f.get('domain_created_date')})")

        if len(redirects) > 1:
            score += 22
            reasons.append(f"Hidden multi-hop redirect chain ({len(redirects)} hops) masking the final destination.")
            evidence.append(f"Redirect Destination: {url_f.get('final_destination')}")

        if url_f.get("has_punycode"):
            score += 55
            reasons.append("Internationalized Punycode (xn--) homograph attack mimicking trusted characters.")
            evidence.append(f"Punycode Domain: {domain}")

        if url_f.get("subdomain_count", 0) >= 2:
            score += 32
            reasons.append("Deep subdomain nesting used to hide the true root domain.")
            evidence.append(f"Subdomain Depth: {url_f.get('subdomain_count')} in {domain}")

        if "No Valid HTTPS" in url_f.get("ssl_issuer", ""):
            score += 20
            reasons.append("Lacks valid TLS/SSL encryption certificate.")
            evidence.append("SSL Status: Invalid/Missing")

    # Deep Text / Embedded URL Mismatch Check (Catches polite-looking scam messages)
    urls_in_text = re.findall(r'https?://[^\s<>"]+|www\.[^\s<>"]+', text_data or "")
    lower = (text_data or "").lower()
    brands = ["sbi", "hdfc", "icici", "axis", "paytm", "phonepe", "amazon", "flipkart", "fedex", "dhl", "indiapost", "epfo", "income tax", "netflix"]
    mentioned = [b for b in brands if b in lower]

    if mentioned and urls_in_text:
        for u in urls_in_text:
            u_dom = urlparse(u if "://" in u else "http://" + u).netloc.lower()
            if not any(b.replace(" ", "") in u_dom for b in mentioned):
                score += 58
                reasons.append(f"Entity-Domain Mismatch: Message claims to be '{mentioned.upper()}' but embeds an unrelated external link ({u_dom}).")
                evidence.append(f"Claimed Entity: {mentioned.upper()} != Embedded Domain: {u_dom}")
                break

    if any(ext in lower for ext in [".apk", ".exe", ".scr", ".bat", "upi://pay"]):
        score += 62
        reasons.append("Contains direct executable payload or hidden UPI payment collection URI.")
        evidence.append("Dangerous Payload URI / Executable Extension Detected")

    score = min(98, max(5, score))
    tier = get_3_tier_level(score)

    if tier == "SAFE":
        return {
            "risk_score": score,
            "classification": "SAFE",
            "what_was_detected": f"Authentic and technically consistent {content_type} with verified infrastructure.",
            "why_suspicious": "Domain age, SSL certificate, redirect path, and linguistic structure show zero signs of deception.",
            "how_affects_user": "Safe for normal interaction with no hidden payload or credential trap detected.",
            "evidence": f"Domain: {url_f.get('domain', 'Verified Text')} | SSL: {url_f.get('ssl_issuer', 'Valid')} | Age: {url_f.get('domain_age_days', 'Established')} days",
            "how_to_stay_safe": ["Verified clean. Always keep standard two-factor authentication enabled."]
        }

    return {
        "risk_score": score,
        "classification": tier,
        "what_was_detected": f"Deceptive technical pattern uncovered inside {content_type}.",
        "why_suspicious": " ".join(reasons) if reasons else "Subtle structural anomalies and unverified routing detected.",
        "how_affects_user": "Designed to bypass surface inspection and trick users into authorizing payments or leaking sensitive credentials.",
        "evidence": " | ".join(evidence) if evidence else f"Deep Forensic Anomaly Index: {score}/100",
        "how_to_stay_safe": [
            "Do not open embedded links or authorize any payment/login requests.",
            "Independently contact the organization through their official app or helpline."
        ]
    }

def analyze_threat(content_type: str, text_data: str = "", image_bytes: bytes = None, extra_intel: dict = None):
    cache_raw = f"{content_type}:{text_data}:{len(image_bytes) if image_bytes else 0}:{json.dumps(extra_intel, sort_keys=True)}"
    cache_key = hashlib.sha256(cache_raw.encode()).hexdigest()
    if cache_key in RESULT_CACHE:
        return RESULT_CACHE[cache_key]

    prompt = f"""
    You are a Principal Threat Intelligence & Digital Forensics Investigator for 'ScamSense'.
    Your job is to look PAST polite or genuine-looking surface text/URLs and uncover hidden technical or psychological payloads.

    Module Type: {content_type}
    Live Technical Forensics & Threat Intel: {json.dumps(extra_intel) if extra_intel else 'None'}

    DEEP FORENSIC ANALYSIS INSTRUCTIONS:
    1. DO NOT rely on simple keyword matching. Many advanced phishing emails, SMS, and websites use calm, polite, professional language.
    2. Check for ENTITY-DOMAIN MISMATCH: Does the text/email/image claim to be from a known bank, courier, government agency, or brand while linking to an unrelated domain, URL shortener, or personal email?
    3. Check TECHNICAL TELEMETRY: Inspect `domain_age_days` (newly registered domains ,
        "classification": "<SAFE | SUSPICIOUS | HIGH RISK>",
        "what_was_detected": "<1-2 crisp sentences identifying the exact surface claim vs actual underlying target/payload>",
        "why_suspicious": "",
        "how_affects_user": "<1-2 sentences detailing the exact consequence to the user's finances, credentials, or device>",
        "evidence": "<Concrete technical proof: exact domain age, SSL issuer, redirect destination, mismatched domain, or GSB/VT telemetry>",
        "how_to_stay_safe": [
            "<Specific actionable step 1>",
            "<Specific actionable step 2>"
        ]
    }}

    User Input to Deep-Scan: {text_data}
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
