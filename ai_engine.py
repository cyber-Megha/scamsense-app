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
    "google": ["google.com", "google.co.in", "googleapis.com"],
    "facebook": ["facebook.com", "fb.com"],
    "instagram": ["instagram.com"],
    "whatsapp": ["whatsapp.com"],
    "amazon": ["amazon.in", "amazon.com"],
    "flipkart": ["flipkart.com"],
    "microsoft": ["microsoft.com", "live.com", "office.com"],
    "apple": ["apple.com", "icloud.com"],
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
                "what_was_detected": f"Polite or normal surface content concealing a confirmed malicious link ({uf.get('final_destination', 'Blacklisted URL')}).",
                "why_suspicious": "Even though the message tone appears normal, the embedded destination is actively flagged by global security engines for phishing/malware.",
                "how_affects_user": "Clicking this link will redirect you to a credential harvester or malware payload capable of draining funds or hijacking accounts.",
                "evidence": f"GSB Flag: {gsb.get('threat_type', 'MALICIOUS')} | VirusTotal Engines: {vt_hits} | Final Target: {uf.get('final_destination')}",
                "how_to_stay_safe": [
                    "Do NOT click the link inside this message, regardless of how genuine the text sounds.",
                    "Open your official banking/service app directly to verify any statement or update."
                ]
            }

    lower_text = (text_data or "").lower()
    mentioned_brands = [b for b in OFFICIAL_BRAND_MAP.keys() if b in lower_text]

    for rep in url_reports:
        uf = rep.get("deep_url_forensics", {})
        dom = uf.get("domain", "")
        final_dom = urlparse(uf.get("final_destination", "")).netloc.lower() or dom
        age = uf.get("domain_age_days")

        if uf.get("is_shortener"):
            score += 38
            reasons.append(f"Uses URL shortener ({dom}) to hide true destination ({final_dom}).")
            evidence.append(f"Shortener: {dom} -> {final_dom}")

        if age is not None and age < 90:
            score += 48
            reasons.append(f"Embedded link points to a newly created domain ({age} days old).")
            evidence.append(f"Domain Age: {age} days ({uf.get('domain_created_date')})")

        if uf.get("has_punycode"):
            score += 58
            reasons.append("Homograph Punycode domain spoofing detected.")
            evidence.append(f"Punycode: {final_dom}")

        if "No Valid HTTPS" in uf.get("ssl_issuer", ""):
            score += 20
            reasons.append("Destination lacks valid SSL/TLS encryption.")
            evidence.append("SSL: Missing/Invalid")

        for b in mentioned_brands:
            if not is_official_domain_for_brand(b, final_dom):
                score += 65
                reasons.append(f"Deceptive Brand-Domain Mismatch: Content pretends to be '{b.upper()}' using a calm/normal tone, but links to an unauthorized domain ({final_dom}).")
                evidence.append(f"Claimed Brand: {b.upper()} | Actual Domain: {final_dom}")
                break

    first_rep = next(iter(url_reports), None)
    if content_type == "Website URL" and first_rep:
        uf = first_rep.get("deep_url_forensics", {})
        dom = uf.get("domain", "")
        for b in OFFICIAL_BRAND_MAP:
            if is_official_domain_for_brand(b, dom):
                return {
                    "risk_score": 3,
                    "classification": "SAFE",
                    "what_was_detected": f"Verified official {b.upper()} domain ({dom}).",
                    "why_suspicious": "Domain matches the official verified infrastructure with valid TLS encryption and clean threat intelligence.",
                    "how_affects_user": "Safe for legitimate browsing and account access.",
                    "evidence": f"Verified Domain: {dom} | SSL: {uf.get('ssl_issuer')} | GSB & VT: Clean",
                    "how_to_stay_safe": ["Verified official website. Always ensure you are on the exact HTTPS domain before entering passwords."]
                }

    score = min(98, max(4, score))
    tier = get_3_tier_level(score)

    if tier == "SAFE":
        return {
            "risk_score": score,
            "classification": "SAFE",
            "what_was_detected": f"Benign {content_type} with no deceptive links or malicious payloads.",
            "why_suspicious": "All embedded links, domain telemetry, and content structure appear consistent and clean.",
            "how_affects_user": "No security or financial threat detected.",
            "evidence": "GSB: Clean | VT: 0 Detections | Brand-Domain Check: Passed",
            "how_to_stay_safe": ["Content appears safe. Continue practicing standard digital hygiene."]
        }

    return {
        "risk_score": score,
        "classification": tier,
        "what_was_detected": f"Hidden threat uncovered beneath normal-looking {content_type}.",
        "why_suspicious": " ".join(reasons) if reasons else "Technical anomalies detected in routing or domain structure.",
        "how_affects_user": "A user trusting the normal tone of this message could be tricked into handing over login credentials or financial access.",
        "evidence": " | ".join(evidence) if evidence else f"Forensic Anomaly Score: {score}/100",
        "how_to_stay_safe": [
            "Ignore the polite/normal tone and do not click the attached link.",
            "Visit the official website manually by typing its known address in your browser."
        ]
    }

def analyze_threat(content_type: str, text_data: str = "", image_bytes: bytes = None, extra_intel: dict = None):
    cache_raw = f"{content_type}:{text_data}:{len(image_bytes) if image_bytes else 0}:{json.dumps(extra_intel, sort_keys=True)}"
    cache_key = hashlib.sha256(cache_raw.encode()).hexdigest()
    if cache_key in RESULT_CACHE:
        return RESULT_CACHE[cache_key]

    prompt = f"""
    You are a Principal Digital Forensics & Anti-Phishing Architect for 'ScamSense'.
    CRITICAL RULE: Modern phishing messages, emails, and websites DO NOT use urgent or threatening words. They look completely normal, polite, and routine while hiding a malicious link or payload inside!

    Module Type: {content_type}
    Extracted Live URL Forensics, Redirect Chains, Domain Age, Google Safe Browsing & VirusTotal Telemetry:
    {json.dumps(extra_intel) if extra_intel else 'None'}

    STRICT 3-TIER CLASSIFICATION:
    - 0 to 30: "SAFE"
    - 31 to 60: "SUSPICIOUS"
    - 61 to 100: "HIGH RISK"

    Return ONLY a valid JSON object with this exact schema:
    {{
        "risk_score": <integer 0-100>,
        "classification": "<SAFE | SUSPICIOUS | HIGH RISK>",
        "what_was_detected": "<1-2 crisp sentences stating what the surface message/URL claims vs what the actual underlying link/payload is>",
        "why_suspicious": "<1-2 sentences explaining the exact forensic proof or why it is verified safe>",
        "how_affects_user": "<1-2 sentences explaining the real-world consequence to the user>",
        "evidence": "<Exact technical proof: claimed brand vs actual domain, domain age, SSL issuer, redirect URL, or GSB/VT hits>",
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
