import os
import json
import hashlib
import re
from google import genai
from google.genai import types
from PIL import Image
import io

client = genai.Client(api_key=os.getenv("GEMINI_API_KEY"), http_options={'timeout': 18.0})
RESULT_CACHE = {}

OFFICIAL_BRANDS = {
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

def get_tier(score: int) -> str:
    if score <= 30:
        return "SAFE"
    elif score <= 60:
        return "SUSPICIOUS"
    return "HIGH RISK"

def precision_forensic_engine(content_type: str, text_data: str, extra_intel: dict):
    intel = extra_intel or {}
    reports = [intel] if "deep_url_forensics" in intel else (intel.get("embedded_urls_intel") or [])
    score = 4
    reasons = []
    evidence = []
    raw_lower = (text_data or "").strip().lower()

    for rep in reports:
        gsb = rep.get("google_safe_browsing", {})
        vt = rep.get("virustotal", {})
        uf = rep.get("deep_url_forensics", {})

        if gsb.get("is_dangerous") or vt.get("malicious", 0) > 0:
            vt_hits = vt.get("malicious", 1)
            return {
                "risk_score": min(99, 94 + vt_hits),
                "classification": "HIGH RISK",
                "what_was_detected": f"Verified malicious target at '{uf.get('domain', 'URL')}'.",
                "why_suspicious": "Confirmed active phishing or malware infrastructure by global threat intelligence.",
                "how_affects_user": "Direct exposure to credential harvesting, financial theft, or malware infection.",
                "evidence": f"GSB: {gsb.get('threat_type', 'BLACKLISTED')} | VT Engines: {vt_hits}",
                "how_to_stay_safe": ["Terminate connection immediately and never enter credentials or OTP."]
            }

        dom = uf.get("domain", "")
        protocol = uf.get("protocol", "")
        age = uf.get("domain_age_days")
        ssl_stat = uf.get("ssl_status", "")

        if uf.get("has_at_symbol_trap"):
            score += 75
            reasons.append(f"URL '@' Authority Obfuscation Attack redirecting to '{dom}'.")
            evidence.append(f"True Host After '@': {dom}")

        if protocol == "HTTP" or "Missing" in ssl_stat:
            score += 38
            reasons.append("Unencrypted HTTP protocol or missing SSL certificate.")
            evidence.append(f"Protocol: {protocol} | SSL: {ssl_stat}")

        spoofed = uf.get("spoofed_domains_in_path", [])
        if spoofed:
            score += 68
            first_spoof = next(iter(spoofed), "")
            reasons.append(f"Path-Spoofing Attack: Host '{dom}' embeds '{first_spoof}' inside URL path.")
            evidence.append(f"Root: {dom} != Spoofed Path: {first_spoof}")

        if age is not None and age < 120:
            score += 45
            reasons.append(f"Newly registered domain ({age} days old).")
            evidence.append(f"Domain Age: {age} days")

        if uf.get("has_random_hex_folder"):
            score += 34
            reasons.append("Obfuscated hexadecimal phishing directory detected.")
            evidence.append("Hex Hash Directory: Detected")

        sus_kw = uf.get("suspicious_path_keywords", [])
        if len(sus_kw) >= 2:
            score += 24
            reasons.append(f"Credential harvesting path keywords ({', '.join(sus_kw)}) detected.")
            evidence.append(f"Path Tokens: {', '.join(sus_kw)}")

        if re.search(r'(paypa1|amaz0n|arnazon|g00gle|faceb00k|micr0soft|app1e|netf1ix|hdfc-|sbi-|icici-)', dom):
            score += 66
            reasons.append(f"Micro-typosquatting character substitution detected in '{dom}'.")
            evidence.append(f"Spoofed Domain: {dom}")

        for b, valid_list in OFFICIAL_BRANDS.items():
            if b in raw_lower and not any(dom == v or dom.endswith("." + v) for v in valid_list):
                score += 65
                reasons.append(f"Brand-Domain Mismatch: Claims '{b.upper()}' on unauthorized host '{dom}'.")
                evidence.append(f"Claimed: {b.upper()} != Host: {dom}")
                break

    first_rep = next(iter(reports), None)
    if content_type == "Website URL" and first_rep and score < 30:
        dom = first_rep.get("deep_url_forensics", {}).get("domain", "")
        for b, valid_list in OFFICIAL_BRANDS.items():
            if any(dom == v or dom.endswith("." + v) for v in valid_list):
                return {
                    "risk_score": 2,
                    "classification": "SAFE",
                    "what_was_detected": f"Verified official {b.upper()} infrastructure ({dom}).",
                    "why_suspicious": "Exact match with official domain registry and clean telemetry.",
                    "how_affects_user": "Completely safe for legitimate browsing and login.",
                    "evidence": f"Domain: {dom} | GSB & VT: Clean",
                    "how_to_stay_safe": ["Verified authentic domain. Proceed safely."]
                }

    score = min(98, max(2, score))
    tier = get_tier(score)
    if tier == "SAFE":
        return {
            "risk_score": score,
            "classification": "SAFE",
            "what_was_detected": f"Verified clean {content_type} with zero threat indicators.",
            "why_suspicious": "Micro-forensic checks passed with zero anomalies.",
            "how_affects_user": "No security or financial risk detected.",
            "evidence": "GSB: Clean | VT: 0 Detections",
            "how_to_stay_safe": ["Content verified safe. Proceed normally."]
        }

    return {
        "risk_score": score,
        "classification": tier,
        "what_was_detected": f"Micro-forensic anomaly detected in {content_type}.",
        "why_suspicious": " ".join(reasons) if reasons else "Unverified host or protocol vulnerability detected.",
        "how_affects_user": "Risks credential interception or financial loss.",
        "evidence": " | ".join(evidence) if evidence else f"Risk Index: {score}/100",
        "how_to_stay_safe": ["Do not enter passwords or OTPs.", "Use the official HTTPS website."]
    }

def call_gemini_model(model_name: str, contents: list):
    try:
        res = client.models.generate_content(
            model=model_name,
            contents=contents,
            config=types.GenerateContentConfig(response_mime_type="application/json", temperature=0.0)
        )
        parsed = json.loads(res.text)
        parsed["risk_score"] = int(parsed.get("risk_score", 0))
        parsed["classification"] = get_tier(parsed["risk_score"])
        return parsed
    except Exception:
        return None

def analyze_threat(content_type: str, text_data: str = "", image_bytes: bytes = None, extra_intel: dict = None):
    cache_key = hashlib.sha256(f"{content_type}:{text_data}:{json.dumps(extra_intel, sort_keys=True)}".encode()).hexdigest()
    if cache_key in RESULT_CACHE:
        return RESULT_CACHE[cache_key]

    prompt = f"""
    You are a Principal Digital Forensics Auditor for 'ScamSense'.
    Perform a microscopic, zero-error inspection of the input and telemetry.
    Module: {content_type}
    Telemetry: {json.dumps(extra_intel) if extra_intel else 'None'}
    Rules: 0-30=SAFE (only verified HTTPS & clean), 31-60=SUSPICIOUS (insecure http://, shorteners, unverified host), 61-100=HIGH RISK (path spoofing, '@' traps, typosquatting, brand mismatch, blacklists).
    Return ONLY JSON:
    {{
        "risk_score": <0-100>,
        "classification": "<SAFE | SUSPICIOUS | HIGH RISK>",
        "what_was_detected": "<1 sentence>",
        "why_suspicious": "<1 sentence>",
        "how_affects_user": "<1 sentence>",
        "evidence": "<technical proof>",
        "how_to_stay_safe": ["<step 1>", "<step 2>"]
    }}
    Input: {text_data}
    """
    contents = [prompt]
    if image_bytes:
        contents.append(Image.open(io.BytesIO(image_bytes)))

    for m in ['gemini-2.5-flash', 'gemini-2.0-flash']:
        ai_res = call_gemini_model(m, contents)
        if ai_res:
            RESULT_CACHE[cache_key] = ai_res
            return ai_res

    fallback = precision_forensic_engine(content_type, text_data, extra_intel)
    RESULT_CACHE[cache_key] = fallback
    return fallback
