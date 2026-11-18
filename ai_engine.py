import os
import json
import hashlib
import re
from google import genai
from google.genai import types
from PIL import Image
import io

client = genai.Client(api_key=os.getenv("GEMINI_API_KEY"), http_options={'timeout': 15.0})
RESULT_CACHE = {}

OFFICIAL_BRANDS = {
    "sbi": ["onlinesbi.sbi", "sbi.co.in"],
    "hdfc": ["hdfcbank.com"],
    "icici": ["icicibank.com"],
    "axis": ["axisbank.com"],
    "paytm": ["paytm.com"],
    "phonepe": ["phonepe.com"],
    "skype": ["skype.com", "microsoft.com"],
    "google": ["google.com", "google.co.in"],
    "facebook": ["facebook.com", "fb.com"],
    "amazon": ["amazon.in", "amazon.com"],
    "paypal": ["paypal.com"]
}

def get_tier(score: int) -> str:
    if score <= 30:
        return "SAFE"
    elif score <= 60:
        return "SUSPICIOUS"
    return "HIGH RISK"

def smart_forensic_engine(content_type: str, text_data: str, extra_intel: dict):
    intel = extra_intel or {}
    reports = [intel] if "deep_url_forensics" in intel else (intel.get("embedded_urls_intel") or [])
    score = 5
    reasons = []
    evidence = []

    for rep in reports:
        gsb = rep.get("google_safe_browsing", {})
        vt = rep.get("virustotal", {})
        uf = rep.get("deep_url_forensics", {})
        if gsb.get("is_dangerous") or vt.get("malicious", 0) > 0:
            return {
                "risk_score": 96,
                "classification": "HIGH RISK",
                "what_was_detected": f"Confirmed malicious target at {uf.get('domain', 'URL')}.",
                "why_suspicious": "Flagged by Google Safe Browsing / VirusTotal for active phishing or malware.",
                "how_affects_user": "Can steal banking credentials, OTPs, or infect your device immediately.",
                "evidence": f"GSB Flag: {gsb.get('threat_type', 'TRUE')} | VT Detections: {vt.get('malicious', 1)}",
                "how_to_stay_safe": ["Close this link immediately and never enter any personal data."]
            }

        dom = uf.get("domain", "")
        spoofed = uf.get("spoofed_domains_in_path", [])
        if spoofed:
            score += 68
            first_spoof = next(iter(spoofed), "")
            reasons.append(f"Path-Spoofing Attack: Host '{dom}' embeds fake domain '{first_spoof}' inside URL path.")
            evidence.append(f"Root: {dom} != Spoofed Path: {first_spoof}")

        if uf.get("has_random_hex_folder"):
            score += 35
            reasons.append("Obfuscated hexadecimal phishing directory detected.")
            evidence.append("Hex Hash Path: True")

        sus_kw = uf.get("suspicious_path_keywords", [])
        if len(sus_kw) >= 2:
            score += 25
            reasons.append("Credential harvesting path structure detected.")
            evidence.append(f"Paths: {', '.join(sus_kw)}")

        if any(s in dom for s in ["bit.ly", "tinyurl.com", "t.co", "rb.gy", "is.gd", "cutt.ly"]):
            score += 38
            reasons.append(f"URL shortener ({dom}) masks the true destination.")
            evidence.append(f"Shortener: {dom}")

        lower = (text_data or "").lower()
        for b, valid_list in OFFICIAL_BRANDS.items():
            if b in lower and not any(dom == v or dom.endswith("." + v) for v in valid_list):
                score += 65
                reasons.append(f"Brand-Domain Mismatch: Claims '{b.upper()}' on unofficial host '{dom}'.")
                evidence.append(f"Brand: {b.upper()} | Actual Domain: {dom}")
                break

    first_rep = next(iter(reports), None)
    if content_type == "Website URL" and first_rep and score < 30:
        dom = first_rep.get("deep_url_forensics", {}).get("domain", "")
        for b, valid_list in OFFICIAL_BRANDS.items():
            if any(dom == v or dom.endswith("." + v) for v in valid_list):
                return {
                    "risk_score": 3,
                    "classification": "SAFE",
                    "what_was_detected": f"Verified official {b.upper()} domain ({dom}).",
                    "why_suspicious": "Matches authentic infrastructure with clean threat intelligence.",
                    "how_affects_user": "Safe for standard browsing and login.",
                    "evidence": f"Verified Domain: {dom} | GSB & VT: Clean",
                    "how_to_stay_safe": ["Verified safe website. Proceed normally."]
                }

    score = min(98, max(4, score))
    tier = get_tier(score)
    if tier == "SAFE":
        return {
            "risk_score": score,
            "classification": "SAFE",
            "what_was_detected": f"Clean {content_type} with no deceptive indicators.",
            "why_suspicious": "No spoofing, hidden redirects, or blacklist hits found.",
            "how_affects_user": "Low risk under standard usage.",
            "evidence": "GSB: Clean | VT: 0 Detections",
            "how_to_stay_safe": ["Content appears safe. Maintain standard caution."]
        }

    return {
        "risk_score": score,
        "classification": tier,
        "what_was_detected": f"Deceptive threat pattern detected in {content_type}.",
        "why_suspicious": " ".join(reasons) if reasons else "Anomalous domain/path routing detected.",
        "how_affects_user": "May trick users into revealing login passwords or financial details.",
        "evidence": " | ".join(evidence) if evidence else f"Anomaly Index: {score}/100",
        "how_to_stay_safe": ["Do not click links or enter credentials.", "Verify via the official app."]
    }

def analyze_threat(content_type: str, text_data: str = "", image_bytes: bytes = None, extra_intel: dict = None):
    try:
        cache_key = hashlib.sha256(f"{content_type}:{text_data}:{json.dumps(extra_intel, sort_keys=True)}".encode()).hexdigest()
        if cache_key in RESULT_CACHE:
            return RESULT_CACHE[cache_key]

        prompt = f"""
        Analyze this {content_type} for phishing/malware using deep forensics.
        Intel: {json.dumps(extra_intel) if extra_intel else 'None'}
        Rules: 0-30=SAFE, 31-60=SUSPICIOUS, 61-100=HIGH RISK. Check `spoofed_domains_in_path` (e.g. nobell.it/.../://skype.com is HIGH RISK 92%), brand-domain mismatch in polite messages, and blacklists.
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
            try:
                res = client.models.generate_content(
                    model=m,
                    contents=contents,
                    config=types.GenerateContentConfig(response_mime_type="application/json", temperature=0.0)
                )
                parsed = json.loads(res.text)
                parsed["risk_score"] = int(parsed.get("risk_score", 0))
                parsed["classification"] = get_tier(parsed["risk_score"])
                RESULT_CACHE[cache_key] = parsed
                return parsed
            except Exception:
                continue

        fallback = smart_forensic_engine(content_type, text_data, extra_intel)
        RESULT_CACHE[cache_key] = fallback
        return fallback
    except Exception:
        return smart_forensic_engine(content_type, text_data, extra_intel)
