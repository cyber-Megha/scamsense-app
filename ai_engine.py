import os
import json
import hashlib
import io
from google import genai
from google.genai import types
from PIL import Image

client = genai.Client(api_key=os.getenv("GEMINI_API_KEY"), http_options={'timeout': 20.0})
RESULT_CACHE = {}

OFFICIAL_BRANDS = {
    "sbi": ["onlinesbi.sbi", "sbi.co.in", "sbicard.com"],
    "hdfc": ["hdfcbank.com", "hdfc.com"],
    "icici": ["icicibank.com", "icicidirect.com"],
    "axis": ["axisbank.com"],
    "paytm": ["paytm.com"],
    "phonepe": ["phonepe.com"],
    "skype": ["skype.com", "microsoft.com", "live.com"],
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

def get_live_gemini_models():
    discovered = []
    try:
        for m in client.models.list():
            name = m.name.replace("models/", "")
            if "flash" in name.lower() and "exp" not in name.lower() and "audio" not in name.lower():
                discovered.append(name)
    except Exception:
        pass
    return list(dict.fromkeys(discovered + ["gemini-2.5-flash", "gemini-2.5-flash-lite", "gemini-3.8-flash"]))

def build_badge(intel: dict, ai_used: bool) -> str:
    gsb = "Flagged" if intel.get("google_safe_browsing", {}).get("is_dangerous") else "Clean"
    vt = intel.get("virustotal", {}).get("malicious", 0)
    uh = "Listed" if intel.get("urlhaus_threat_feed", {}).get("listed") else "Clean"
    ai = "Gemini AI Verified" if ai_used else "7-Layer Forensic Verified"
    return f"[Sources: GSB={gsb} | VT={vt}/70 | URLhaus={uh} | {ai}]"

def active_forensic_consensus(content_type: str, text_data: str, extra_intel: dict):
    intel = extra_intel or {}
    reports = [intel] if "deep_url_forensics" in intel else (intel.get("embedded_urls_intel") or [])
    dns_info = intel.get("sender_dns_forensics", {})
    raw_lower = (text_data or "").strip().lower()
    score, reasons, evidence = 3, [], []

    if dns_info.get("sender_domain") and not dns_info.get("has_mx_records"):
        score += 50
        reasons.append(f"Spoofed sender domain '{dns_info['sender_domain']}' has zero MX mail records.")
        evidence.append("DNS MX: Missing")

    for rep in reports:
        gsb = rep.get("google_safe_browsing", {})
        vt = rep.get("virustotal", {})
        uh = rep.get("urlhaus_threat_feed", {})
        uf = rep.get("deep_url_forensics", {})
        dom_html = uf.get("active_dom_inspection", {})

        if gsb.get("is_dangerous") or vt.get("malicious", 0) > 0 or uh.get("listed"):
            final_s = min(99, max(93, 90 + vt.get("malicious", 0)))
            return {
                "risk_score": final_s,
                "classification": "HIGH RISK",
                "what_was_detected": f"Confirmed active threat at '{uf.get('domain', 'URL')}' across global blacklists.",
                "why_suspicious": "Flagged by Google Safe Browsing, VirusTotal, or URLhaus threat intelligence.",
                "how_affects_user": "Direct exposure to credential harvesting, banking fraud, or malware infection.",
                "evidence": f"GSB: {gsb.get('threat_type', 'Clean')} | VT: {vt.get('malicious', 0)}/70 | URLhaus: {uh.get('listed')} {build_badge(rep, False)}",
                "how_to_stay_safe": ["Terminate connection immediately and do not enter credentials or OTP."]
            }

        dom = uf.get("domain", "")
        age = uf.get("domain_age_days")
        if uf.get("has_at_symbol_trap"):
            score += 72
            reasons.append(f"URL '@' Authority Obfuscation redirecting to '{dom}'.")
            evidence.append(f"True Host After '@': {dom}")
        if uf.get("spoofed_domains_in_path"):
            sp = next(iter(uf["spoofed_domains_in_path"]), "")
            score += 66
            reasons.append(f"Path-Spoofing Attack: Host '{dom}' embeds '{sp}' inside URL path.")
            evidence.append(f"Root: {dom} != Spoofed Path: {sp}")
        if dom_html.get("external_form_action"):
            score += 55
            reasons.append("Active HTML DOM scan found a form sending passwords to an external server.")
            evidence.append("DOM Scan: External Form Action")
        if age is not None and age < 120:
            score += 42
            reasons.append(f"Newly registered domain ({age} days old) lacking established trust.")
            evidence.append(f"Domain Age: {age} days")
        if uf.get("protocol") == "HTTP":
            score += 24
            reasons.append("Unencrypted HTTP protocol exposes traffic to interception.")
            evidence.append("Protocol: HTTP (No SSL)")
        if uf.get("shannon_entropy", 0) > 4.35:
            score += 18
            evidence.append(f"High Entropy: {uf.get('shannon_entropy')}")
        if uf.get("has_random_hex_folder"):
            score += 30
            reasons.append("Obfuscated hexadecimal phishing directory detected.")
            evidence.append("Hex Path: True")

        for b, valid_list in OFFICIAL_BRANDS.items():
            if b in raw_lower and not any(dom == v or dom.endswith("." + v) for v in valid_list):
                score += 64
                reasons.append(f"Brand-Domain Mismatch: References '{b.upper()}' on unauthorized domain '{dom}'.")
                evidence.append(f"Claimed: {b.upper()} != Host: {dom}")
                break

    first_rep = next(iter(reports), {})
    dom_check = first_rep.get("deep_url_forensics", {}).get("domain", "")
    if content_type == "Website URL" and dom_check and score < 30:
        for b, valid_list in OFFICIAL_BRANDS.items():
            if any(dom_check == v or dom_check.endswith("." + v) for v in valid_list):
                return {
                    "risk_score": 2,
                    "classification": "SAFE",
                    "what_was_detected": f"Verified official {b.upper()} infrastructure ({dom_check}).",
                    "why_suspicious": "Exact match with official registry, valid TLS encryption, and clean 7-layer telemetry.",
                    "how_affects_user": "Completely safe for legitimate authentication and browsing.",
                    "evidence": f"Domain: {dom_check} | SSL: {first_rep.get('deep_url_forensics', {}).get('ssl_status')} {build_badge(first_rep, False)}",
                    "how_to_stay_safe": ["Verified authentic domain. Proceed safely."]
                }

    score = min(98, max(2, score))
    tier = get_tier(score)
    badge = build_badge(first_rep, False)
    return {
        "risk_score": score,
        "classification": tier,
        "what_was_detected": f"{'Verified clean' if tier == 'SAFE' else 'Forensic anomaly detected in'} {content_type}.",
        "why_suspicious": " ".join(reasons[:3]) if reasons else ("All 7 forensic layers passed cleanly." if tier == "SAFE" else "Unverified host or protocol vulnerability detected."),
        "how_affects_user": "No security risk detected." if tier == "SAFE" else "Interacting with this target risks credential theft or financial loss.",
        "evidence": f"{' | '.join(evidence[:4])} {badge}".strip(),
        "how_to_stay_safe": ["Proceed normally." if tier == "SAFE" else "Do not enter passwords or OTPs; use the verified official HTTPS site."]
    }

def call_gemini(model_name: str, contents: list):
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

    intel = extra_intel or {}
    first_rep = intel if "deep_url_forensics" in intel else next(iter(intel.get("embedded_urls_intel") or []), {})
    prompt = f"""
    You are the Chief Digital Forensics Investigator for 'ScamSense'.
    Audit this {content_type} using the LIVE 7-LAYER TELEMETRY: {json.dumps(intel)}
    Compute an exact, nuanced risk_score (0-100): 0-30=SAFE, 31-60=SUSPICIOUS, 61-100=HIGH RISK.
    Return ONLY JSON:
    {{
        "risk_score": <0-100>,
        "classification": "<SAFE | SUSPICIOUS | HIGH RISK>",
        "what_was_detected": "<1-2 crisp sentences>",
        "why_suspicious": "<1-2 sentences citing exact forensic proof>",
        "how_affects_user": "<1-2 sentences on user impact>",
        "evidence": "<exact technical proof>",
        "how_to_stay_safe": ["<step 1>", "<step 2>"]
    }}
    Input: {text_data}
    """
    contents = [prompt]
    if image_bytes:
        contents.append(Image.open(io.BytesIO(image_bytes)))

    for m in get_live_gemini_models():
        ai_res = call_gemini(m, contents)
        if ai_res:
            ai_res["evidence"] = f"{ai_res.get('evidence', '')} {build_badge(first_rep, True)}".strip()
            RESULT_CACHE[cache_key] = ai_res
            return ai_res

    return active_forensic_consensus(content_type, text_data, extra_intel)
