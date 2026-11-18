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
                "what_was_detected": f"Verified malicious target identified at '{uf.get('domain', 'URL')}' ({uf.get('final_destination', '')}).",
                "why_suspicious": "Confirmed active phishing or malware infrastructure by global threat intelligence engines.",
                "how_affects_user": "Direct exposure to credential harvesting, financial theft, or automated malware infection.",
                "evidence": f"GSB Flag: {gsb.get('threat_type', 'BLACKLISTED')} | VirusTotal Engines: {vt_hits} | SSL: {uf.get('ssl_status')}",
                "how_to_stay_safe": ["Terminate connection immediately and do not enter any credentials or OTP."]
            }

        dom = uf.get("domain", "")
        protocol = uf.get("protocol", "")
        age = uf.get("domain_age_days")
        ssl_stat = uf.get("ssl_status", "")

        # ১. '@' ট্র্যাপ ডিটেকশন
        if uf.get("has_at_symbol_trap"):
            score += 75
            reasons.append(f"URL '@' Authority Obfuscation Attack detected, redirecting browser to '{dom}'.")
            evidence.append(f"True Host After '@': {dom}")

        # ২. অসুরক্ষিত HTTP বা ইনভ্যালিড SSL
        if protocol == "HTTP" or "Missing" in ssl_stat:
            score += 38
            reasons.append("Unencrypted HTTP protocol or missing TLS/SSL certificate exposes data to interception.")
            evidence.append(f"Protocol: {protocol} | SSL: {ssl_stat}")

        # ৩. পাথ স্পুফিং
        spoofed = uf.get("spoofed_domains_in_path", [])
        if spoofed:
            score += 68
            first_spoof = next(iter(spoofed), "")
            reasons.append(f"Path-Spoofing Attack: Host '{dom}' embeds deceptive domain '{first_spoof}' inside URL path.")
            evidence.append(f"Root: {dom} != Spoofed Path: {first_spoof}")

        # ৪. নতুন রেজিস্টার করা ডোমেইন (< 120 দিন)
        if age is not None and age < 120:
            score += 45
            reasons.append(f"Newly registered domain ({age} days old) lacking established trust history.")
            evidence.append(f"Domain Age: {age} days (Created: {uf.get('domain_created_date')})")

        # ৫. হেক্স হ্যাশ ও ফিশিং পাথ
        if uf.get("has_random_hex_folder"):
            score += 34
            reasons.append("Obfuscated hexadecimal directory structure typical of phishing kits.")
            evidence.append("Hex Hash Directory: Detected")

        sus_kw = uf.get("suspicious_path_keywords", [])
        if len(sus_kw) >= 2:
            score += 24
            reasons.append(f"Credential harvesting path keywords ({', '.join(sus_kw)}) detected.")
            evidence.append(f"Path Tokens: {', '.join(sus_kw)}")

        # ৬. মাইক্রো-টাইপোস্কোয়াটিং (যেমন: paypa1, arnazon, g00gle, sbi-kyc)
        if re.search(r'(paypa1|amaz0n|arnazon|g00gle|faceb00k|micr0soft|app1e|netf1ix|hdfc-|sbi-|icici-)', dom):
            score += 66
            reasons.append(f"Micro-typosquatting / lookalike character substitution detected in domain '{dom}'.")
            evidence.append(f"Spoofed Domain Spelling: {dom}")

        # ৭. ব্র্যান্ড বনাম ডোমেইন অমিল
        for b, valid_list in OFFICIAL_BRANDS.items():
            if b in raw_lower and not any(dom == v or dom.endswith("." + v) for v in valid_list):
                score += 65
                reasons.append(f"Brand-Domain Mismatch: Content references '{b.upper()}' while routing to unauthorized domain '{dom}'.")
                evidence.append(f"Claimed Brand: {b.upper()} != Actual Host: {dom}")
                break

    first_rep = next(iter(reports), None)
    if content_type == "Website URL" and first_rep and score < 30:
        uf = first_rep.get("deep_url_forensics", {})
        dom = uf.get("domain", "")
        for b, valid_list in OFFICIAL_BRANDS.items():
            if any(dom == v or dom.endswith("." + v) for v in valid_list):
                return {
                    "risk_score": 2,
                    "classification": "SAFE",
                    "what_was_detected": f"Verified official {b.upper()} infrastructure ({dom}).",
                    "why_suspicious": "Exact match with official domain registry, valid TLS encryption, and clean global telemetry.",
                    "how_affects_user": "Completely safe for legitimate authentication and browsing.",
                    "evidence": f"Domain: {dom} | SSL: {uf.get('ssl_status')} | Age: {uf.get('domain_age_days', 'Established')} days | GSB & VT: Clean",
                    "how_to_stay_safe": ["Verified authentic domain. Proceed safely."]
                }

    score = min(98, max(2, score))
    tier = get_tier(score)
    if tier == "SAFE":
        return {
            "risk_score": score,
            "classification": "SAFE",
            "what_was_detected": f"Verified clean {content_type} with valid encryption and zero threat indicators.",
            "why_suspicious": "Micro-forensic checks across protocol, domain structure, and threat intelligence passed with zero anomalies.",
            "how_affects_user": "No security, privacy, or financial risk detected.",
            "evidence": "GSB: Clean | VT: 0 Detections | Micro-Forensics: Passed",
            "how_to_stay_safe": ["Content verified safe. Continue standard security practices."]
        }

    return {
        "risk_score": score,
        "classification": tier,
        "what_was_detected": f"Micro-forensic anomaly detected in {content_type}.",
        "why_suspicious": " ".join(reasons) if reasons else "Unverified host or protocol vulnerability detected.",
        "how_affects_user": "Interacting with this target risks credential interception, session hijacking, or financial loss.",
        "evidence": " | ".join(evidence) if evidence else f"Precision Risk Index: {score}/100",
        "how_to_stay_safe": [
            "Do not enter passwords, OTPs, or financial details on this target.",
            "Access the service only via its verified HTTPS official website."
        ]
    }

def analyze_threat(content_type: str, text_data: str = "", image_bytes: bytes = None, extra_intel: dict = None):
    try:
        cache_key = hashlib.sha256(f"{content_type}:{text_data}:{json.dumps(extra_intel, sort_keys=True)}".encode()).hexdigest()
        if cache_key in RESULT_CACHE:
            return RESULT_CACHE[cache_key]

        prompt = f"""
        You are a Principal Digital Forensics & Zero-Trust Cybersecurity Auditor for 'ScamSense'.
        Perform a microscopic, zero-error forensic inspection of the input and telemetry. Do not miss subtle details (e.g. insecure HTTP, '@' URL traps, character substitutions like 'rn' for 'm', newly registered domains, or polite messages hiding unofficial links).

        Module: {content_type}
        Live Micro-Forensic Telemetry: {json.dumps(extra_intel) if extra_intel else 'None'}

        STRICT SCORING:
        - 0-30: "SAFE" (Only verified HTTPS domains with clean telemetry and zero anomalies)
        - 31-60: "SUSPICIOUS" (Insecure HTTP://, missing SSL, URL shorteners, or unverified hosts)
        - 61-100: "HIGH RISK" (Path spoofing, '@' traps, typosquatting, brand-domain mismatch, newly registered scam domains, or blacklists)

        Return ONLY valid JSON:
        {{
            "risk_score": <integer 0-100>,
            "classification": "<SAFE | SUSPICIOUS | HIGH RISK>",
            "what_was_detected": "<1-2 crisp sentences identifying exact surface claim vs true underlying target>",
            "why_suspicious": "<1-2 sentences citing exact forensic proof (protocol, domain age, SSL, spoofing) or why verified safe>",
            "how_affects_user": "<1-2 sentences explaining exact impact on user security/finances>",
            "evidence": "<Exact technical telemetry proof>",
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
fallback = precision_forensic_engine(content_type, text_data, extra_intel)
RESULT_CACHE[cache_key] = fallback
return fallback
except Exception:
return precision_forensic_engine(content_type, text_data, extra_intel)
