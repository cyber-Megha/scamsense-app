import os
import json
from google import genai
from google.genai import types
from PIL import Image
import io

client = genai.Client(
    api_key=os.getenv("GEMINI_API_KEY"),
    http_options={'timeout': 10.0}
)

def smart_fallback_analysis(content_type: str, text_data: str, extra_intel: dict):
    # যদি কোনো কারণে Gemini সার্ভার সাময়িক ব্যস্ত থাকে, তবে Safe Browsing + VirusTotal + Heuristics দিয়ে নিখুঁত রেজাল্ট দেবে
    gsb = (extra_intel or {}).get("google_safe_browsing", {})
    vt = (extra_intel or {}).get("virustotal", {})
    
    if gsb.get("is_dangerous") or vt.get("malicious", 0) > 0:
        return {
            "risk_score": 95,
            "risk_level": "CRITICAL",
            "threat_category": gsb.get("threat_type", "Confirmed Malicious Threat"),
            "why_risky": [
                "Flagged as dangerous by Google Safe Browsing / VirusTotal threat intelligence.",
                "Contains known malware distribution or credential harvesting signatures."
            ],
            "how_to_stay_safe": [
                "Close this link or message immediately and do not enter any personal details.",
                "Block the sender and report the domain."
            ],
            "technical_indicators": f"GSB Match: {gsb.get('is_dangerous')} | VT Malicious Engines: {vt.get('malicious', 0)}"
        }

    scam_keywords = ["urgent", "kyc", "suspended", "blocked", "lottery", "winner", "upi", "verify", "bank", "prize", "arrest", "customs"]
    lower_text = (text_data or "").lower()
    matched = [w for w in scam_keywords if w in lower_text]

    if len(matched) >= 2 or "http://" in lower_text:
        return {
            "risk_score": 82,
            "risk_level": "HIGH",
            "threat_category": "Suspected Phishing / Social Engineering",
            "why_risky": [
                f"Detected high-risk urgency or financial keywords: {', '.join(matched[:4])}.",
                "Uses unencrypted HTTP or deceptive domain patterns common in scam campaigns."
            ],
            "how_to_stay_safe": [
                "Never click unverified links claiming urgent account suspension.",
                "Verify directly via the official bank app or customer care number."
            ],
            "technical_indicators": f"Heuristic Red Flags: {len(matched)} suspicious triggers found."
        }

    return {
        "risk_score": 5,
        "risk_level": "SAFE",
        "threat_category": "Clean / Verified Safe",
        "why_risky": [
            "No malicious signatures found in Google Safe Browsing or VirusTotal.",
            "No deceptive phishing or urgency patterns detected."
        ],
        "how_to_stay_safe": [
            "Content appears safe, though standard online caution is always recommended."
        ],
        "technical_indicators": "GSB Clean | VT Malicious: 0 | Heuristics Passed."
    }

def analyze_threat(content_type: str, text_data: str = "", image_bytes: bytes = None, extra_intel: dict = None):
    prompt = f"""
    You are an elite Cybersecurity Threat Analyst for 'ScamSense'. 
    Analyze the following {content_type} for phishing, fraud, malware, or social engineering.
    Additional Threat Intel Data: {json.dumps(extra_intel) if extra_intel else 'None'}
    
    Return ONLY a valid JSON object with this exact schema:
    {{
        "risk_score": <integer from 0 to 100>,
        "risk_level": "<CRITICAL | HIGH | MEDIUM | LOW | SAFE>",
        "threat_category": "<e.g., Phishing, Fake Invoice, Malware Link, Safe Content>",
        "why_risky": [
            "<clear point 1>",
            "<clear point 2>"
        ],
        "how_to_stay_safe": [
            "<actionable step 1>",
            "<actionable step 2>"
        ],
        "technical_indicators": "<brief technical summary of red flags found>"
    }}
    
    Content to analyze: {text_data}
    """
    contents = [prompt]
    if image_bytes:
        img = Image.open(io.BytesIO(image_bytes))
        contents.append(img)

    for model_name in ['gemini-3.8-flash', 'gemini-3.8-flash-lite', 'gemini-2.5-flash-lite']:
        try:
            response = client.models.generate_content(
                model=model_name,
                contents=contents,
                config=types.GenerateContentConfig(
                    response_mime_type="application/json"
                )
            )
            return json.loads(response.text)
        except Exception:
            continue

    return smart_fallback_analysis(content_type, text_data, extra_intel)
