import os, json, hashlib, io, re, requests
from google import genai
from google.genai import types
from PIL import Image

GEMINI_KEY = os.getenv("GEMINI_API_KEY")
GROQ_KEY = os.getenv("GROQ_API_KEY")
OPENROUTER_KEY = os.getenv("OPENROUTER_API_KEY")

client = genai.Client(api_key=GEMINI_KEY, http_options={'timeout': 18.0}) if GEMINI_KEY else None
RESULT_CACHE = {}

def get_tier(score: int) -> str:
    if score <= 30: return "SAFE"
    elif score <= 60: return "SUSPICIOUS"
    return "HIGH RISK"

def parse_ai_json(raw_text: str):
    cleaned = raw_text.strip()
    if cleaned.startswith("```"):
        cleaned = re.sub(r"^```(?:json)?\s*|\s*```$", "", cleaned, flags=re.IGNORECASE).strip()
    parsed = json.loads(cleaned)
    parsed["risk_score"] = int(parsed.get("risk_score", 0))
    parsed["classification"] = get_tier(parsed["risk_score"])
    return parsed

def call_groq_ai(prompt: str):
    if not GROQ_KEY: return None
    try:
        r = requests.post(
            "https://groq.com",
            headers={"Authorization": f"Bearer {GROQ_KEY}", "Content-Type": "application/json"},
            json={
                "model": "llama-3.3-70b-versatile",
                "messages": [{"role": "user", "content": prompt}],
                "temperature": 0.0,
                "response_format": {"type": "json_object"}
            },
            timeout=14
        )
        if r.status_code == 200:
            first_choice = next(iter(r.json().get("choices", [])), {})
            content = first_choice.get("message", {}).get("content", "")
            if content: return parse_ai_json(content)
    except Exception: pass
    return None

def call_openrouter_ai(prompt: str):
    if not OPENROUTER_KEY: return None
    for model_id in ["meta-llama/llama-3.3-70b-instruct:free", "google/gemma-3-27b-it:free", "deepseek/deepseek-chat-v3-0324:free"]:
        try:
            r = requests.post(
                "https://openrouter.ai",
                headers={"Authorization": f"Bearer {OPENROUTER_KEY}", "Content-Type": "application/json"},
                json={"model": model_id, "messages": [{"role": "user", "content": prompt}], "temperature": 0.0},
                timeout=15
            )
            if r.status_code == 200:
                first_choice = next(iter(r.json().get("choices", [])), {})
                content = first_choice.get("message", {}).get("content", "")
                if content: return parse_ai_json(content)
        except Exception: continue
    return None

def call_gemini_ai(contents: list):
    if not client: return None
    for m in ["gemini-2.5-flash", "gemini-2.5-flash-lite"]:
        try:
            res = client.models.generate_content(
                model=m, contents=contents,
                config=types.GenerateContentConfig(response_mime_type="application/json", temperature=0.0)
            )
            return parse_ai_json(res.text)
        except Exception: continue
    return None

def backup_content_analyzer(content_type: str, text_data: str, extra_intel: dict):
    intel = extra_intel or {}
    rep = intel if "deep_url_forensics" in intel else next(iter(intel.get("embedded_urls_intel") or []), {})
    gsb = rep.get("google_safe_browsing", {}).get("is_dangerous", False)
    vt = rep.get("virustotal", {}).get("malicious", 0)
    uh = rep.get("urlhaus_threat_feed", {}).get("listed", False)
    uf = rep.get("deep_url_forensics", {})
    page = uf.get("live_page_content", {})
    dom = uf.get("domain", "Target")

    if gsb or vt > 0 or uh:
        return {
            "risk_score": 96, "classification": "HIGH RISK",
            "what_was_detected": f"Confirmed malicious target identified at '{dom}'.",
            "why_suspicious": "Actively flagged by global threat intelligence feeds for phishing or malware.",
            "how_affects_user": "Direct risk of credential theft, financial loss, or device compromise.",
            "evidence": f"Host: {dom} | Protocol: {uf.get('protocol', 'N/A')} | Threat Feed: Confirmed",
            "how_to_stay_safe": ["Close immediately and do not enter any personal or financial details."]
        }

    score = 15
    if page.get("asks_password_or_pin") and page.get("external_form_targets"): score = 88
    elif uf.get("has_at_symbol_trap"): score = 85
    elif uf.get("protocol") == "HTTP": score = 45
    elif page.get("visible_text_sample"): score = 18
    else: score = 42

    tier = get_tier(score)
    return {
        "risk_score": score, "classification": tier,
        "what_was_detected": f"Analyzed {content_type} ({dom}) — Title: '{page.get('page_title') or 'N/A'}'.",
        "why_suspicious": "Evaluated live page structure, form destinations, and domain consistency.",
        "how_affects_user": "Safe for normal viewing." if tier == "SAFE" else "Exercise caution before sharing credentials or sensitive data.",
        "evidence": f"Domain: {dom} | SSL: {uf.get('ssl_status', 'Checked')} | Password Form: {page.get('asks_password_or_pin', False)}",
        "how_to_stay_safe": ["Proceed safely." if tier == "SAFE" else "Verify the source before entering any sensitive information."]
    }

def analyze_threat(content_type: str, text_data: str = "", image_bytes: bytes = None, extra_intel: dict = None):
    cache_key = hashlib.sha256(f"{content_type}:{text_data}:{len(image_bytes) if image_bytes else 0}:{json.dumps(extra_intel, sort_keys=True)}".encode()).hexdigest()
    if cache_key in RESULT_CACHE: return RESULT_CACHE[cache_key]

    intel = extra_intel or {}
    prompt = f"""
    You are an elite, independent Senior Cybersecurity & Digital Forensics Investigator for 'ScamSense'.
    Do NOT make superficial judgments based solely on whether a domain is unfamiliar, uses HTTPS, or has a non-standard TLD.
    Instead, think deeply like a human forensic investigator by examining the ACTUAL LIVE CONTENT, INTENT, AND CONTEXT provided in the telemetry below:

    Input Type: {content_type}
    Live Extracted Content & Technical Telemetry: {json.dumps(intel)}

    HOW TO REASON INTELLIGENTLY:
    1. READ THE ACTUAL CONTENT (`live_page_content`, email body, message text, or image): What is this page or message actually doing?
       - If it is a genuine informational site, legitimate business/government portal (e.g., Salik toll service), personal blog, or benign document with no deception or credential harvesting -> classify as SAFE (1-28%), even if the TLD is uncommon.
       - If the content pretends to be a bank, courier, government agency, or brand, uses subtle spelling tricks (e.g., 'familly'), hosts a login/credential form on an unrelated domain or public cloud storage bucket, sends form data to an external server, or embeds a deceptive link inside a polite message -> classify as HIGH RISK (75-98%).
       - If the page blocks inspection, lacks clear identity while asking for user interaction, or shows ambiguous anomalies without confirmed malice -> classify as SUSPICIOUS (35-60%).
    2. Never mention any AI model names, API names, or internal tools.

    Return ONLY a valid JSON object:
    {{
        "risk_score": <integer 0-100>,
        "classification": "<SAFE | SUSPICIOUS | HIGH RISK>",
        "what_was_detected": "<2 clear sentences describing what the target actually is and what its live content/text does>",
        "why_suspicious": "<2-3 detailed sentences explaining the exact behavioral and technical reasoning behind your verdict>",
        "how_affects_user": "<2 clear sentences explaining the real-world impact on the user>",
        "evidence": "<Specific proof from the live page content, domain structure, SSL, or routing telemetry>",
        "how_to_stay_safe": ["<Clear actionable step 1>", "<Clear actionable step 2>"]
    }}
    User Input: {text_data}
    """

    ai_output = None
    if image_bytes:
        ai_output = call_gemini_ai([prompt, Image.open(io.BytesIO(image_bytes))])
    else:
        ai_output = call_groq_ai(prompt) or call_openrouter_ai(prompt) or call_gemini_ai([prompt])

    if ai_output:
        RESULT_CACHE[cache_key] = ai_output
        return ai_output

    return backup_content_analyzer(content_type, text_data, extra_intel)
